require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');

const authRoutes = require('./routes/auth');
const paymentsRouter = require('./routes/payments');
const employeesRouter = require('./routes/employees');

const app = express();

// -----------------------------
// ENVIRONMENT
// -----------------------------
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 4000;

// TRUST PROXY
if (isProduction) {
  app.set('trust proxy', 1);
}

// -----------------------------
// SECURITY MIDDLEWARES
// -----------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'", 
        "https://big-5-bank-api-backend.onrender.com",
        "https://big-5-bank-frontend.onrender.com"
      ],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

// -----------------------------
// LOGGING + BODY PARSING
// -----------------------------
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// -----------------------------
// CORS - FIXED VERSION
// -----------------------------
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5173',
      'https://localhost:5173',
      'https://big-5-bank-frontend.onrender.com'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  exposedHeaders: ['X-CSRF-Token'] // Expose CSRF token header
}));

app.options('*', cors());

// -----------------------------
// RATE LIMITING
// -----------------------------
app.use(rateLimit({ windowMs: 15*60*1000, max: 200 }));

// -----------------------------
// CSRF SETUP - FIXED FOR CROSS-DOMAIN
// -----------------------------
// Use session-based CSRF instead of cookie-based for cross-domain
const csrfProtection = csrf({ 
  cookie: false, // CRITICAL: Don't use cookies for cross-domain
  sessionKey: 'csrfSecret' // We'll store in a cookie manually
});

// Custom CSRF middleware that works cross-domain
const csrfMiddleware = (req, res, next) => {
  // Generate or retrieve CSRF secret
  let secret = req.cookies.csrfSecret;
  
  if (!secret) {
    // Generate new secret
    secret = require('crypto').randomBytes(32).toString('hex');
    res.cookie('csrfSecret', secret, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 3600000,
      path: '/'
    });
  }
  
  // Attach secret to session for csrf library
  req.session = req.session || {};
  req.session.csrfSecret = secret;
  
  csrfProtection(req, res, next);
};

// Provide CSRF token endpoint
app.get('/api/csrf-token', csrfMiddleware, (req, res) => {
  const token = req.csrfToken();
  console.log('CSRF token generated:', token.substring(0, 10) + '...');
  
  // Return token in response body (not cookie)
  res.json({ csrfToken: token });
});

// -----------------------------
// DATABASE CONNECTION
// -----------------------------
if (!process.env.MONGO_URI) {
  console.error('MONGO_URI not set in .env');
  process.exit(1);
}

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error(err); process.exit(1); });

// -----------------------------
// ROUTES
// -----------------------------
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/', (req,res) => res.json({ ok:true, message:'Backend running' }));

// Middleware to apply CSRF to state-changing requests
const applyCSRF = (req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    csrfMiddleware(req, res, next);
  } else {
    next();
  }
};

// Apply CSRF to all protected routes
app.use('/api/auth', applyCSRF, authRoutes);
app.use('/api/payments', applyCSRF, paymentsRouter);
app.use('/api/employees', applyCSRF, employeesRouter);

// -----------------------------
// CSRF ERROR HANDLER
// -----------------------------
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    console.error('CSRF token validation failed');
    console.error('Token from header:', req.headers['x-csrf-token']?.substring(0, 10) + '...');
    return res.status(403).json({ 
      error: 'Invalid CSRF token',
      message: 'Please refresh the page and try again'
    });
  }
  next(err);
});

// -----------------------------
// GLOBAL ERROR HANDLER
// -----------------------------
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

// -----------------------------
// START SERVER
// -----------------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${isProduction ? 'production' : 'development'}`);
});