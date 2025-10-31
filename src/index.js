require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const crypto = require('crypto');

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
// CORS
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
  exposedHeaders: ['X-CSRF-Token']
}));

app.options('*', cors());

// -----------------------------
// RATE LIMITING
// -----------------------------
app.use(rateLimit({ windowMs: 15*60*1000, max: 200 }));

// -----------------------------
// CSRF SETUP - SIMPLIFIED
// -----------------------------
// Store secrets in memory (for single-instance apps)
// For multi-instance, use Redis or database
const csrfSecrets = new Map();

// Provide CSRF token endpoint - NO CSRF PROTECTION ON THIS ENDPOINT
app.get('/api/csrf-token', (req, res) => {
  try {
    // Check if user already has a valid secret
    let secret = req.cookies.csrfSecret;
    let isNewSecret = false;
    
    if (!secret || !csrfSecrets.has(secret)) {
      // Generate NEW secret only if none exists
      secret = crypto.randomBytes(32).toString('hex');
      csrfSecrets.set(secret, Date.now());
      isNewSecret = true;
      
      console.log('🔐 Generated NEW CSRF secret:', secret.substring(0, 10) + '...');
      
      // Set cookie with secret
      res.cookie('csrfSecret', secret, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        maxAge: 3600000, // 1 hour
        path: '/'
      });
    } else {
      // Reuse existing secret - just refresh timestamp
      csrfSecrets.set(secret, Date.now());
      console.log('♻️  Reusing existing CSRF secret:', secret.substring(0, 10) + '...');
    }
    
    // Generate token from secret
    const token = crypto.createHmac('sha256', secret)
      .update('csrf-token')
      .digest('hex');
    
    console.log(`✅ CSRF token generated (${isNewSecret ? 'NEW' : 'REUSED'} secret):`, token.substring(0, 10) + '...');
    res.json({ csrfToken: token });
  } catch (error) {
    console.error('❌ Error generating CSRF token:', error);
    res.status(500).json({ error: 'Failed to generate CSRF token' });
  }
});

// CSRF validation middleware
const validateCsrf = (req, res, next) => {
  try {
    const token = req.headers['x-csrf-token'];
    const secret = req.cookies.csrfSecret;
    
    console.log('🔍 Validating CSRF token...');
    console.log('   Token received:', token ? token.substring(0, 10) + '...' : 'NONE');
    console.log('   Secret cookie:', secret ? secret.substring(0, 10) + '...' : 'NONE');
    
    if (!token) {
      console.error('❌ No CSRF token in request headers');
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        message: 'No CSRF token provided'
      });
    }
    
    if (!secret || !csrfSecrets.has(secret)) {
      console.error('❌ No valid CSRF secret in cookies');
      console.log('   Available secrets:', Array.from(csrfSecrets.keys()).map(s => s.substring(0, 10) + '...'));
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        message: 'Session expired. Please refresh the page.'
      });
    }
    
    // Verify token matches secret
    const expectedToken = crypto.createHmac('sha256', secret)
      .update('csrf-token')
      .digest('hex');
    
    console.log('   Expected token:', expectedToken.substring(0, 10) + '...');
    
    if (token !== expectedToken) {
      console.error('❌ CSRF token mismatch!');
      console.error('   Got:     ', token.substring(0, 20) + '...');
      console.error('   Expected:', expectedToken.substring(0, 20) + '...');
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        message: 'Token verification failed'
      });
    }
    
    console.log('✅ CSRF token valid!');
    next();
  } catch (error) {
    console.error('❌ CSRF validation error:', error);
    res.status(403).json({ 
      error: 'Invalid CSRF token',
      message: 'Validation error'
    });
  }
};

// Clean up old secrets every hour
setInterval(() => {
  const now = Date.now();
  const oneHour = 3600000;
  
  for (const [secret, timestamp] of csrfSecrets.entries()) {
    if (now - timestamp > oneHour) {
      csrfSecrets.delete(secret);
    }
  }
  
  console.log(`Cleaned up CSRF secrets. Active sessions: ${csrfSecrets.size}`);
}, 3600000);

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
    validateCsrf(req, res, next);
  } else {
    next();
  }
};

// Apply CSRF to all protected routes
app.use('/api/auth', applyCSRF, authRoutes);
app.use('/api/payments', applyCSRF, paymentsRouter);
app.use('/api/employees', applyCSRF, employeesRouter);

// -----------------------------
// GLOBAL ERROR HANDLER
// -----------------------------
app.use((err, req, res, _next) => {
  console.error('Error:', err.message);
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