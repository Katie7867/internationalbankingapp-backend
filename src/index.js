require('dotenv').config();
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');              
const ExpressBrute = require('express-brute'); 

const authRoutes = require('./routes/auth');
const paymentsRouter = require('./routes/payments');
const app = express();

const USE_HTTPS = process.env.USE_HTTPS !== 'false';

// -----------------------------
// SECURITY MIDDLEWARES
// -----------------------------
//set secure headers, CSP, HSTS, and prevent clickjacking
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000 }));
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: [
        "'self'",
        "https://big-5-bank-frontend.onrender.com",
        "https://big-5-bank-api-backend.onrender.com"
      ],
      imgSrc: ["'self'", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
      reportUri: '/api/csp-report'
    },
  })
);
app.use(helmet.frameguard({ action: 'deny' }));

//Morgan request logging
app.use(morgan('dev'));

//limit body size to prevent large payload attacks
app.use(express.json({ limit: '10kb' }));

// Dynamic Report-To header (fixes localhost:4000)
app.use((req, res, next) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const baseUrl = isProduction ? `https://${req.headers.host}` : 'https://localhost:4000';
  res.setHeader(
    'Report-To',
    JSON.stringify([{
      group: 'csp-endpoint',
      max_age: 10886400,
      endpoints: [{ url: `${baseUrl}/api/csp-report` }],
      include_subdomains: true,
    }])
  );
  next();
});

// -----------------------------
// CORS
// -----------------------------
//allow requests only from trusted frontend with credentials
app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'https://localhost:5173',
      'https://big-5-bank-frontend.onrender.com'  
    ],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    credentials: true,
  })
);
// -----------------------------
// RATE LIMITING
// -----------------------------
//protect against brute-force and DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
});
app.use(limiter);

// -----------------------------
// HTTPS REDIRECT (PRODUCTION)
// -----------------------------
//force HTTPS in production
if (process.env.NODE_ENV === 'production' && USE_HTTPS) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// -----------------------------
// CSRF PROTECTION
// -----------------------------
//use cookie-based CSRF tokens for all sensitive routes
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

//endpoint to issue CSRF token cookie
app.get('/api/csrf-token', (req, res) => {
  const token = req.csrfToken ? req.csrfToken() : 'token';
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    secure: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
  });
  res.json({ csrfToken: token });
})

//protect payments routes with CSRF middleware
app.use('/api/payments', csrfProtection, paymentsRouter);

//handle CSRF errors
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'invalid CSRF token' });
  }
  next(err);
});

// -----------------------------
// MONGODB CONNECTION
// -----------------------------
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('MONGO_URI not set in .env');
  process.exit(1);
}

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// -----------------------------
// EXPRESS-BRUTE (login protection)
// -----------------------------
const store = new ExpressBrute.MemoryStore();

const bruteforce = new ExpressBrute(store, {
  freeRetries: 5,
  minWait: 5 * 60 * 1000,   // 5 minutes
  maxWait: 60 * 60 * 1000,  // 1 hour
  lifetime: 60 * 60,        // reset after 1 hour

  //custom response when locked out
  failCallback: (req, res, next, nextValidRequestDate) => {
    res.status(429).json({
      error: 'Too many login attempts. Please try again in 5 minutes.',
      retryAfter: nextValidRequestDate, // gives the timestamp when they can retry
    });
  },
});

// Apply brute-force protection only to login route
// NOTE: keep this BEFORE the authRoutes middleware so it runs for /api/auth/login
app.post('/api/auth/login', bruteforce.prevent, (req, res, next) => {
  next(); // hand off to your existing auth logic inside authRoutes
});

// -----------------------------
// ROUTES
// -----------------------------
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is healthy' });
});
app.use('/api/auth', authRoutes);
app.use('/api/employees', require('./routes/employees'));


app.get('/', (req, res) =>
  res.json({ ok: true, message: 'INSY7314 backend running' })
);
// -----------------------------
// CSP VIOLATION REPORT ENDPOINT
// -----------------------------
app.post(
  '/api/csp-report',
  express.json({ type: 'application/csp-report' }),
  (req, res) => {
    const report = req.body['csp-report'];
    if (report) {
      console.warn('CSP VIOLATION DETECTED:', {
        time: new Date().toISOString(),
        documentUri: report['document-uri'],
        blockedUri: report['blocked-uri'],
        violatedDirective: report['violated-directive'],
        sourceFile: report['source-file'],
        lineNumber: report['line-number'],
      });
    }
    res.status(204).end();
  }
);
// -----------------------------
// GLOBAL ERROR HANDLER
// -----------------------------
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

// -----------------------------
// HPP PROTECTION (parameter pollution)
// -----------------------------
const hpp = require('hpp');
app.use(hpp());

// -----------------------------
// TRUST PROXY
// -----------------------------
//safe configuration for reverse proxy and secure cookies
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1); //trust first proxy
} else {
  app.set('trust proxy', false);
}
// -----------------------------
// START SERVER (Render only)
// -----------------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
