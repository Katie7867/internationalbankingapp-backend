require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const authRoutes = require('./routes/auth');
const paymentsRouter = require('./routes/payments');

const app = express();

// -----------------------------
// PROXY SETTINGS
// -----------------------------
//trust proxy headers in production (for HTTPS redirect, secure cookies)
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
} else {
  app.set('trust proxy', false);
}

// -----------------------------
// SECURITY MIDDLEWARES
// -----------------------------
//helmet for secure headers, CSP, HSTS, and frameguard
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    connectSrc: [
      "'self'",
      "https://big-5-bank-frontend.onrender.com", // ✅ allow frontend to connect
      "https://big-5-bank-api-backend.onrender.com" // ✅ allow backend self-calls
    ],
    imgSrc: ["'self'", "data:"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));

app.use(helmet.frameguard({ action: 'deny' }));

//limit body size to prevent large payload attacks
app.use(express.json({ limit: '10kb' }));

// -----------------------------
// CORS
// -----------------------------

//****************
//Code Attribution
//The following CORS code was taken from MDN Web Docs
//Author: s.n.
//Link: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
//****************

//allow requests only from trusted frontend with credentials
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://localhost:5173',
    'https://big-5-bank-frontend.onrender.com'
  ],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));


// -----------------------------
// RATE LIMITING
// -----------------------------

//****************
//Code Attribution
//The following Rate Limit code was taken from MDN Web Docs
//Authors: Arvin Kahbazi, Maarten Balliauw, and Rick Anderson
//Link: https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit?view=aspnetcore-9.0
//****************

//protect against brute-force and DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use(limiter);

// -----------------------------
// HTTPS REDIRECT (PRODUCTION)
// -----------------------------
//force HTTPS in production
if (process.env.NODE_ENV === 'production') {
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

//****************
//Code Attribution
//The following CRSF code was taken from MDN Web Docs
//Author: s.n.
//Link: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
//****************

//use cookie-based CSRF tokens
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

//endpoint to issue CSRF token cookie
app.get('/api/csrf-token', (req, res) => {
  const token = req.csrfToken ? req.csrfToken() : 'token';
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict'
  });
  res.json({ csrfToken: token });
});


// -----------------------------
// ROUTES
// -----------------------------
app.use('/api/auth', authRoutes);

//protect payments routes with CSRF middleware
app.use('/api/payments', csrfProtection, paymentsRouter);

//basic health check endpoints
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'INSY7314 backend running' });
});

app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});

// -----------------------------
// ERROR HANDLING
// -----------------------------
//csurf errors (invalid/missing CSRF token)
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'invalid CSRF token' });
  }
  next(err);
});

//global fallback error handler
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

module.exports = app;
