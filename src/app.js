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

// Trust proxy per env
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
} else {
  app.set('trust proxy', false);
}

// -----------------------------
// Security Middlewares
// -----------------------------
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000 }));
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    connectSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    styleSrc: ["'self'", "'unsafe-inline'"], // remove 'unsafe-inline' in production if possible
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));
app.use(helmet.frameguard({ action: 'deny' }));

app.use(express.json({ limit: '10kb' }));

// -----------------------------
// CORS
// -----------------------------
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || 'https://yourfrontenddomain.com',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));

// -----------------------------
// Rate Limiting
// -----------------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use(limiter);

// -----------------------------
// HTTPS Redirect (Production Only)
// -----------------------------
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// -----------------------------
// CSRF Protection
// -----------------------------
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// Endpoint to issue CSRF token cookie
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false, // must be readable by frontend
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict'
  });
  res.json({ csrfToken: req.csrfToken() });
});

app.use('/api/auth', authRoutes);

// Protect payments routes
app.use('/api/payments', csrfProtection, paymentsRouter);

app.get('/', (req, res) => {
  res.json({ ok: true, message: 'INSY7314 backend running' });
});

// Health for CI/tests
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});

// csurf error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'invalid CSRF token' });
  }
  next(err);
});

// Global error handler
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

module.exports = app;


