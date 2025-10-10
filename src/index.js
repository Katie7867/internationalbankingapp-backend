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

const authRoutes = require('./routes/auth');
const paymentsRouter = require('./routes/payments');

const app = express();

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
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"], // remove 'unsafe-inline' in production if possible
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
app.use(helmet.frameguard({ action: 'deny' }));

//limit body size to prevent large payload attacks
app.use(express.json({ limit: '10kb' }));

// -----------------------------
// CORS
// -----------------------------
//allow requests only from trusted frontend with credentials
app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'https://localhost:5173',
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

// HTTPS REDIRECT (PRODUCTION + HTTPS only)
// -----------------------------
// Force HTTPS only when we actually run HTTPS
if (process.env.NODE_ENV === 'production' && process.env.USE_HTTPS === 'true') {
  // If behind a proxy/load balancer, Express can detect req.secure when trust proxy is on
  app.use((req, res, next) => {
    const forwardedProto = req.headers['x-forwarded-proto'];
    if (!req.secure && forwardedProto !== 'https') {
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

// Helper: decide if cookies should be "secure"
const isSecureCookie = (req) =>
  req.secure ||
  process.env.USE_HTTPS === 'true' ||
  process.env.NODE_ENV === 'production';

//endpoint to issue CSRF token cookie
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false, // must be readable by frontend
    secure: isSecureCookie(req),
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
  });
  res.json({ csrfToken: req.csrfToken() });
});

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
// ROUTES
// -----------------------------
app.use('/api/auth', authRoutes);

app.get('/', (req, res) =>
  res.json({ ok: true, message: 'INSY7314 backend running' })
);

// -----------------------------
// GLOBAL ERROR HANDLER
// -----------------------------
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

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
// START SERVER (HTTPS optional)
// -----------------------------
const PORT = process.env.PORT || 4000;
const HOST = '0.0.0.0';
const USE_HTTPS = process.env.USE_HTTPS === 'true';

if (USE_HTTPS) {
  try {
    const httpsOptions = {
      key: fs.readFileSync('./ssl/key.pem'),
      cert: fs.readFileSync('./ssl/cert.pem'),
    };
    https.createServer(httpsOptions, app).listen(PORT, HOST, () => {
      console.log(`HTTPS server listening at https://localhost:${PORT}`);
    });
  } catch (e) {
    console.warn('[WARN] USE_HTTPS=true but SSL files missing or unreadable. Falling back to HTTP.', e.message);
    http.createServer(app).listen(PORT, HOST, () => {
      console.log(`HTTP server (fallback) listening at http://localhost:${PORT}`);
    });
  }
} else {
  http.createServer(app).listen(PORT, HOST, () => {
    console.log(`HTTP server listening at http://localhost:${PORT}`);
  });
}

module.exports = app