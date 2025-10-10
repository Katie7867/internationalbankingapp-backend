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
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"], // remove 'unsafe-inline' in production if possible
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
app.use(helmet.frameguard({ action: 'deny' }));

//Morgan request logging
app.use(morgan('dev'));

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
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    httpOnly: false, // must be readable by frontend
    secure: true, // always secure for HTTPS
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
// START HTTPS SERVER
// -----------------------------
//const http = require('http');
const path = require('path');

const PORT = process.env.PORT || 4000;
//const USE_HTTPS = process.env.USE_HTTPS === 'true';

// resolve certs relative to project root (one level up from /src)
const keyPath = path.join(__dirname, '..', 'ssl', 'key.pem');
const certPath = path.join(__dirname, '..', 'ssl', 'cert.pem');

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`HTTPS server listening at https://localhost:${PORT}`);
  });
} else {
  http.createServer(app).listen(PORT, () => {
    console.log(`HTTP server listening at http://localhost:${PORT}`);
    if (USE_HTTPS) {
      console.warn('USE_HTTPS is true but SSL files were not found. Falling back to HTTP.');
      console.warn(`Checked paths:\n - ${keyPath}\n - ${certPath}`);
    }
  });
}
