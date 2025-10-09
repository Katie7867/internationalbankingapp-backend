require('dotenv').config();
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const https = require('https');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const paymentsRouter = require('./routes/payments');

const app = express();

// -----------------------------
// Security Middlewares
// -----------------------------
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

app.use(express.json({ limit: '10kb' }));

// -----------------------------
// CORS
// -----------------------------
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
// Rate Limiting
// -----------------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
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
    secure: true, // 🔒 always secure since we’re serving HTTPS
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
  });
  res.json({ csrfToken: req.csrfToken() });
});

// Protect payments routes
app.use('/api/payments', csrfProtection, paymentsRouter);

// csurf error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'invalid CSRF token' });
  }
  next(err);
});

// -----------------------------
// MongoDB Connection
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
// Routes
// -----------------------------
app.use('/api/auth', authRoutes);

app.get('/', (req, res) =>
  res.json({ ok: true, message: 'INSY7314 backend running' })
);

// -----------------------------
// Global Error Handler
// -----------------------------
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'server error' });
});

// -----------------------------
// Trust Proxy (safe config)
// -----------------------------
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1); // trust first proxy
} else {
  app.set('trust proxy', false);
}

// -----------------------------
// Start HTTPS Server
// -----------------------------
const PORT = process.env.PORT || 4000;

const httpsOptions = {
  key: fs.readFileSync('./ssl/key.pem'),   // 🔧 use your actual key file
  cert: fs.readFileSync('./ssl/cert.pem'), // 🔧 use your actual cert file
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`🚀 Server listening at https://localhost:${PORT}`);
});