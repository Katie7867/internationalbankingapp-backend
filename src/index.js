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

const FRONTEND_URL = process.env.FRONTEND_ORIGIN || (isProduction
  ? 'https://big-5-bank-frontend.onrender.com'
  : 'http://localhost:5173');

// -----------------------------
// SECURITY MIDDLEWARES
// -----------------------------
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", FRONTEND_URL],
      imgSrc: ["'self'", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
app.use(helmet.frameguard({ action: 'deny' }));

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
  origin: FRONTEND_URL,
  credentials: true
}));

// -----------------------------
// RATE LIMITING
// -----------------------------
app.use(rateLimit({ windowMs: 15*60*1000, max: 200 }));

// -----------------------------
// CSRF SETUP
// -----------------------------
const csrfProtection = csrf({ cookie: true });

// Provide CSRF token for the frontend
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,          // readable by frontend JS
    secure: isProduction,     // only secure in prod
    sameSite: isProduction ? 'None' : 'Lax'
  });
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

// ---------- AUTH ROUTES ----------
// Only protect POST/PUT/DELETE routes with CSRF
app.use('/api/auth', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    csrfProtection(req, res, next);
  } else {
    next();
  }
}, authRoutes);

// ---------- PAYMENTS ROUTES ----------
app.use('/api/payments', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    csrfProtection(req, res, next);
  } else {
    next();
  }
}, paymentsRouter);

// ---------- EMPLOYEES ROUTES ----------
app.use('/api/employees', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    csrfProtection(req, res, next);
  } else {
    next();
  }
}, employeesRouter);

// -----------------------------
// CSRF ERROR HANDLER
// -----------------------------
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'invalid CSRF token' });
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
if (isProduction) {
  app.set('trust proxy', 1);
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
} else {
  app.listen(PORT, () => console.log(`Dev server running at http://localhost:${PORT}`));
}
