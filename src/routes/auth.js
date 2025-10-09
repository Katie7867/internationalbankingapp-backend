const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const crypto = require('crypto');

const User = require('../models/User');
const { patterns } = require('../validation/authValidation');

const router = express.Router();
const SALT_ROUNDS = 12;

// -------------------------
// SECURITY MIDDLEWARE
// -------------------------
router.use(helmet());
router.use(xss());
router.use(mongoSanitize());

// per-credential limiter (5 attempts per minute)
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => {
    const userKey = `${req.body.username || ''}:${req.body.accountNumber || ''}`.trim();
    return userKey || req.ip;
  },
  handler: (req, res) => res.status(429).json({ error: 'Too many attempts, please try again later.' })
});

// -------------------------
// REGISTER (customers only)
// -------------------------
// DEBUG-friendly register handler (temporary)
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    // basic checks for clearer early errors
    if (!fullName || !idNumber || !accountNumber || !username || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // validate with your patterns
    if (
      !patterns.fullName.test(fullName) ||
      !patterns.idNumber.test(idNumber) ||
      !patterns.accountNumber.test(accountNumber) ||
      !patterns.username.test(username) ||
      !patterns.password.test(password)
    ) {
      return res.status(400).json({ error: 'Validation failed (client values do not match server regex)' });
    }

    //collision check
    const existing = await User.findOne({ $or: [{ username }, { accountNumber }] });
    if (existing) return res.status(400).json({ error: 'User or account already exists' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = await User.create({
      fullName,
      idNumber,
      accountNumber,
      username,
      passwordHash,
      role: 'customer'
    });

    return res.json({ message: 'registered', userId: newUser._id, role: newUser.role });
  } catch (err) {
    console.error('REGISTER ERROR:', err);

    //Common helpful error responses
    if (err.name === 'ValidationError') {
      return res.status(400).json({ error: 'Mongo validation error', details: err.message });
    }
    if (err.code === 11000) {
      // duplicate key
      const dupField = Object.keys(err.keyValue || {}).join(', ');
      return res.status(400).json({ error: `Duplicate field: ${dupField}` });
    }

    // fallback: reveal message while debugging — remove in production
    return res.status(500).json({ error: 'server error', message: err.message });
  }
});

// -------------------------
// LOGIN
// -------------------------
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password, accountNumber } = req.body;

    if (!username || !password || !accountNumber) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!patterns.accountNumber.test(accountNumber)) {
      return res.status(400).json({ error: 'Invalid account number format' });
    }

    const user = await User.findOne({ username, accountNumber });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    // rotate and persist refreshId (server-side)
    const refreshId = crypto.randomBytes(32).toString('hex');
    user.refreshId = refreshId;
    user.refreshExpires = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await user.save();

    const secureFlag = process.env.NODE_ENV === 'production';

    const accessToken = jwt.sign(
      { sub: user._id, role: user.role },
      process.env.JWT_SECRET || 'devsecret',
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { sub: user._id, rid: refreshId },
      process.env.JWT_REFRESH_SECRET || 'refreshsecret',
      { expiresIn: '7d' }
    );

    // Set secure cookies
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ message: 'Login successful', role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------
// REFRESH (rotate + re-issue tokens)
// -------------------------
router.post('/refresh', async (req, res) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ error: 'no refresh token' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET || 'refreshsecret');
    } catch (e) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.refreshId || user.refreshId !== payload.rid) {
      return res.status(401).json({ error: 'refresh token revoked' });
    }
    if (user.refreshExpires && Date.now() > user.refreshExpires) {
      return res.status(401).json({ error: 'refresh token expired' });
    }

    // rotate refreshId
    const newRefreshId = crypto.randomBytes(32).toString('hex');
    user.refreshId = newRefreshId;
    user.refreshExpires = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await user.save();

    const newRefreshToken = jwt.sign(
      { sub: user._id, rid: newRefreshId },
      process.env.JWT_REFRESH_SECRET || 'refreshsecret',
      { expiresIn: '7d' }
    );

    const newAccessToken = jwt.sign(
      { sub: user._id, role: user.role },
      process.env.JWT_SECRET || 'devsecret',
      { expiresIn: '15m' }
    );

    const secureFlag = process.env.NODE_ENV === 'production';
    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000
    });

    return res.json({ message: 'refreshed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token && req.cookies) token = req.cookies.access_token;
    if (!token) return res.status(401).json({ error: 'no token' });

    const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET || 'devsecret');
    // return only safe claims
    const user = { id: decoded.sub || decoded._id || decoded.userId, role: decoded.role || decoded.role };
    return res.json({ user });
  } catch (_err) {
    return res.status(401).json({ error: 'invalid token' });
  }
});

// -------------------------
// LOGOUT
// -------------------------
router.post('/logout', async (req, res) => {
  try {
    const token = req.cookies?.refresh_token;
    if (token) {
      try {
        const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET || 'refreshsecret');
        const user = await User.findById(payload.sub);
        if (user) { user.refreshId = null; user.refreshExpires = null; await user.save(); }
      } catch (_err) { /* ignore */ }
    }
    const secureFlag = process.env.NODE_ENV === 'production';
    res.clearCookie('access_token', { httpOnly: true, secure: secureFlag, sameSite: 'Strict' });
    res.clearCookie('refresh_token', { httpOnly: true, secure: secureFlag, sameSite: 'Strict' });
    return res.json({ message: 'logged out' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

module.exports = router;