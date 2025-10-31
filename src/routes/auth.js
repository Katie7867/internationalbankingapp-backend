const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const crypto = require('crypto');
const PEPPER = process.env.PEPPER_SECRET || 'devpepper';
const zxcvbn = require('zxcvbn');

const User = require('../models/User');
const { patterns } = require('../validation/authValidation');

const router = express.Router();
const SALT_ROUNDS = 12;

// -------------------------
// SECURITY MIDDLEWARE
// -------------------------
//protect headers, prevent XSS, and sanitize Mongo queries
router.use(helmet());
router.use(xss());
router.use(mongoSanitize());

//limit login/register attempts to prevent brute force attacks
//CURRENTLY IN DEV MODE - ADJUST VALUES FOR PRODUCTION
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                  // 100 attempts
  keyGenerator: (req) => {
    //limit per username/accountNumber combination
    const userKey = `${req.body.username || ''}:${req.body.accountNumber || ''}`.trim();
    return userKey || req.ip;
  },
  handler: (req, res) => res.status(429).json({ error: 'Too many attempts, please try again later.' })
});

// -------------------------
// REGISTER (customers only)
// -------------------------
//handle new user registration securely
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    //check all required fields are present
    if (!fullName || !idNumber || !accountNumber || !username || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    //validate inputs against server-side patterns to prevent invalid data
    if (
      !patterns.fullName.test(fullName) ||
      !patterns.idNumber.test(idNumber) ||
      !patterns.accountNumber.test(accountNumber) ||
      !patterns.username.test(username) ||
      !patterns.password.test(password)
    ) {
      return res.status(400).json({ error: 'Validation failed (client values do not match server regex)' });
    }

    //check for existing user to prevent duplicates
    const existing = await User.findOne({ $or: [{ username }, { accountNumber }] });
    if (existing) return res.status(400).json({ error: 'User or account already exists' });

    // check password strength using zxcvbn
    const strength = zxcvbn(password);
    if (strength.score < 2) {
      return res.status(400).json({ error: 'Password too weak — please choose a stronger password' });
    }

    //hash password securely before storing
    const passwordHash = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);

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

    //handle validation errors securely
    if (err.name === 'ValidationError') {
      return res.status(400).json({ error: 'Mongo validation error', details: err.message });
    }
    if (err.code === 11000) {
      const dupField = Object.keys(err.keyValue || {}).join(', ');
      return res.status(400).json({ error: `Duplicate field: ${dupField}` });
    }

    //fallback error message (avoid revealing sensitive info in production)
    return res.status(500).json({ error: 'server error', message: err.message });
  }
});

// -------------------------
// LOGIN
// -------------------------
//authenticate users securely
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password, accountNumber } = req.body;

    if (!username || !password || !accountNumber) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // FIX: Convert to string for regex + DB match
    const accStr = String(accountNumber).trim();

    //validate account number format
    if (!patterns.accountNumber.test(accStr)) {
      return res.status(400).json({ error: 'Invalid account number format' });
    }

    //find user and verify password
    const user = await User.findOne({ username, accountNumber: accStr });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password + PEPPER, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    // ... rest of JWT logic (unchanged)
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

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: secureFlag ? 'none' : 'lax',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: secureFlag ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ message: 'Login successful', role: user.role });
  } catch (err) {
    console.error('LOGIN ERROR:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------------
// REFRESH TOKENS
// -------------------------
//rotate and re-issue access and refresh tokens
router.post('/refresh', async (req, res) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ error: 'no refresh token' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET || 'refreshsecret');
    } catch (_e) {
      return res.status(401).json({ error: 'invalid refresh token' });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.refreshId || user.refreshId !== payload.rid) {
      return res.status(401).json({ error: 'refresh token revoked' });
    }
    if (user.refreshExpires && Date.now() > user.refreshExpires) {
      return res.status(401).json({ error: 'refresh token expired' });
    }

    //rotate refreshId for security
    const newRefreshId = crypto.randomBytes(32).toString('hex');
    user.refreshId = newRefreshId;
    user.refreshExpires = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await user.save();

    //issue new tokens
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
      sameSite: secureFlag ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: secureFlag,
      sameSite: secureFlag ? 'none' : 'lax',
      maxAge: 15 * 60 * 1000
    });

    return res.json({ message: 'refreshed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// -------------------------
// GET CURRENT USER
// -------------------------
//return minimal safe user info from token
router.get('/me', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token && req.cookies) token = req.cookies.access_token;
    if (!token) return res.status(401).json({ error: 'no token' });

    const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET || 'devsecret');
    const user = { id: decoded.sub || decoded._id || decoded.userId, role: decoded.role || decoded.role };
    return res.json({ user });
  } catch (_err) {
    return res.status(401).json({ error: 'invalid token' });
  }
});

// -------------------------
// LOGOUT
// -------------------------
//clear tokens and revoke refresh tokens
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
    res.clearCookie('access_token', { httpOnly: true, secure: secureFlag, sameSite: secureFlag ? 'none' : 'lax' });
    res.clearCookie('refresh_token', { httpOnly: true, secure: secureFlag, sameSite: secureFlag ? 'none' : 'lax' });
    return res.json({ message: 'logged out' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

module.exports = router;
