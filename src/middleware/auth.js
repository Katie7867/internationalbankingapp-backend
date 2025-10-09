// middleware/auth.js
const jwt = require('jsonwebtoken');

/**
 * Authentication middleware
 * Verifies JWT (from Authorization header or access_token cookie)
 * and attaches decoded user to req.user
 */
function auth(req, res, next) {
  // 1) Try Authorization header first
  const authHeader = req.headers.authorization;
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  // 2) Fallback to cookie named access_token
  if (!token && req.cookies && req.cookies.access_token) {
    token = req.cookies.access_token;
  }

  if (!token) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
    const userId = decoded.id || decoded._id || decoded.userId || decoded.sub;
    if (!userId) {
      return res.status(401).json({ error: 'invalid token: no user id claim' });
    }

    req.user = { ...decoded, id: userId };
    next();
  } catch (_err) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

/**
 * Role-based authorization middleware
 * Usage: authorize('customer') or authorize('employee')
 */
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

module.exports = { auth, authorize };