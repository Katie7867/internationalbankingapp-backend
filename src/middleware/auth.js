// middleware/auth.js
const jwt = require('jsonwebtoken')

/**
 * Authentication middleware
 * Verifies JWT and attaches decoded user to req.user
 */
function auth(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecret')
    req.user = decoded
    next()
  } catch (err) {
    return res.status(401).json({ error: 'invalid or expired token' })
  }
}

/**
 * Role-based authorization middleware
 * Usage: authorize('customer') or authorize('employee')
 */
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' })
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}

module.exports = { auth, authorize }
