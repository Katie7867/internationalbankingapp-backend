// middleware/auth.js
const jwt = require('jsonwebtoken');

//****************
//Code Attribution
//The following JWT code was taken from JWT Debugger
//Author: s.n.
//Link: https://www.jwt.io/introduction#what-is-json-web-token
//****************

//check user authentication using JWT from header or cookie
function auth(req, res, next) {
  //get token from Authorization header if present
  const authHeader = req.headers.authorization;
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }

  //if no header token, check access_token cookie
  if (!token && req.cookies && req.cookies.access_token) {
    token = req.cookies.access_token;
  }

  //deny request if no token found
  if (!token) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    //verify token validity and expiration using server secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');

    //get user id from token claims
    const userId = decoded.id || decoded._id || decoded.userId || decoded.sub;
    if (!userId) {
      return res.status(401).json({ error: 'invalid token: no user id claim' });
    }

    //attach verified user info to request object
    req.user = { ...decoded, id: userId };
    next();
  } catch (_err) {
    //handle invalid or expired tokens
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

//check user roles for authorization
function authorize(...roles) {
  return (req, res, next) => {
    //ensure user is logged in
    if (!req.user) return res.status(401).json({ error: 'unauthorized' });

    //allow access only for permitted roles
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'forbidden' });

    next();
  };
}

module.exports = { auth, authorize };
