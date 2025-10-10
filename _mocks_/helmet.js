// __mocks__/helmet.js
// Export a function (like the real helmet) that returns a no-op middleware.
// Also mock the sub-helpers called in app.js (hsts, csp, frameguard).
const helmet = () => (req, res, next) => next();

helmet.hsts = () => (req, res, next) => next();
helmet.contentSecurityPolicy = () => (req, res, next) => next();
helmet.frameguard = () => (req, res, next) => next();

module.exports = helmet;
