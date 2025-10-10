// ---- mock security/rate-limit middlewares to no-ops ----
jest.mock('helmet', () => {
  const helmet = () => (req, res, next) => next();
  helmet.hsts = () => (req, res, next) => next();
  helmet.contentSecurityPolicy = () => (req, res, next) => next();
  helmet.frameguard = () => (req, res, next) => next();
  return helmet;
});
jest.mock('xss-clean', () => () => (req, res, next) => next());
jest.mock('express-mongo-sanitize', () => () => (req, res, next) => next());
jest.mock('express-rate-limit', () => () => (req, res, next) => next());

jest.mock('jsonwebtoken', () => ({ verify: jest.fn() }));
const jwt = require('jsonwebtoken');
const { auth, authorize } = require('../src/middleware/auth');

const mkRes = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn() });

describe('auth middleware', () => {
  test('401 when no token', () => {
    const req = { headers: {}, cookies: {} };
    const res = mkRes();
    const next = jest.fn();
    auth(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('401 when jwt invalid', () => {
    jwt.verify.mockImplementation(() => { throw new Error('bad'); });
    const req = { headers: { authorization: 'Bearer abc' }, cookies: {} };
    const res = mkRes();
    const next = jest.fn();
    auth(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('attaches req.user and calls next when valid', () => {
    jwt.verify.mockReturnValue({ sub: 'u1', role: 'customer' });
    const req = { headers: { authorization: 'Bearer good' }, cookies: {} };
    const res = mkRes();
    const next = jest.fn();
    auth(req, res, next);
    expect(req.user.id).toBe('u1');
    expect(req.user.role).toBe('customer');
    expect(next).toHaveBeenCalled();
  });
});

describe('authorize middleware', () => {
  test('401 if not authenticated', () => {
    const req = {};
    const res = mkRes();
    const next = jest.fn();
    authorize('employee')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  test('403 if wrong role', () => {
    const req = { user: { role: 'customer' } };
    const res = mkRes();
    const next = jest.fn();
    authorize('employee')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('allows when role matches', () => {
    const req = { user: { role: 'employee' } };
    const res = mkRes();
    const next = jest.fn();
    authorize('employee')(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});
