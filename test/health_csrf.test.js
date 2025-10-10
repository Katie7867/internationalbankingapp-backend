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

const request = require('supertest');
const app = require('../src/app');


describe('health & csrf', () => {
  it('GET /health -> 200 with ok:true and ts', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(typeof res.body.ts).toBe('number');
  });

  it('GET /api/csrf-token -> returns token and sets cookie', async () => {
    const res = await request(app).get('/api/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toBeTruthy();
    expect(res.headers['set-cookie']).toBeDefined();
  });
});
