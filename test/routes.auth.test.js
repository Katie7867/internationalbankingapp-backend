
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

jest.mock('../src/models/User'); 

const request = require('supertest');
const app = require('../src/app');
const User = require('../src/models/User'); 

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');  


beforeEach(() => {
  jest.resetAllMocks();
});
afterEach(() => {
  jest.restoreAllMocks();   // restores any jest.spyOn back to the real implementation
  jest.clearAllMocks();     // clears call history
});

// ---------- REGISTER ----------
describe('POST /api/auth/register', () => {
  test('400 when missing fields', async () => {
    const res = await request(app).post('/api/auth/register').send({ username: 'u1' });
    expect(res.status).toBe(400);
  });

  test('400 when validation fails', async () => {
    const body = { fullName: 'A', idNumber: '123', accountNumber: '123', username: 'x', password: 'weak' };
    const res = await request(app).post('/api/auth/register').send(body);
    expect(res.status).toBe(400);
  });

  test('400 when user exists (duplicate)', async () => {
    User.findOne.mockResolvedValue({ _id: 'u1' });
    const body = {
      fullName: 'Valid Name',
      idNumber: '1234567890123',
      accountNumber: '12345678',
      username: 'user_1',
      password: 'Aa1!aaaa'
    };
    const res = await request(app).post('/api/auth/register').send(body);
    expect(res.status).toBe(400);
    expect(User.findOne).toHaveBeenCalled();
  });

  test('200 on success (returns message & userId & role)', async () => {
    User.findOne.mockResolvedValue(null);
    bcrypt.hash = jest.fn().mockResolvedValue('hashed!');
    User.create.mockResolvedValue({ _id: 'u1', role: 'customer' });
    const body = {
      fullName: 'Valid Name',
      idNumber: '1234567890123',
      accountNumber: '12345678',
      username: 'user_1',
      password: 'Aa1!aaaa'
    };
    const res = await request(app).post('/api/auth/register').send(body);
    expect(res.status).toBe(200); // your code uses res.json() without explicit 201
    expect(res.body).toMatchObject({ message: 'registered', userId: 'u1', role: 'customer' });
    expect(bcrypt.hash).toHaveBeenCalled();
    expect(User.create).toHaveBeenCalled();
  });
});

// ---------- LOGIN ----------
describe('POST /api/auth/login', () => {
  test('400 when missing fields', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'u', password: 'p' });
    expect(res.status).toBe(400);
  });

  test('400 invalid account number format', async () => {
    const res = await request(app).post('/api/auth/login').send({
      username: 'user_1', password: 'Aa1!aaaa', accountNumber: '123' // too short
    });
    expect(res.status).toBe(400);
  });

  test('401 when user not found', async () => {
    User.findOne.mockResolvedValue(null);
    const res = await request(app).post('/api/auth/login').send({
      username: 'user_1', password: 'Aa1!aaaa', accountNumber: '12345678'
    });
    expect(res.status).toBe(401);
  });

  test('401 when bad password', async () => {
    User.findOne.mockResolvedValue({ _id: 'u1', role: 'customer', passwordHash: 'hashed' });
    bcrypt.compare = jest.fn().mockResolvedValue(false);
    const res = await request(app).post('/api/auth/login').send({
      username: 'user_1', password: 'wrong', accountNumber: '12345678'
    });
    expect(res.status).toBe(401);
  });

  test('200 on success, sets cookies, returns role', async () => {
    User.findOne.mockResolvedValue({ _id: 'u1', role: 'customer', passwordHash: 'hashed', save: jest.fn() });
    bcrypt.compare = jest.fn().mockResolvedValue(true);
    jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from('refreshId')); // stabilize rid
    jwt.sign = jest.fn().mockReturnValueOnce('access.jwt').mockReturnValueOnce('refresh.jwt');

    const res = await request(app).post('/api/auth/login').send({
      username: 'user_1', password: 'Aa1!aaaa', accountNumber: '12345678'
    });

    expect(res.status).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.body).toMatchObject({ message: 'Login successful', role: 'customer' });
  });
});

// ---------- REFRESH ----------
describe('POST /api/auth/refresh', () => {
  test('401 when no refresh token cookie', async () => {
    const res = await request(app).post('/api/auth/refresh');
    expect(res.status).toBe(401);
  });

  test('401 when invalid refresh token', async () => {
    jest.spyOn(jwt, 'verify').mockImplementation(() => { throw new Error('bad token'); });
    const res = await request(app).post('/api/auth/refresh').set('Cookie', ['refresh_token=bad']);
    expect(res.status).toBe(401);
  });

  test('401 when refresh token revoked/mismatched', async () => {
    jest.spyOn(jwt, 'verify').mockReturnValue({ sub: 'u1', rid: 'RID1' });
    User.findById.mockResolvedValue({ _id: 'u1', refreshId: 'RID2' }); // mismatch
    const res = await request(app).post('/api/auth/refresh').set('Cookie', ['refresh_token=good']);
    expect(res.status).toBe(401);
  });

  test('401 when refresh token expired', async () => {
    jest.spyOn(jwt, 'verify').mockReturnValue({ sub: 'u1', rid: 'RID1' });
    User.findById.mockResolvedValue({ _id: 'u1', refreshId: 'RID1', refreshExpires: Date.now() - 1000 });
    const res = await request(app).post('/api/auth/refresh').set('Cookie', ['refresh_token=good']);
    expect(res.status).toBe(401);
  });

  test('200 on success, rotates and sets cookies', async () => {
    jest.spyOn(jwt, 'verify').mockReturnValue({ sub: 'u1', rid: 'RID1' });
    const save = jest.fn();
    User.findById.mockResolvedValue({ _id: 'u1', role: 'customer', refreshId: 'RID1', refreshExpires: Date.now() + 999999, save });
    jwt.sign = jest.fn().mockReturnValueOnce('new.refresh.jwt').mockReturnValueOnce('new.access.jwt');

    const res = await request(app).post('/api/auth/refresh').set('Cookie', ['refresh_token=good']);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'refreshed' });
    expect(res.headers['set-cookie']).toBeDefined();
  });
});

// ---------- ME ----------
describe('GET /api/auth/me', () => {
  test('401 when no token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  test('401 when token invalid', async () => {
    jest.spyOn(jwt, 'verify').mockImplementation(() => { throw new Error('bad'); });
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer bad');
    expect(res.status).toBe(401);
  });

  test('200 when token valid (header)', async () => {
    jest.spyOn(jwt, 'verify').mockReturnValue({ sub: 'u1', role: 'customer' });
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer good');
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ id: 'u1', role: 'customer' });
  });

  test('200 when token valid (cookie)', async () => {
    jest.spyOn(jwt, 'verify').mockReturnValue({ sub: 'u1', role: 'customer' });
    const res = await request(app).get('/api/auth/me').set('Cookie', ['access_token=good']);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ id: 'u1', role: 'customer' });
  });
});
