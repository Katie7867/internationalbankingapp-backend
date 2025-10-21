const request = require('supertest');
const express = require('express');
const router = require('../src/routes/employees');
const { auth: _auth, authorize: _authorize } = require('../src/middleware/auth');

// mock auth middleware
jest.mock('../src/middleware/auth', () => ({
  auth: (req, res, next) => next(),
  authorize: () => (req, res, next) => next(),
}));

// mock User model chainable behavior
jest.mock('../src/models/User', () => ({
  find: jest.fn().mockReturnValue({
    select: jest.fn().mockResolvedValue([
      { username: 'emp1', fullName: 'John Employee' },
    ]),
  }),
}));

const app = express();
app.use(express.json());
app.use('/api/employees', router);

describe('Employees Routes', () => {
  it('GET /api/employees should return list', async () => {
    const res = await request(app).get('/api/employees');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('employees');
    expect(Array.isArray(res.body.employees)).toBe(true);
  });
});
