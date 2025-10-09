// test/health.test.js
const request = require('supertest');
const app = require('../src/app');

describe('Health', () => {
  it('GET /health -> 200 with ok:true', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('ok', true);
    expect(typeof res.body.ts).toBe('number');
  });
});
