// import supertest for HTTP request simulation
const request = require('supertest');
const app = require('../src/app');

// -----------------------------
// HEALTH ENDPOINT TEST
// -----------------------------
//verifies that backend is running and returns correct structure
describe('Health', () => {
  it('GET /health -> 200 with ok:true', async () => {
    //send GET request to /health
    const res = await request(app).get('/health');

    //expect HTTP 200 OK
    expect(res.statusCode).toBe(200);

    //expect response body to indicate service is healthy
    expect(res.body).toHaveProperty('ok', true);

    //timestamp should be a number
    expect(typeof res.body.ts).toBe('number');
  });
});
