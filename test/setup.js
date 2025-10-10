/* eslint-env jest */

process.env.JWT_SECRET = 'test-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.NODE_ENV = 'test';

jest.mock('express-rate-limit');
jest.mock('helmet');
jest.mock('xss-clean');
jest.mock('express-mongo-sanitize');