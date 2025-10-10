// src/models/__mocks__/User.js
const { jest: Jest } = require('@jest/globals');
module.exports = {
  findOne: Jest.fn(),
  findById: Jest.fn(),
  create: Jest.fn(),
};