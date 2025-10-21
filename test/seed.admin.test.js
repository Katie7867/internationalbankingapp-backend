const mongoose = require('mongoose');
const User = require('../src/models/User');

jest.mock('../src/models/User', () => ({
  findOne: jest.fn(),
  create: jest.fn(),
}));

describe('Seed Admin Script', () => {
  it('should connect and exit gracefully', async () => {
    const connect = jest.spyOn(mongoose, 'connect').mockResolvedValue();
    const disconnect = jest.spyOn(mongoose, 'disconnect').mockResolvedValue();

    User.findOne.mockResolvedValue(null);
    User.create.mockResolvedValue({ username: 'testadmin' });

    // import the function and await it
    const seedAdmin = require('../src/seed/seedAdmin.js');
    await seedAdmin();

    expect(connect).toHaveBeenCalled();
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'testadmin',
        role: 'admin',
      })
    );
    expect(disconnect).toHaveBeenCalled();
  });
});
