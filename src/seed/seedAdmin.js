const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();
const User = require('../models/User');

const SALT_ROUNDS = 12;
const PEPPER = process.env.PEPPER_SECRET || 'devpepper';

// -------------------------
// SEED ADMIN
// -------------------------

async function seedAdmin() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    const username = 'testadmin';
    const existing = await User.findOne({ username });
    if (existing) {
      console.log('Admin already exists');
      return;
    }

    const password = 'Admin@123';
    const passwordHash = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);

    const admin = await User.create({
      fullName: 'System Administrator',
      idNumber: '0000000000000',
      accountNumber: '99999999',
      username,
      passwordHash,
      role: 'admin',
    });

    console.log('Seeded admin:', admin.username);
    await mongoose.disconnect();
    console.log('Done.');
  } catch (err) {
    console.error('Error seeding admin:', err);
  }
}

seedAdmin();

module.exports = seedAdmin;
