// routes/employees.js
const express = require('express');
const { auth, authorize } = require('../middleware/auth');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const { patterns } = require('../validation/authValidation');
const zxcvbn = require('zxcvbn');
const PEPPER = process.env.PEPPER_SECRET || 'devpepper';
const SALT_ROUNDS = 12;

const router = express.Router();

// GET: list all employees
router.get('/', auth, authorize('admin'), async (req, res) => {
  try {
    const employees = await User.find({ role: 'employee' }).select('-passwordHash -refreshId -refreshExpires');
    res.json({ employees });
  } catch (err) {
    res.status(500).json({ error: 'server error', details: err.message });
  }
});

// POST: register new employee (admin only)
router.post('/register', auth, authorize('admin'), async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    if (!fullName || !idNumber || !accountNumber || !username || !password)
      return res.status(400).json({ error: 'All fields required' });

    if (
      !patterns.fullName.test(fullName) ||
      !patterns.idNumber.test(idNumber) ||
      !patterns.accountNumber.test(accountNumber) ||
      !patterns.username.test(username) ||
      !patterns.password.test(password)
    )
      return res.status(400).json({ error: 'Validation failed' });

    const existing = await User.findOne({ $or: [{ username }, { accountNumber }] });
    if (existing) return res.status(400).json({ error: 'Employee already exists' });

    const strength = zxcvbn(password);
    if (strength.score < 2)
      return res.status(400).json({ error: 'Password too weak' });

    const passwordHash = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);
    const employee = await User.create({
      fullName, idNumber, accountNumber, username, passwordHash, role: 'employee'
    });

    res.json({ message: 'Employee registered', employeeId: employee._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

module.exports = router;
