const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const { patterns } = require('../validators')

const router = express.Router()
const SALT_ROUNDS = 12

// -------------------------
// REGISTER
// -------------------------
router.post('/register', async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password, role } = req.body

    // Validation
    if (
      !patterns.fullName.test(fullName) ||
      !patterns.idNumber.test(idNumber) ||
      !patterns.accountNumber.test(accountNumber) ||
      !patterns.username.test(username)
    ) {
      return res.status(400).json({ error: 'validation failed' })
    }

    // Check if user or account exists
    const existing = await User.findOne({ $or: [{ username }, { accountNumber }] })
    if (existing) return res.status(400).json({ error: 'User or account exists' })

    // Hash password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS)

    // Assign role → default to 'customer'
    const assignedRole = role && ['customer', 'employee'].includes(role) ? role : 'customer'

    const newUser = await User.create({
      fullName,
      idNumber,
      accountNumber,
      username,
      passwordHash,
      role: assignedRole
    })

    return res.json({ message: 'registered', userId: newUser._id, role: newUser.role })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server error' })
  }
})

// -------------------------
// LOGIN
// -------------------------
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })
    if (!user) return res.status(401).json({ error: 'invalid credentials' })

    const valid = await bcrypt.compare(password, user.passwordHash)
    if (!valid) return res.status(401).json({ error: 'invalid credentials' })

    const token = jwt.sign(
      { sub: user._id, role: user.role },
      process.env.JWT_SECRET || 'devsecret',
      { expiresIn: '1h' }
    )

    return res.json({ token, role: user.role })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server error' })
  }
})

module.exports = router
