// routes/payment.js
const express = require('express')
const Payment = require('../models/Payment')
const { auth } = require('../middleware/auth') // <-- import actual function
const { patterns } = require('../validators')

const router = express.Router()

// -------------------------
// CUSTOMER ROUTES
// -------------------------

// Role-based middleware for single role
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' })
    if (req.user.role !== role) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}

// Create payment (customer)
router.post('/', auth, requireRole('customer'), async (req, res) => {
  try {
    const { amount, currency, provider, payeeAccount, swift } = req.body

    // Validation
    if (
      !patterns.amount.test(String(amount)) ||
      !patterns.swift.test(swift) ||
      !patterns.accountNumber.test(payeeAccount)
    ) {
      return res.status(400).json({ error: 'validation failed' })
    }

    const payment = await Payment.create({
      customerId: req.user.sub,
      amount: Number(amount),
      currency,
      provider,
      payeeAccount,
      swift
    })

    return res.json({
      message: 'Payment created',
      payment: {
        id: payment._id,
        amount: payment.amount,
        currency: payment.currency,
        provider: payment.provider,
        payeeAccount: payment.payeeAccount,
        swift: payment.swift,
        status: payment.status,
        createdAt: payment.createdAt
      }
    })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server error' })
  }
})

// Get my payments (customer)
router.get('/me', auth, requireRole('customer'), async (req, res) => {
  try {
    const payments = await Payment.find({ customerId: req.user.sub }).sort({ createdAt: -1 })
    res.json(payments)
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server error' })
  }
})

// -------------------------
// EMPLOYEE ROUTES
// -------------------------

// Get pending payments (employee)
router.get('/pending', auth, requireRole('employee'), async (req, res) => {
  try {
    const payments = await Payment.find({ status: 'pending' })
      .populate('customerId', 'fullName accountNumber username')
      .limit(200)
    res.json(payments)
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server error' })
  }
})

// Verify payment (employee)
router.post('/:id/verify', auth, requireRole('employee'), async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.id)
    if (!payment) return res.status(404).json({ error: 'not found' })

    payment.status = 'verified'
    await payment.save()

    // Placeholder: send to SWIFT system (out of scope)
    res.json({ ok: true })
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'server error' })
  }
})

module.exports = router
