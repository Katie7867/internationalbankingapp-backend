// routes/payments.js
const express = require('express')
const Payment = require('../models/Payment')
const { auth } = require('../middleware/auth')
const { patterns } = require('../validators')

const router = express.Router()

// -------------------------
// ROLE CHECK
// -------------------------
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' })
    if (req.user.role !== role) return res.status(403).json({ error: 'forbidden' })
    next()
  }
}

// -------------------------
// CUSTOMER ROUTES
// -------------------------

// Create payment
router.post('/', auth, requireRole('customer'), async (req, res, next) => {
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

    if (!['USD', 'EUR', 'ZAR'].includes(currency)) {
      return res.status(400).json({ error: 'unsupported currency' })
    }

    const payment = await Payment.create({
      customerId: req.user.sub,
      amount: Number(amount),
      currency,
      provider: provider || 'SWIFT',
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
    next(e)
  }
})

// Get my payments
router.get('/me', auth, requireRole('customer'), async (req, res, next) => {
  try {
    const payments = await Payment.find({ customerId: req.user.sub }).sort({ createdAt: -1 })
    res.json(payments)
  } catch (e) {
    next(e)
  }
})

// -------------------------
// EMPLOYEE ROUTES
// -------------------------

// Get pending payments
router.get('/pending', auth, requireRole('employee'), async (req, res, next) => {
  try {
    const payments = await Payment.find({ status: 'pending' })
      .populate('customerId', 'fullName accountNumber username')
      .limit(200)
    res.json(payments)
  } catch (e) {
    next(e)
  }
})

// Verify payment
router.post('/:id/verify', auth, requireRole('employee'), async (req, res, next) => {
  try {
    const payment = await Payment.findById(req.params.id)
    if (!payment) return res.status(404).json({ error: 'not found' })

    payment.status = 'verified'
    await payment.save()

    res.json({ ok: true, payment })
  } catch (e) {
    next(e)
  }
})

// Send payment
router.post('/:id/send', auth, requireRole('employee'), async (req, res, next) => {
  try {
    const payment = await Payment.findById(req.params.id)
    if (!payment) return res.status(404).json({ error: 'not found' })

    if (payment.status !== 'verified') {
      return res.status(400).json({ error: 'payment must be verified first' })
    }

    payment.status = 'sent'
    await payment.save()

    res.json({ ok: true, payment })
  } catch (e) {
    next(e)
  }
})

module.exports = router
