// src/controllers/paymentsController.js
const { Payment } = require('../models/Payment');
const User = require('../models/User'); // use proper model
const { createPaymentSchema } = require('../validation/paymentValidation');

const normalizeStatus = (s) => (s === 'submitted' ? 'pending' : s);

exports.createPayment = async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) return res.status(401).json({ error: 'unauthorized' });

    const { value, error } = createPaymentSchema.validate(req.body, { abortEarly: false });
    if (error) {
      return res.status(400).json({
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      });
    }

    // Normalize
    value.currency = String(value.currency).toUpperCase().trim();
    value.payeeSwift = String(value.payeeSwift).toUpperCase().replace(/\s+/g, '');
    value.payeeAccountNumber = String(value.payeeAccountNumber).replace(/\s+/g, '');
    value.payeeName = String(value.payeeName).trim();
    if (value.reference) value.reference = String(value.reference).trim();

    const payment = await Payment.create({
      customerId: req.user.id,
      amount: value.amount,
      currency: value.currency,
      provider: value.provider || 'SWIFT',
      payeeName: value.payeeName,
      payeeAccountNumber: value.payeeAccountNumber,
      payeeSwift: value.payeeSwift,
      reference: value.reference || '',
      status: 'pending',
      submittedAt: new Date()
    });

    return res.status(201).json({ message: 'Payment created', paymentId: payment._id });
  } catch (err) {
    console.error('CREATE PAYMENT ERROR:', err);
    next(err);
  }
};

exports.listMyPayments = async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) return res.status(401).json({ error: 'unauthorized' });

    const payments = await Payment.find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .lean();

    // normalize legacy statuses for client
    const out = payments.map(p => ({
      ...p,
      status: normalizeStatus(p.status),
      submittedAt: p.submittedAt || p.createdAt
    }));

    res.json({ payments: out });
  } catch (err) {
    console.error('LIST MY PAYMENTS ERROR:', err);
    next(err);
  }
};

exports.listAllPayments = async (req, res, next) => {
  try {
    if (!req.user || req.user.role !== 'employee') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const payments = await Payment.find()
      .sort({ createdAt: -1 })
      .populate('customerId', 'username accountNumber fullName')
      .lean();

    const out = payments.map(p => ({
      _id: p._id,
      amount: p.amount,
      currency: p.currency,
      provider: p.provider,
      payeeName: p.payeeName,
      payeeAccountNumber: p.payeeAccountNumber,
      payeeSwift: p.payeeSwift,
      reference: p.reference,
      status: normalizeStatus(p.status),
      submittedAt: p.submittedAt || p.createdAt,
      customer: p.customerId || null
    }));

    console.log('LIST ALL: found', out.length, 'payments');
    res.json({ payments: out });
  } catch (err) {
    console.error('LIST ALL PAYMENTS ERROR:', err);
    next(err);
  }
};

exports.getPaymentById = async (req, res, next) => {
  try {
    const payment = await Payment.findById(req.params.id).lean();
    if (!payment) return res.status(404).json({ error: 'Payment not found' });

    if (!req.user) return res.status(401).json({ error: 'unauthorized' });
    if (req.user.role !== 'employee' && String(payment.customerId) !== String(req.user.id)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // populate customer info using User model
    let customer = null;
    if (payment.customerId) {
      customer = await User.findById(payment.customerId).select('username accountNumber fullName').lean();
    }

    const out = {
      ...payment,
      status: normalizeStatus(payment.status),
      submittedAt: payment.submittedAt || payment.createdAt,
      customer: customer || null
    };
    delete out.customerId;

    res.json({ payment: out });
  } catch (err) {
    console.error('GET PAYMENT ERROR:', err);
    next(err);
  }
};

exports.updatePaymentStatus = async (req, res, next) => {
  try {
    if (!req.user || req.user.role !== 'employee') return res.status(403).json({ error: 'Unauthorized' });

    const { status } = req.body;
    if (!['sent_to_swift', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const payment = await Payment.findById(req.params.id);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });

    payment.status = status;
    await payment.save();

    res.json({ message: 'Status updated', payment });
  } catch (err) {
    console.error('UPDATE PAYMENT STATUS ERROR:', err);
    next(err);
  }
};