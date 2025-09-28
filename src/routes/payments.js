const express = require('express');
const router = express.Router();
const { createPayment, listMyPayments, listAllPayments, getPaymentById, updatePaymentStatus  } = require('../controllers/paymentsController');
const { auth } = require('../middleware/auth'); // JWT middleware

router.use(auth);
router.post('/', createPayment);
router.get('/mine', listMyPayments);
router.get('/all', listAllPayments);
router.get('/:id', getPaymentById);
router.patch('/:id/status', updatePaymentStatus);

module.exports = router;
