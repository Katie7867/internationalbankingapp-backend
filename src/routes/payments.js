const express = require('express');
const router = express.Router();
const { createPayment, listMyPayments, listAllPayments, getPaymentById, updatePaymentStatus  } = require('../controllers/paymentsController');
const { auth } = require('../middleware/auth'); //JWT authentication middleware

// -------------------------
// PROTECT ALL PAYMENT ROUTES
// -------------------------
//require user to be authenticated for all payment actions
router.use(auth);

//create a new payment for authenticated user
router.post('/', createPayment);

//list payments belonging only to the authenticated user
router.get('/mine', listMyPayments);

//list all payments (employee-only access enforced in controller)
router.get('/all', listAllPayments);

//get details of a single payment; access checked in controller
router.get('/:id', getPaymentById);

//update payment status (employee-only access enforced in controller)
router.patch('/:id/status', updatePaymentStatus);

module.exports = router;
