const express = require('express');
const router = express.Router();
const { createPayment, listMyPayments } = require('../controllers/paymentsController');
const { auth } = require('../middleware/auth'); // JWT middleware

router.use(auth);
router.post('/', createPayment);
router.get('/mine', listMyPayments);

module.exports = router;
