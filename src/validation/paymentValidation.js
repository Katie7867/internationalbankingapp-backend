const Joi = require('joi');
const cc = require('currency-codes');

//regex for SWIFT/BIC: 8 or 11 characters, uppercase letters and digits
const bicRegex = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/;

//validate currency code against real ISO 4217 codes
const currencyCode = Joi.string().uppercase().length(3).custom((v, helpers) => {
  if (!cc.code(v)) return helpers.error('any.invalid', { message: 'Invalid ISO 4217 currency code' });
  return v;
}, 'ISO 4217 check');

// -------------------------
// PAYMENT CREATION VALIDATION
// -------------------------
//ensures all inputs are valid, safe, and within allowed ranges
exports.createPaymentSchema = Joi.object({
  //amount must be positive and within a reasonable limit
  amount: Joi.number().positive().max(100000000).required(),

  //currency must be a valid ISO 4217 code
  currency: currencyCode.required(),

  //provider must be SWIFT only
  provider: Joi.string().valid('SWIFT').required(),

  //payee name: 2-120 characters, prevents empty or invalid names
  payeeName: Joi.string().min(2).max(120).required(),

  //account number: 8-12 digits to prevent invalid accounts
  payeeAccountNumber: Joi.string().pattern(/^\d{8,12}$/).required(),

  //SWIFT/BIC code: validate format to prevent invalid bank info
  payeeSwift: Joi.string().uppercase().pattern(bicRegex).required(),

  //optional reference: max 20 chars
  reference: Joi.string().max(20).allow('', null)
})
