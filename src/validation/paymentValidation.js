const Joi = require('joi');
const cc = require('currency-codes');

// SWIFT/BIC: 8 or 11 chars
const bicRegex = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/;

// Accept only real ISO-4217 currency codes
const currencyCode = Joi.string().uppercase().length(3).custom((v, helpers) => {
  if (!cc.code(v)) return helpers.error('any.invalid', { message: 'Invalid ISO 4217 currency code' });
  return v;
}, 'ISO 4217 check');

exports.createPaymentSchema = Joi.object({
  amount: Joi.number().positive().max(100000000).required(),
  currency: currencyCode.required(),
  provider: Joi.string().valid('SWIFT').required(),
  payeeName: Joi.string().min(2).max(120).required(),
  payeeAccountNumber: Joi.string().pattern(/^\d{8,12}$/).required(),
  payeeSwift: Joi.string().uppercase().pattern(bicRegex).required(),

  reference: Joi.string().max(20).allow('', null)
})
