const mongoose = require('mongoose');

//define schema for payment records
const paymentSchema = new mongoose.Schema(
  {
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

    amount: { type: Number, required: true, min: 0.01 },

    currency: { type: String, required: true, uppercase: true, trim: true, match: /^[A-Z]{3}$/},

    provider: { type: String, required: true, enum: ['SWIFT'], default: 'SWIFT' },

    payeeName: { type: String, required: true, trim: true },
    payeeAccountNumber: { type: String, required: true, trim: true },
    payeeSwift: { type: String, required: true, uppercase: true, trim: true },

    reference: { type: String, trim: true, maxlength: 20 },

    //status controlled with enum to prevent invalid values
    status: {
      type: String,
      enum: ['pending','sent_to_swift','rejected'],
      default: 'pending',
      index: true
    },

    //track submission time for auditing
    submittedAt: { type: Date, default: Date.now }
  },
  { timestamps: true } //automatic createdAt and updatedAt fields
);

//index for sorting by creation date efficiently
paymentSchema.index({ createdAt: -1 });

module.exports = {
  Payment: mongoose.model('Payment', paymentSchema)
};
