const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema(
  {
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: true, min: 0.01 },
    currency: { type: String, required: true, uppercase: true, trim: true, match: /^[A-Z]{3}$/},
    provider: { type: String, required: true, enum: ['SWIFT'], default: 'SWIFT' },

    payeeName: { type: String, required: true, trim: true },
    payeeAccountNumber: { type: String, required: true, trim: true },
    payeeSwift: { type: String, required: true, uppercase: true, trim: true }, 

    reference: { type: String, trim: true, maxlength: 35 }, 

    status: {
      type: String,
      enum: ['submitted','pending_verification','verified','sent_to_swift','failed','cancelled'],
      default: 'submitted',
      index: true
    },
    submittedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

paymentSchema.index({ createdAt: -1 });

module.exports = {
  Payment: mongoose.model('Payment', paymentSchema)
};
