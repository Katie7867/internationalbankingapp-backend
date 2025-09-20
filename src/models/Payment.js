const mongoose = require('mongoose')
const paymentSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, required: true },
  provider: { type: String, default: 'SWIFT' },
  payeeAccount: { type: String, required: true },
  swift: { type: String, required: true },
  status: { type: String, enum: ['pending','verified','sent'], default: 'pending' }
},{ timestamps:true })

module.exports = mongoose.model('Payment', paymentSchema)
