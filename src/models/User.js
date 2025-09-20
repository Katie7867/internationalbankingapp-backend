const mongoose = require('mongoose')
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  idNumber: { type: String, required: true },
  accountNumber: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['customer','employee'], default: 'customer' }
},{ timestamps: true })

module.exports = mongoose.model('User', userSchema)
