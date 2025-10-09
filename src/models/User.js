const mongoose = require('mongoose');

//define schema for user accounts
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  idNumber: { type: String, required: true },
  accountNumber: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },

  //store hashed password only
  passwordHash: { type: String, required: true },

  //role-based access control: customer or employee
  role: { type: String, enum: ['customer', 'employee'], default: 'customer' },

  //refresh token id for secure session management
  refreshId: { type: String, default: null },

  //expiration for refresh token to enforce session security
  refreshExpires: { type: Date, default: null }
}, { timestamps: true }); //automatic createdAt and updatedAt fields

module.exports = mongoose.model('User', userSchema);
