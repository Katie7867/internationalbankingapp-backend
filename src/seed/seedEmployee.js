const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
require('dotenv').config()

const User = require('../models/User.js')
const SALT_ROUNDS = 12

// -------------------------
// SEED EMPLOYEE ACCOUNT
// -------------------------
//creates an initial employee user for testing or admin purposes
async function seedEmployee() {
  try {
    //connect to MongoDB securely using environment variable
    await mongoose.connect(process.env.MONGO_URI)

    //check if employee already exists to prevent duplicates
    const existing = await User.findOne({ username: 'testemployee' })
    if (existing) {
      console.log('Employee already exists:', existing.username)
      await mongoose.disconnect()
      return
    }

    //hash password securely before storing
    const passwordHash = await bcrypt.hash('Test@123', SALT_ROUNDS)

    //create new employee account
    const newEmployee = await User.create({
      fullName: 'Employee 1',
      idNumber: '0401015800087', 
      accountNumber: '12345123',
      username: 'testemployee',
      passwordHash,
      role: 'employee'
    })

    console.log('Employee seeded successfully:', newEmployee)
    await mongoose.disconnect()
  } catch (err) {
    //log error and exit process to avoid inconsistent state
    console.error('Error seeding employee:', err)
    process.exit(1)
  }
}

seedEmployee()
