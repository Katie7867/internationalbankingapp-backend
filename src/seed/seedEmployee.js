const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
require('dotenv').config()

const User = require('../models/User.js')
const SALT_ROUNDS = 12
const PEPPER = process.env.PEPPER_SECRET || 'devpepper';

// -------------------------
// SEED EMPLOYEE ACCOUNT
// -------------------------
//creates an initial employee user for testing or admin purposes
async function seedEmployee() {
  try {
    //connect to MongoDB securely using environment variable
    await mongoose.connect(process.env.MONGO_URI)

    //check if employee already exists to prevent duplicates
    const existing = await User.findOne({ username: 'employeetest' })
    if (existing) {
      console.log('Employee already exists:', existing.username)
      await mongoose.disconnect()
      return
    }

    //hash password securely before storing
    const passwordHash = await bcrypt.hash('Test@123' + PEPPER , SALT_ROUNDS)

    //create new employee account
    const newEmployee = await User.create({
      fullName: 'Employee 1',
      idNumber: '0401015800123', 
      accountNumber: '12312345',
      username: 'employeetest',
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
