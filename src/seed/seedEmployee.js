// seedEmployee.js
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
require('dotenv').config()

const User = require('../models/User.js')

const SALT_ROUNDS = 12

async function seedEmployee() {
  try {
    await mongoose.connect(process.env.MONGO_URI)

    // Check if employee already exists
    const existing = await User.findOne({ username: 'testemployee' })
    if (existing) {
      console.log('Employee already exists:', existing.username)
      await mongoose.disconnect()
      return
    }

    const passwordHash = await bcrypt.hash('Test@123', SALT_ROUNDS)

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
    console.error('Error seeding employee:', err)
    process.exit(1)
  }
}

seedEmployee()
