const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
require('dotenv').config()

const User = require('../models/User.js')

const SALT_ROUNDS = 12
const PEPPER = process.env.PEPPER_SECRET || 'devpepper'

// -------------------------
// SEED MULTIPLE EMPLOYEES
// -------------------------
async function seedEmployees() {
  try {
    // connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI)
    console.log('Connected to MongoDB')

    // employee data
    const employees = [
      { fullName: 'Employee 1', idNumber: '0401015800123', accountNumber: '12345123', username: 'testemployee', password: 'Test@123' },
      { fullName: 'Employee 2', idNumber: '0401015800456', accountNumber: '12312345', username: 'employeetest', password: 'Test@123' },
      { fullName: 'Employee 3', idNumber: '0401015800789', accountNumber: '123123123', username: 'employee1', password: 'Test@123' },
      { fullName: 'Employee 4', idNumber: '0401015800999', accountNumber: '12121212', username: 'employee2', password: 'Test@123' },
      { fullName: 'Employee 5', idNumber: '0401015800111', accountNumber: '1234512345', username: 'employee3', password: 'Test@123' },
    ]

    for (const emp of employees) {
      const existing = await User.findOne({ username: emp.username })
      if (existing) {
        console.log(`Employee ${emp.username} already exists, skipping.`)
        continue
      }

      const passwordHash = await bcrypt.hash(emp.password + PEPPER, SALT_ROUNDS)

      const newEmployee = await User.create({
        fullName: emp.fullName,
        idNumber: emp.idNumber,
        accountNumber: emp.accountNumber,
        username: emp.username,
        passwordHash,
        role: 'employee'
      })

      console.log('Seeded:', newEmployee.username)
    }

    await mongoose.disconnect()
    console.log('All employees seeded successfully and disconnected from MongoDB.')
  } catch (err) {
    console.error('Error seeding employees:', err)
    process.exit(1)
  }
}

seedEmployees()
