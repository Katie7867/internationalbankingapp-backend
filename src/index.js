require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const cors = require('cors')
const mongoose = require('mongoose')

const authRoutes = require('./routes/auth')
const paymentRoutes = require('./routes/payments')

const app = express()

// -----------------------------
// Security middlewares
// -----------------------------
app.use(helmet())
app.use(express.json({ limit: '10kb' }))
app.use(cors({ origin: true, credentials: true }))
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 })
app.use(limiter)

// -----------------------------
// Connect to MongoDB Atlas
// -----------------------------
const MONGO_URI = process.env.MONGO_URI
if (!MONGO_URI) {
  console.error("❌ MONGO_URI not set in .env")
  process.exit(1)
}

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err)
    process.exit(1)
  })

// -----------------------------
// Routes
// -----------------------------
app.use('/api/auth', authRoutes)
app.use('/api/payments', paymentRoutes)

app.get('/', (req, res) =>
  res.json({ ok: true, message: 'INSY7314 backend running' })
)

// -----------------------------
// Global Error Handler
// -----------------------------
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: 'server error' })
})

// -----------------------------
// Start Server
// -----------------------------
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
