require('dotenv').config();
const mongoose = require('mongoose');
const http = require('http');
const app = require('./app');

// -----------------------------
// MongoDB Connection
// -----------------------------
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("MONGO_URI not set in .env");
  process.exit(1);
}

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// -----------------------------
// Start Server with HTTPS
// -----------------------------

const PORT = process.env.PORT || 4000;
const HOST = '0.0.0.0';
const server = http.createServer(app);

if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, HOST, () => {
    console.log(`Server listening at http://localhost:${PORT}`);
  });
}

module.exports = { app, server };
