<p align="center">
  <img src="https://github.com/VCDN-2025/insy7314-poe-part-2-ST10249863-TiffanyMather/blob/main/Big5_Bank_logo.png" width="220" alt="Big 5 Bank Logo"/>
</p>

# 🛡️ INSY7314 — Secure International Payments API (Backend)

**Bank:** Big 5 Bank  
**Tech:** Node.js · Express · MongoDB (Mongoose)  
**Security:** HTTPS/TLS, JWT (15min + refresh), bcrypt (12 rounds), Helmet, CSRF, Rate Limiting, Brute-Force Protection, Input Whitelisting (RegEx), CORS, XSS/Injection Prevention  
**CI/CD:** CircleCI → SonarQube + Jest + Coverage | Docker + docker-compose

This repository contains the **REST API** for the INSY7314 Secure Customer & Employee International Payments Portal. It exposes endpoints for **authentication**, **customer payments**, and **employee verification**, implementing comprehensive security controls required by the **INSY7314 POE Task**.

---

## 📖 Table of Contents
1. [Introduction](#-introduction)  
2. [Purpose](#-purpose)  
3. [Prerequisites](#-prerequisites)  
4. [Installation & Quickstart](#-installation--quickstart)  
5. [Environment Configuration (.env)](#-environment-configuration-env)  
6. [SSL/TLS Setup](#-ssltls-setup)  
7. [Running the Application](#-running-the-application)  
8. [API Endpoints](#-api-endpoints)  
9. [Security Implementation](#-security-implementation)  
10. [Attack Protection Details](#-attack-protection-details)  
11. [Input Validation (RegEx Whitelisting)](#-input-validation-regex-whitelisting)  
12. [Testing](#-testing)  
13. [DevSecOps Pipeline](#-devsecops-pipeline)  
14. [Project Structure](#-project-structure)  
15. [Seeding Employee Accounts](#-seeding-employee-accounts)  
16. [Docker Deployment](#-docker-deployment)  
17. [Troubleshooting](#-troubleshooting)  
18. [POE Compliance Checklist](#-poe-compliance-checklist)  
19. [License & Credits](#-license--credits)
20. [Repository Links](#-repository-links)  
21. [Demo Video](#-demo-video)  

---

## 🟢 Introduction
A production-grade, security-hardened banking API that enables:
- **Customer Registration & Login** with password hashing and salting
- **International SWIFT Payment Creation** with comprehensive validation
- **Employee Portal** for payment verification and approval
- **Token-based authentication** with automatic refresh mechanism
- **Complete protection** against OWASP Top 10 vulnerabilities

---

## 🎯 Purpose
Deliver a **secure, auditable, enterprise-ready** backend that:
-  Enforces **bcrypt password hashing with 12 salt rounds**
-  Implements **short-lived JWTs (15min)** with **refresh token rotation**
-  **Whitelists all inputs** using strict RegEx patterns
-  Serves traffic over **HTTPS/TLS** with HSTS headers
-  Prevents **10+ attack vectors**: CSRF, XSS, SQL/NoSQL Injection, Session Hijacking, Clickjacking, MITM, DDoS, Brute Force
-  Provides **role-based access control** (Customer vs Employee vs Admin)
-  Includes **comprehensive error handling** and security logging

---
<p align="center">
  
  <img src="https://media0.giphy.com/media/v1.Y2lkPWFkZWE2ZTUyYzc5c2MxcXFpc2NqeGI4c2hjNXB4bGF2YmozdGFnOHdjb3JtMWRjeiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/077i6AULCXc0FKTj9s/giphy.gif" width="250" alt="wallet GIF"/>
</p>
---

## 🧰 Prerequisites

### Required
- **Node.js 20+** and **npm 9+**
- **MongoDB 6+** (Atlas cloud or local instance)
- **OpenSSL** (for generating SSL certificates)

### Optional
- **Docker** & **docker-compose** (for containerized deployment)
- **CircleCI** account (for CI/CD pipeline)
- **SonarQube** instance (for SAST analysis)

---

## 🚀 Installation & Quickstart

```bash
# 1) Clone the repository
git clone <your-backend-repo-url>
cd backend

# 2) Install dependencies
npm ci

# 3) Generate SSL certificates (see SSL/TLS Setup section)
npm run generate-ssl

# 4) Configure environment variables
cp .env.example .env
# Edit .env with your MongoDB URI and secrets

# 5) Seed employee accounts 
npm run seed

# 6) Start development server with HTTPS
npm run dev

# Server running at https://localhost:4000
```

---

## 🔧 Environment Configuration (.env)

Create a **`.env`** file in the project root:

```env
# ============================================
# APPLICATION SETTINGS
# ============================================
NODE_ENV=development
PORT=4000

# ============================================
# DATABASE
# ============================================

# For MongoDB Atlas:
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/insy7314?retryWrites=true&w=majority

# ============================================
# JWT AUTHENTICATION
# ============================================
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long
JWT_REFRESH_SECRET=your-refresh-token-secret-minimum-32-characters
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# ============================================
# PASSWORD SECURITY
# ============================================
BCRYPT_SALT_ROUNDS=12

# ============================================
# CSRF PROTECTION
# ============================================
CSRF_SECRET=your-csrf-secret-minimum-32-characters-long

# ============================================
# CORS CONFIGURATION
# ============================================
FRONTEND_URL=https://localhost:5173
# For production, use your actual frontend domain

# ============================================
# RATE LIMITING (DDoS Protection)
# ============================================
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100

# ============================================
# BRUTE FORCE PROTECTION
# ============================================
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_TIME_HOURS=2

# ============================================
# SSL/TLS CERTIFICATES
# ============================================
SSL_KEY_PATH=./ssl/server.key
SSL_CERT_PATH=./ssl/server.cert

# ============================================
# LOGGING
# ============================================
LOG_LEVEL=info
```

> **⚠️ CRITICAL:** Never commit `.env` to version control. Add it to `.gitignore`.

---
---
<p align="center">
  
  <img src="https://media4.giphy.com/media/v1.Y2lkPWFkZWE2ZTUyYzc5c2MxcXFpc2NqeGI4c2hjNXB4bGF2YmozdGFnOHdjb3JtMWRjeiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/RDZo7znAdn2u7sAcWH/giphy.gif" alt="shield GIF"/>
</p>

---
## 🔐 SSL/TLS Setup

### For Development (Self-Signed Certificate)

```bash
# Create ssl directory
mkdir ssl

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 -keyout ssl/server.key -out ssl/server.cert -days 365 -nodes -subj "/C=ZA/ST=KwaZulu-Natal/L=Durban/O=Big5Bank/CN=localhost"
```

### For Production

Use **Let's Encrypt** or your organization's CA-signed certificates:

```bash
# Place your production certificates
cp /path/to/production/privkey.pem ssl/server.key
cp /path/to/production/fullchain.pem ssl/server.cert
```

### Trust Self-Signed Certificate (Development)

**Chrome/Edge:**
1. Visit `https://localhost:4000`
2. Click "Advanced" → "Proceed to localhost (unsafe)"

**System-wide (macOS):**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ssl/server.cert
```

---

## ▶️ Running the Application

```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start

# With Docker
docker-compose up --build

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Seed employee accounts
npm run seed
```

---

## 📡 API Endpoints

### Authentication Routes (`/api/auth`)

| Method | Endpoint | Description | Auth Required | Role |
|--------|----------|-------------|---------------|------|
| GET | `/me` | Get current user info | ✅ | Any |
| POST | `/logout` | Logout and invalidate tokens | ✅ | Any |
| POST | `/register` | Register new user |  | Any |

### Customer Payment Routes (`/api/payments`)

| Method | Endpoint | Description | Auth Required | Role |
|--------|----------|-------------|---------------|------|
| POST | `/` | Create international payment | ✅ | Customer |
| GET | `/my-payments` | Get my payment history | ✅ | Customer |

### Employee Routes (`/api/payments`)

| Method | Endpoint | Description | Auth Required | Role |
|--------|----------|-------------|---------------|------|
| GET | `/` | Get all payments (pending/verified) | ✅ | Employee |
| PUT | `/:id/verify` | Verify/approve payment | ✅ | Employee |

### Utility Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check endpoint |
| GET | `/api/csrf-token` | Get CSRF token for forms |

---

## 🛡️ Security Implementation

### 1. Password Security 
- **bcrypt hashing** with 12 salt rounds
- **Automatic salting** on user creation
- **Password complexity requirements**:
  - Minimum 8 characters
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 number
  - At least 1 special character
- Passwords **never stored in plaintext**
- Password change tracking for token invalidation

### 2. Authentication & Authorization 
- **JWT-based authentication**
- **Short-lived access tokens** (15 minutes)
- **Long-lived refresh tokens** (7 days) with rotation
- **HTTPOnly, Secure, SameSite cookies** for token storage
- **Role-based access control** (Customer vs Employee)
- **Token blacklisting** on password change
- **Automatic token refresh** on expiration

### 3. Input Whitelisting (RegEx) 
All inputs validated against strict RegEx patterns:
- Names, ID numbers, account numbers
- SWIFT codes, IBANs
- Amounts, currencies
- See [Input Validation](#-input-validation-regex-whitelisting) section

### 4. SSL/TLS (HTTPS) 
- **All traffic encrypted** with TLS 1.2+
- **HTTPS enforcement** in production
- **HTTP to HTTPS redirect** middleware
- **HSTS headers** with preload
- **Secure cookie flags** enforced

---

## 🔒 Attack Protection Details

###  CSRF (Cross-Site Request Forgery)
- **Implementation:** `csrf-csrf` with double-submit cookie pattern
- **Token generation:** Unique per session
- **Validation:** All POST/PUT/DELETE requests require valid token
- **Cookie security:** HTTPOnly, Secure, SameSite=strict

###  Brute Force Protection
- **Rate limiting:** 5 login attempts per 15 minutes per IP
- **Account lockout:** Lock for 2 hours after 5 failed attempts
- **Exponential backoff:** Increasing delays between attempts
- **IP-based tracking:** Redis/memory store for distributed systems

###  Session Hijacking
- **Short-lived JWTs:** 15-minute expiration
- **Refresh token rotation:** New token on each refresh
- **Token binding:** User agent and IP validation (optional)
- **Logout invalidation:** Server-side token blacklisting

###  Clickjacking
- **X-Frame-Options:** DENY header via Helmet
- **CSP frame-ancestors:** 'none' directive
- **iframe protection:** Prevents embedding in other sites

###  SQL/NoSQL Injection
- **Mongoose parameterized queries:** No string concatenation
- **express-mongo-sanitize:** Strips `$` and `.` from user input
- **Input validation:** RegEx whitelisting before database operations
- **Type coercion prevention:** Strict schema validation

###  XSS (Cross-Site Scripting)
- **Content Security Policy:** Strict CSP via Helmet
- **Input sanitization:** `xss-clean` middleware
- **Output encoding:** React auto-escaping on frontend
- **No inline scripts:** CSP blocks `unsafe-inline`
- **HTTP-only cookies:** JavaScript cannot access tokens

###  MITM (Man-in-the-Middle)
- **HTTPS/TLS encryption:** All traffic encrypted
- **HSTS headers:** Force HTTPS for 1 year with preload
- **Certificate pinning:** Available for mobile apps
- **Secure cookie flags:** Prevent transmission over HTTP

###  DDoS (Distributed Denial of Service)
- **Global rate limiting:** 100 requests per 15 minutes per IP
- **Request size limits:** 10KB max body size
- **Connection timeouts:** 30-second request timeout
- **Helmet security headers:** Various protections
- **Ready for WAF:** Compatible with CloudFlare, AWS WAF

###  Additional Protections
- **HPP (HTTP Parameter Pollution):** `hpp` middleware
- **DNS Rebinding:** Host header validation
- **Open Redirects:** URL validation on redirects
- **XXE (XML External Entity):** JSON-only API
- **Timing Attacks:** Constant-time comparisons

---

##  Input Validation (RegEx Whitelisting)

### Authentication Fields
```javascript
// Full Name: Letters, spaces, hyphens, apostrophes (2-100 chars)
fullName: /^[a-zA-Z\s'-]{2,100}$/

// South African ID Number: Exactly 13 digits
idNumber: /^[0-9]{13}$/

// Account Number: 10-12 digits
accountNumber: /^[0-9]{10,12}$/

// Password: Min 8 chars, 1 upper, 1 lower, 1 digit, 1 special
password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+=\-\[\]{}|\\:;"'<>,.\/])[A-Za-z\d@$!%*?&#^()_+=\-\[\]{}|\\:;"'<>,.\/]{8,}$/
```

### Payment Fields
```javascript
// Amount: Positive number, max 2 decimals, up to 999,999.99
amount: /^(?!0+\.00$)(?:[1-9]\d{0,5}|0)(?:\.\d{1,2})?$/

// Currency: 3 uppercase letters (ISO 4217)
currency: /^[A-Z]{3}$/

// SWIFT/BIC Code: 8 or 11 alphanumeric
swiftCode: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/

// IBAN/Account: 10-34 alphanumeric
recipientAccount: /^[A-Z0-9]{10,34}$/

// Recipient Name: Letters, spaces, hyphens, apostrophes
recipientName: /^[a-zA-Z\s'-]{2,100}$/

// Bank Name: Letters, numbers, spaces, common punctuation
bankName: /^[a-zA-Z0-9\s.,'&-]{2,100}$/
```

### Supported Currencies
```javascript
['USD', 'EUR', 'GBP', 'ZAR', 'JPY', 'AUD', 'CAD', 'CHF', 'CNY', 'INR']
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Watch mode for development
npm run test:watch

# Generate coverage report
npm run test:coverage

# Run specific test file
npm test -- auth.test.js

# Run integration tests only
npm run test:integration
```

### Test Coverage Requirements
- **Statements:** >80%
- **Branches:** >75%
- **Functions:** >80%
- **Lines:** >80%

### Test Structure
```
tests/
├── unit/
│   ├── models/
│   ├── middleware/
│   └── validation/
├── integration/
│   ├── auth.test.js
│   ├── payments.test.js
│   └── admin.test.js
└── setup.js
```

---
<p align="center">
  
  <img src="https://media2.giphy.com/media/v1.Y2lkPWFkZWE2ZTUyYzc5c2MxcXFpc2NqeGI4c2hjNXB4bGF2YmozdGFnOHdjb3JtMWRjeiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/bKj0qEKTVBdF2o5Dgn/giphy.gif" alt=" Access denied GIF"/>
</p>
---

## 🔁 DevSecOps Pipeline

### CircleCI Workflow
```yaml
1. Checkout code
2. Setup Node.js 20
3. Install dependencies (npm ci)
4. Run linter (ESLint)
5. Run security audit (npm audit)
6. Run tests with coverage
7. Upload coverage to Codecov
8. SonarQube SAST analysis
9. Build Docker image
10. Deploy to staging (optional)
```

### SAST (Static Analysis)
- **Tool:** SonarQube
- **Checks:** Code smells, security hotspots, vulnerabilities, duplications
- **Quality Gate:** 0 critical issues, <3% duplication

### SCA (Software Composition Analysis)
- **Tool:** npm audit
- **Checks:** Known vulnerabilities in dependencies
- **Policy:** Block builds with high/critical vulnerabilities

### Container Scanning
- **Tool:** Trivy / Snyk
- **Scans:** Docker images for OS and library vulnerabilities

---

## 📁 Project Structure

```
backend/
├── src/
│   ├── controllers/          # Route logic handlers
│   ├── middleware/
│   │   └── auth.js          # JWT verification & authorization
│   ├── models/
│   │   ├── User.js          # User schema with password hashing
│   │   └── Payment.js       # Payment schema
│   ├── routes/
│   │   ├── auth.js          # Authentication endpoints
│   │   └── payments.js      # Payment endpoints
│   ├── validation/
│   │   ├── authValidation.js    # Auth input validators
│   │   └── paymentValidation.js # Payment input validators
│   ├── seed/
│   │   └── seedEmployee.js  # Employee account seeder
│   └── index.js             # App entry point with security
├── ssl/
│   ├── server.key           # SSL private key
│   └── server.cert          # SSL certificate
├── tests/                   # Test suites
├── .env.example            # Environment template
├── .gitignore
├── package.json
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 👤 Seeding Employee Accounts

**Task 3 Requirement:** Employee accounts must be pre-created (no registration).

```bash
# Seed default employee accounts
npm run seed

# This creates:
# Username: employee1
# Account: 9999999991
# Password: Employee@123

# Username: employee2
# Account: 9999999992
# Password: Employee@123
```

### Manual Employee Creation
```javascript
// src/seed/seedEmployee.js
const employees = [
  {
    fullName: 'John Employee',
    idNumber: '9999999999991',
    accountNumber: '9999999991',
    password: 'Employee@123',
    role: 'employee'
  }
];
```


---

## 🐳 Docker Deployment

### Docker Compose (Development)
```bash
# Build and start all services
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down
```

### Production Docker Build
```bash
# Build optimized image
docker build -t big5bank/backend:latest .

# Run with environment variables
docker run -d \
  -p 4000:4000 \
  --env-file .env \
  --name backend-api \
  big5bank/backend:latest
```

---

## 🔧 Troubleshooting

### Issue: "SSL Certificate Error"
**Solution:**
```bash
# Regenerate certificates
cd ssl
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.cert -days 365 -nodes
```

### Issue: "MongoDB Connection Failed"
**Solution:**
- Check `MONGODB_URI` in `.env`
- Ensure MongoDB is running: `brew services start mongodb-community` (macOS)
- For Atlas: Whitelist your IP in Network Access

### Issue: "CSRF Token Invalid"
**Solution:**
- Ensure frontend calls `/api/csrf-token` before POST requests
- Check `CSRF_SECRET` matches between restarts
- Verify cookies are enabled in browser

### Issue: "Account Locked"
**Solution:**
- Wait 2 hours, OR
- Manually unlock: `db.users.updateOne({accountNumber: "123"}, {$unset: {lockUntil: 1}, $set: {loginAttempts: 0}})`

### Issue: "Port 4000 Already in Use"
**Solution:**
```bash
# Find and kill process
lsof -ti:4000 | xargs kill -9

# Or change PORT in .env
PORT=4001
```

---

## ✅ POE Compliance Checklist

### Task 2: Customer Portal 
- ✅ Password hashing and salting (bcrypt, 12 rounds)
- ✅ Input whitelisting with RegEx patterns
- ✅ SSL/TLS traffic encryption
- ✅ Protection against all listed attacks
- ✅ Customer registration and login
- ✅ International payment creation

### Task 3: Employee Portal 
- ✅ Pre-created employee accounts (no registration)
- ✅ Password hashing and salting
- ✅ Input whitelisting with RegEx
- ✅ SSL/TLS traffic encryption
- ✅ Protection against all attacks
- ✅ Payment verification functionality

### Security Protections 
- ✅ CSRF protection (csrf-csrf)
- ✅ Brute-force protection (rate limiting + account lockout)
- ✅ CORS restrictions (strict whitelist)
- ✅ Session hijacking (JWT rotation)
- ✅ Clickjacking (X-Frame-Options)
- ✅ SQL/NoSQL injection (sanitization + validation)
- ✅ XSS (CSP + xss-clean)
- ✅ MITM (HTTPS + HSTS)
- ✅ DDoS (rate limiting + request limits)

---

## 📋 Sample Requests

### Register Customer
```bash
curl -k -X POST https://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "Tiffany Mather",
    "idNumber": "9512045678901",
    "accountNumber": "1234567890",
    "password": "SecurePass@123"
  }'
```

### Login
```bash
curl -k -X POST https://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "accountNumber": "1234567890",
    "password": "SecurePass@123"
  }'
```

### Create Payment
```bash
curl -k -X POST https://localhost:4000/api/payments \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": "2500.50",
    "currency": "USD",
    "provider": "SWIFT",
    "recipientName": "John Doe",
    "recipientBank": "First National Bank",
    "recipientAccount": "US12345678901234",
    "swiftCode": "FNBAUS33"
  }'
```

### Verify Payment (Employee)
```bash
curl -k -X PUT https://localhost:4000/api/payments/PAYMENT_ID/verify \
  -H "Authorization: Bearer EMPLOYEE_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN"
```

---

## 📜 License & Credits

**License:** MIT License

**Built by:** The Bankrupt Bunch  
**Course:** INSY7314 - Secure Software Development  
**Institution:** Varsity College  
**Year:** 2025

**Security Frameworks:**
- OWASP Top 10 2021
- CWE Top 25
- NIST Cybersecurity Framework

**Technologies:**
- Node.js, Express.js
- MongoDB, Mongoose
- JWT, bcrypt
- Helmet, CORS, express-rate-limit
- Jest, Supertest
- Docker, CircleCI, SonarQube

---

## 📞 Support

For issues or questions:
1. Check [Troubleshooting](#-troubleshooting)
2. Review [API Endpoints](#-api-endpoints)
3. Open an issue on GitHub
4. Contact: tiffany.mather@student.vc.edu

---
---

## 🔗 Repository Links

```
Frontend (this repo): https://github.com/VCDN-2025/insy7314-poe-part-3-ST10249863-TiffanyMather.git
Backend (API):        https://github.com/VCDN-2025/insy7314-poe-part-2-ST10249863-TiffanyMather.git
```

---

## 🎥 Demo Video

[Watch the Demo on YouTube](https://youtu.be/eC-iYNzju1s)

<p align="center">

  <img src="https://media1.giphy.com/media/v1.Y2lkPWFkZWE2ZTUyYzc5c2MxcXFpc2NqeGI4c2hjNXB4bGF2YmozdGFnOHdjb3JtMWRjeiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/sRFEa8lbeC7zbcIZZR/giphy-downsized-medium.gif" width="380" alt=" Bank GIF"/>
</p>

---

**⚠️ Important:** This is an educational project. For production banking systems, conduct thorough security audits, penetration testing, and compliance reviews (PCI DSS, GDPR, etc.).

© 2025 Big 5 Bank - Educational Project
