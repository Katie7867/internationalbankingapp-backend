<p align="center">
  
  <img src="https://github.com/VCDN-2025/insy7314-poe-part-2-ST10249863-TiffanyMather/blob/main/Big5_Bank_logo.png" width="220" alt="Big 5 Bank Logo"/>
</p>

# 🛡️ INSY7314 — Secure International Payments API (Backend)

**Bank:** Big 5 Bank  
**Tech:** Node.js · Express · MongoDB (Mongoose)  
**Security:** HTTPS, JWT (short-lived), bcrypt, Helmet, rate limiting, brute-force protection, input whitelisting, CORS, centralised error handling  
**CI/CD:** CircleCI → SonarQube + Jest + coverage | Dockerfile + docker-compose

This repository contains the **REST API** for the INSY7314 Secure Customer & Employee International Payments Portal. It exposes endpoints for **auth**, **customer payments**, and **employee verification**, and implements the security controls required by the **INSY7314 POE** tasks and rubrics.

---

## 📖 Table of Contents
1. [Introduction](#-introduction)  
2. [Purpose](#-purpose)  
3. [Prerequisites](#-prerequisites)  
4. [Quickstart](#-quickstart)  
5. [.env Configuration](#-env-configuration)  
6. [Running (HTTPS, Docker, CircleCI)](#-running-https-docker-circleci)  
7. [API Endpoints](#-api-endpoints)  
8. [Security Controls](#-security-controls)  
9. [Validation (Regex Whitelists)](#-validation-regex-whitelists)  
10. [Testing](#-testing)  
11. [DevSecOps (CI/CD + SAST + SCA)](#-devsecops-cicd--sast--sca)  
12. [Alignment with INSY7314 POE](#-alignment-with-insy7314-poe)  
13. [Sample Requests](#-sample-requests)  
14. [License & Credits](#-license--credits)

---

## 🟢 Introduction
A secure banking API to:
- Register/login **Customers** and **Employees**  
- Allow **Customers** to create international **SWIFT** payments  
- Allow **Employees** to review **pending** payments and **verify** them

---

## 🟠 Purpose
Provide a **hardened, auditable** backend that:
- Enforces **password hashing + salting** (bcrypt)  
- Uses **short-lived JWTs** and role-based authorization  
- Validates/whitelists **all inputs** with regex  
- Serves traffic over **HTTPS** in dev and supports secure deployment  
- Blocks common attacks with **Helmet**, **rate limiting**, **express-brute**, **CORS** rules

---

## 🧰 Prerequisites
- **Node.js 20+** and **npm**  
- **MongoDB** (Atlas or local)  
- **OpenSSL certs** for local HTTPS (`ssl/key.pem`, `ssl/cert.pem`)  
- (Optional) **Docker** / **docker-compose**  
- (Optional) **CircleCI** & **SonarQube** project

---

## 🚀 Quickstart
```bash
# 1) Clone
git clone <your-backend-repo-url>
cd backend

# 2) Install
npm ci

# 3) Configure environment
cp .env.example .env   # then edit values

# 4) Run dev (HTTPS)
npm run dev    # nodemon + HTTPS (see .env)
# => https://localhost:4000
```

---

## 🔧 .env Configuration
Create **`.env`** in the project root:

```env

PORT=4000
MONGO_URI=mongodb+srv://macegolf:MattINSY123%24@pulsevote-cluster.xqq4rsb.mongodb.net/insy7314?retryWrites=true&w=majority
JWT_SECRET=Yc7$2!kL9%Jd8@Mn3*Vx
NODE_ENV=development
FRONTEND_ORIGIN=https://localhost:5173



# App
NODE_ENV=development
PORT=4000

# Mongo
MONGO_URI=mongodb://localhost:27017/insy7314

# Auth
JWT_SECRET=change_me
JWT_EXPIRES_IN=15m
BCRYPT_SALT_ROUNDS=12

# Security
CORS_ORIGIN=https://localhost:5173
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=100
BRUTE_FREE_RETRIES=5
BRUTE_LIFETIME_SEC=900

# HTTPS (dev)
SSL_KEY_PATH=./ssl/key.pem
SSL_CERT_PATH=./ssl/cert.pem

# Logging
LOG_LEVEL=info
```

> **Note:** Secrets must **never** be committed to source control.

---

## 🔐 Running (HTTPS, Docker, CircleCI)

### Local HTTPS
Express boots an HTTPS server when `SSL_KEY_PATH` and `SSL_CERT_PATH` are present.

```
/ssl
  ├─ key.pem
  └─ cert.pem
  └─openssl.cnf

```

### Docker
```bash
# build and run
docker compose up --build
# API => https://localhost:4000
```

### CircleCI (CI/CD)
The pipeline runs **Jest** tests, uploads **coverage**, and triggers **SonarQube** analysis.  
See **`.circleci/config.yml`**.

---

## 📡 API Endpoints

### Auth
- `POST /api/v1/auth/register` — Register **Customer** (Employee accounts are pre-created)  
- `POST /api/v1/auth/login` — Login (Customer or Employee) → **JWT**

### Customer
- `POST /api/v1/payments` — Create payment (**Customer JWT**)  
- `GET  /api/v1/payments/my` — My payments (**Customer JWT**)

### Employee
- `GET  /api/v1/admin/payments/pending` — List pending (**Employee JWT**)  
- `POST /api/v1/admin/payments/:id/verify` — Verify payment (**Employee JWT**)

---

## 🛡️ Security Controls

| Control              | Implementation                                                                 |
|----------------------|---------------------------------------------------------------------------------|
| Password hashing     | **bcrypt** with `BCRYPT_SALT_ROUNDS`; never store plaintext                     |
| Auth                 | Short-lived **JWT**; role claim: `customer` / `employee`                        |
| Transport            | **HTTPS** in dev (local certs) and prod (reverse proxy/ingress)                 |
| Headers              | `helmet()` (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)           |
| Rate limiting        | `express-rate-limit` with `RATE_LIMIT_*` envs                                   |
| Brute force          | `express-brute` or memory/Redis store for login endpoints                       |
| Input validation     | Central validators + **regex whitelisting** for IDs, SWIFT, amounts, names      |
| CORS                 | Allowlist via `CORS_ORIGIN`                                                     |
| Error handling       | Centralised handler: hides stack in prod; structured logging                    |
| Logging/Audit        | `morgan` (HTTP) + app logger; include request ids                               |
| Secrets              | `.env` only; never in repo; use vault/CI secrets for prod                       |

---

## ✅ Validation (Regex Whitelists)
*(Used both in request validators and at the schema level.)*
```txt
Name          : ^[A-Za-z][A-Za-z\s\-']{1,49}$
ID Number     : ^\d{6,20}$
Account Number: ^\d{6,20}$
SWIFT/BIC     : ^[A-Z0-9]{8}([A-Z0-9]{3})?$
Amount        : ^\d+(\.\d{1,2})?$
Currency (ISO): ^[A-Z]{3}$
```

---

## 🧪 Testing
```bash
# unit + integration tests
npm test

# watch mode
npm run test:watch

# coverage
npm run test:cov
```

**Outputs**
- Coverage HTML: `./coverage/`  
- JUnit XML: `./test-results/` (for CI)

---

## 🔁 DevSecOps (CI/CD + SAST + SCA)
- **CircleCI workflow:** `checkout → node setup → npm ci → lint → test → coverage → sonar-scanner`  
- **SAST:** SonarQube (code smells, hotspots, duplication)  
- **SCA:** `npm audit --omit=dev` (dependency vulnerabilities)  
- **Artifacts:** test results + coverage uploaded for inspection

---

## 🧭 Alignment with INSY7314 POE
This backend implements the POE requirements for **password security**, **input whitelisting**, **SSL/TLS**, and **protection against listed attacks**; it also includes an optional **DevSecOps** pipeline with **SonarQube** and supports **preconfigured employee accounts** to meet the staff portal constraints.

---

## 🧪 Sample Requests

### Register (Customer)
```bash
curl -k -X POST https://localhost:4000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName": "Tiffany Mather",
    "idNumber": "1234567890123",
    "accountNumber": "123456123456",
    "password": "Test@123"
  }'
```

### Login (Customer/Employee)
```bash
curl -k -X POST https://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{ "username": "testcustomer", "accountNumber": "123456123456", "password": "Test@123" }'
# => { "token": "JWT..." }
```

### Create Payment (Customer)
```bash
curl -k -X POST https://localhost:4000/api/v1/payments \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": "1500.00",
    "currency": "USD",
    "provider": "SWIFT",
    "payeeAccount": "9876543210",
    "swiftCode": "ABCDUS33"
  }'
```

### Verify Payment (Employee)
```bash
curl -k -X POST https://localhost:4000/api/v1/admin/payments/663de1f5a1/verify \
  -H "Authorization: Bearer <EMPLOYEE_JWT>"
```

---

## 📜 License & Credits
- **License:** MIT (see `LICENSE`)  
- Built by **The Bankrupt Bunch** for **INSY7314** at **Big 5 Bank**.  
- © 2025 — Educational use. All trademarks belong to their respective owners.
