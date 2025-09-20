# INSY7314 - Backend (MERN Secure Payments API)

## Overview
This is the backend API for the INSY7314 secure Customer International Payments Portal.

- **Technology:** Node.js + Express + MongoDB
- **Authentication:** JWT-based
- **Security:** Password hashing (bcrypt), input validation
- **Roles:** Customer & Employee

It handles user management, payments, and employee verification workflows.

---

## Features Implemented (✅)

### Backend
- User registration and login (Customer & Employee)
- JWT authentication middleware
- Role-based authorization
- Create and view payments (Customer)
- Pending payments and verification (Employee)
- Input validation using regex

### Database / Architecture
- MongoDB with Mongoose
- MERN stack compatible
- Role-based access control

---

## Routes / API Endpoints

### Auth
- `POST /auth/register` – Register a new user  
- `POST /auth/login` – Login and receive JWT

### Customer Payments
- `POST /payments` – Create a payment (requires Customer JWT)  
- `GET /payments/me` – List my payments (requires Customer JWT)

### Employee Workflows
- `GET /payments/pending` – List pending payments (requires Employee JWT)  
- `POST /payments/:id/verify` – Verify a payment (requires Employee JWT)

---

## Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd backend
