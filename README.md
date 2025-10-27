# Secure Messaging Application

This project is a secure client-server messaging application for encrypted communication between multiple clients. It is built with:

- **Server**: Node.js + Express + MongoDB
- **Client**: React

It supports authentication, message encryption, broadcasting via SSE (Server-Sent Events), and secure storage.

---

## Project Structure

secure-messaging-app/
│
├── client/ # React frontend
├── server/ # Node.js backend
│ ├── cert/ # TLS/SSL certificates (.pem/.pfx)
│ ├── logs/ # Server logs (ignored by Git)
│ ├── models/ # Mongoose models
│ ├── routes/ # API routes
│ └── server.js # Main server file
└── README.md


---

## Prerequisites

- Node.js v18+
- MongoDB
- OpenSSL (for generating TLS certificates)

---

## Setup

### 1. Install dependencies

```bash
# Server
cd server
npm install

# Client
cd ../client
npm install
