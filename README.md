# Secure Messaging Application

A secure client-server messaging application supporting authentication, encrypted communication, and broadcast messaging without WebSockets.

- Server: Node.js, Express, MongoDB (Mongoose), HTTPS/TLS, JWT, bcrypt, winston
- Client: React, Axios, JSEncrypt, Server-Sent Events (SSE)

The app demonstrates secure credentials handling, TLS transport, RSA-based message submission, and SSE broadcasting. Notes on encryption-at-rest and scalability are included below.

---

## Project Structure

secure-messaging-app/
- client/ — React frontend
- server/ — Node.js backend
  - cert/ — TLS certificates (optional)
  - logs/ — server logs (created at runtime)
  - models/ — Mongoose models
  - server.js — server entry
- README.md

---

## Prerequisites

- Node.js 18+
- MongoDB (local or remote)
- OpenSSL (for local dev certificate)

---

## Environment Variables

Create `server/.env` with:

```
MONGO_URL=mongodb://localhost:27017/secure_messaging
JWT_SECRET=replace-with-a-long-random-secret

# HTTPS (PFX bundle)
SSL_PFX_PATH=./cert/server.pfx
SSL_PFX_PASS=1234

# Optional RSA keys (if not provided, the server generates ephemeral keys on startup)
# RSA_PRIVATE_KEY_PATH=./cert/private.pem
# RSA_PUBLIC_KEY_PATH=./cert/public.pem
```

---

## Generate a Development TLS Certificate

```bash
# Generate self-signed cert and key (PEM)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# Create a PFX for the Node HTTPS server
openssl pkcs12 -export -out server.pfx -inkey key.pem -in cert.pem -passout pass:1234

# Move into server/cert/
mkdir -p server/cert
mv server.pfx server/cert/
```

Note: Browsers will warn on self-signed certs. Proceed for local development.

---

## Install & Run

```bash
# Install server deps
cd server
npm install

# Install client deps
cd ../client
npm install
```

Start the server (HTTPS):

```bash
cd server
npm start
# Server listens on https://localhost:3001
```

Start the client (React dev server):

```bash
cd client
npm start
# App opens at http://localhost:3000
```

---

## Features Mapped to Requirements

- Authentication: Username/password with bcrypt hashing, JWT for session tokens.
- Encrypted transport: All API and SSE endpoints run over HTTPS/TLS.
- Public/private key mechanism: Server exposes RSA public key; client encrypts message payloads using RSA before sending; server decrypts with private key.
- Broadcasting without WebSockets: Implemented using SSE (`/events`); all connected clients receive broadcast messages.
- Message storage: Messages are persisted in MongoDB. Note: current model stores plaintext (see Security section for at-rest encryption recommendation).
- Logging: Winston logs significant events (registration, login, message send, SSE connects/disconnects).
- Query API: Authenticated endpoint to fetch recent messages.

---

## API Reference

Base URL: `https://localhost:3001`

- GET `/public-key`
  - Returns the server RSA public key (PEM, text/plain).

- POST `/register`
  - Body: `{ "username": string, "password": string }`
  - Creates a new user (bcrypt-hashed password).

- POST `/login`
  - Body: `{ "username": string, "password": string }`
  - Returns: `{ "token": string }` (JWT, 1h expiry).

- GET `/events` (SSE stream)
  - Stream of broadcast messages in the form `{ sender, content, timestamp }`.
  - Note: Current implementation does not require auth on the SSE stream (see Security section for recommended hardening).

- POST `/send`
  - Body: `{ "token": string, "content": string }`
    - `content` is a base64 string containing RSA-encrypted payload from the client.
  - On success, message is broadcast to all connected SSE clients.

- GET `/messages`
  - Headers: `Authorization: Bearer <JWT>`
  - Returns the most recent messages.

---

## Client Usage (React)

- Register a user, then log in to obtain a JWT.
- The chat view:
  - Fetches RSA public key from `/public-key`.
  - Opens an SSE connection to `/events` for real-time broadcasts.
  - Encrypts your message using RSA and posts to `/send` with your JWT.

---

## Security & Design Choices

- Transport Security (TLS):
  - The server runs exclusively over HTTPS using a PFX bundle.

- Authentication:
  - Passwords are hashed with `bcrypt` (cost factor 12).
  - JWT used for authorization to protected endpoints (`/send`, `/messages`).

- Encryption in Transit:
  - Client encrypts message content with server RSA public key (currently PKCS#1 v1.5 via JSEncrypt), server decrypts with private key.
  - SSE and all HTTP endpoints are over TLS.

- Encryption at Rest (Recommendation):
  - The current `Message` model stores plaintext content. For the exercise requirement “encrypted at rest,” implement AES-256-GCM using a server-held key (e.g., `MESSAGE_AES_KEY`), storing `iv`, `ciphertext`, and `authTag` per message, and decrypting for authorized reads.

  Note about development/homework use:
  - For the purposes of a take-home assignment or local development it's acceptable to use a temporary key or use the provided convenience `DEV_PERSIST_MESSAGE_KEY` behavior so you can demonstrate encryption-at-rest across restarts. This is intended only for development and testing. Do NOT use a persisted or temporary key like this in production; instead, store `MESSAGE_AES_KEY` in a proper secrets manager and follow secure key-rotation practices.

- Hybrid Crypto (Recommendation):
  - RSA is not suitable for large payloads. Prefer hybrid encryption: encrypt the message with AES-GCM, then wrap the AES key with RSA (OAEP preferred), enabling longer messages and modern security.

- SSE vs WebSockets:
  - SSE is used to satisfy the “no WebSockets” constraint and supports one-way server->client streams efficiently.

- Logging:
  - Winston writes to console and rotating files in `server/logs/`.

---

## Scalability Notes (10,000 Concurrent Connections)

To handle 10k+ SSE clients:
- Run multiple Node processes (PM2/cluster) across CPU cores.
- Place behind a reverse proxy (nginx) with HTTP/2, tuned timeouts, and keepalive.
- Implement periodic SSE heartbeats to detect dead connections and keep intermediaries from closing idle streams.
- Increase OS file descriptor limits (ulimits) and tune Node/HTTP server headers accordingly.
- Ensure non-blocking handlers; avoid synchronous heavy work in the request path.

The current code demonstrates SSE broadcasting and is a good starting point; production scaling requires the above operational tuning.

---

## Seeding the Database (Script)

Add a script (example path `server/scripts/seed.js`) to insert mock users and messages. Example flow:
- Connect to `MONGO_URL`.
- Create users with `bcrypt`-hashed passwords.
- Insert messages (encrypted if at-rest encryption is implemented).

Run with:

```bash
node server/scripts/seed.js
```

---

## Tests

Recommended unit tests (e.g., Jest):
- User authentication: registration, bcrypt hash verification, login issuing JWT.
- Message encryption/decryption: AES-GCM round-trip (if at-rest encryption implemented) and RSA unwrap for hybrid.
- Broadcasting: Posting to `/send` results in downstream SSE message for connected clients.

Add scripts to `server/package.json`:

```json
{
  "scripts": {
    "test": "jest"
  }
}
```

Then run:

```bash
cd server
npm test
```

---

## Trade-offs & Limitations

- Messages are currently stored in plaintext; implement AES-GCM for encryption at rest to fully meet the requirement.
- SSE endpoint is unauthenticated; add JWT verification to `/events` to prevent unauthorized listeners.
- JSEncrypt uses PKCS#1 v1.5; prefer RSA-OAEP and a hybrid scheme for larger/safer messages.
- Operational scaling (10k+) depends on clustering, proxying, and OS tuning not shown in code.

---

## License

For educational/demonstration purposes. Adjust and harden before production use.
