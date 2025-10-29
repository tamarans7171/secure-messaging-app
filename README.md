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

## Environment variables

Create `server/.env` (or set env vars in your environment). Important variables used by the project:

- `MONGO_URL` — MongoDB connection string (required for server and tests).
- `REDIS_URL` — Redis connection for cross-worker pub/sub (optional for single-process runs).
- `JWT_SECRET` — Secret used to sign JWTs (required).
- `MESSAGE_AES_KEY` — Base64-encoded 32-byte AES key used to encrypt messages at rest. If not provided, you can enable `DEV_PERSIST_MESSAGE_KEY=1` to generate and persist a key for local development (see note below).
- `DEV_PERSIST_MESSAGE_KEY` — When `1`, server will create `server/data/MESSAGE_AES_KEY` containing a generated base64 key (development convenience only).
- `GROUP_AES_KEY` — Optional base64 32-byte AES key shared with clients to allow client-side decryption of broadcasts/history.
- `SSL_PFX_PATH` / `SSL_PFX_PASS` — Path and passphrase for HTTPS PFX bundle (development cert at `server/cert/server.pfx` is provided).
- `RSA_PRIVATE_KEY_PATH` / `RSA_PUBLIC_KEY_PATH` — Optional RSA key file paths. If omitted the server generates an ephemeral RSA pair on startup.
- `PORT` — Server port (default: 3001).

Example minimal `server/.env` for local development:

```
MONGO_URL=mongodb://localhost:27017/secure-chat
REDIS_URL=redis://localhost:6379
JWT_SECRET=change_me_for_demo
DEV_PERSIST_MESSAGE_KEY=1
SSL_PFX_PATH=server/cert/server.pfx
SSL_PFX_PASS=1234
PORT=3001
```

Note: `DEV_PERSIST_MESSAGE_KEY` is a development-only convenience that persists a generated `MESSAGE_AES_KEY` to `server/data/`. Do NOT use this method for production key management; use a secret manager instead.

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

## Features implemented

- Authentication: Username/password with bcrypt hashing; JWT for authorization.
- Transport encryption: TLS for all HTTP and SSE endpoints (development certificate included).
- Client→server envelope: client encrypts messages with server RSA public key; server decrypts with private key.
- Broadcasting without WebSockets: SSE (`/events`) plus Redis pub/sub for multi-worker broadcasts.
- Encryption at rest: messages are stored encrypted using AES-256-GCM (`MESSAGE_AES_KEY`) — the server encrypts on write and attempts to decrypt on read; when server cannot decrypt it returns the encrypted blob so clients holding the group key may decrypt locally.
- Logging: Winston logs significant events (registration, login, message send, SSE connects/disconnects).
- Query API: Authenticated GET `/messages` supports pagination and returns decrypted plaintext when the server can decrypt, else an encrypted blob.

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
  - Authenticated SSE stream for broadcasts (supports `?token=` or `Authorization: Bearer <token>`). Returns messages as `{ sender, content, timestamp }` where `content` is either plaintext or an object `{ mode: 'aes-gcm' | 'plaintext', ... }`.

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

## Security & design choices

- Transport Security (TLS):
  - The server runs exclusively over HTTPS using a PFX bundle.

- Authentication:
  - Passwords are hashed with `bcrypt` (cost factor 12).
  - JWT used for authorization to protected endpoints (`/send`, `/messages`).

- Encryption in Transit:
  - Client encrypts message content with server RSA public key (currently PKCS#1 v1.5 via JSEncrypt), server decrypts with private key.
  - SSE and all HTTP endpoints are over TLS.


- Encryption at rest:
  - Messages are encrypted using AES-256-GCM before being stored. The server uses `MESSAGE_AES_KEY` (base64 32-bytes) to encrypt/decrypt messages. If the server cannot decrypt a stored message (missing or rotated key), it returns an encrypted blob so clients that possess the group key can decrypt locally.

  Development note:
  - For the demo you may enable `DEV_PERSIST_MESSAGE_KEY=1` so the server generates and persists a key in `server/data/`. This is only for local testing and demonstration.

- Hybrid crypto:
  - The server accepts RSA-encrypted envelopes; for production prefer hybrid encryption (AES-GCM for message body + RSA-OAEP to wrap the AES key).

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
