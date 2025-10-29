// server.js
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { privateDecrypt, generateKeyPairSync, randomBytes, createCipheriv, createDecipheriv } = require("crypto");
const winston = require("winston");
const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
app.use(cors());
app.use(express.json());

// --- Logging (winston) ---
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// --- DB connect ---
mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info("MongoDB connected"))
  .catch(err => {
    logger.error("MongoDB connection error", { error: err });
    process.exit(1);
  });

// --- RSA key management ---
let privateKeyPem;
let publicKeyPem;

// אם קיימים קבצים בסביבה נטען, אחרת ניצור ephemeral keys
if (process.env.RSA_PRIVATE_KEY_PATH && process.env.RSA_PUBLIC_KEY_PATH) {
  try {
    privateKeyPem = fs.readFileSync(process.env.RSA_PRIVATE_KEY_PATH, "utf8");
    publicKeyPem = fs.readFileSync(process.env.RSA_PUBLIC_KEY_PATH, "utf8");
    logger.info("Loaded RSA keys from files");
  } catch (err) {
    logger.warn("RSA key files not found, generating ephemeral keys");
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
      privateKeyEncoding: { type: "pkcs1", format: "pem" }
    });
    publicKeyPem = publicKey;
    privateKeyPem = privateKey;
  }
} else {
  // Generate ephemeral keys (dev only)
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" }
  });
  publicKeyPem = publicKey;
  privateKeyPem = privateKey;
  logger.warn("Generated ephemeral RSA keypair on startup (dev only)");
}


// SSE clients
const clients = new Set();
function broadcast(message) {
  const payload = JSON.stringify(message);
  for (const res of clients) {
    try {
      res.write(`data: ${payload}\n\n`);
    } catch (err) {
      logger.error("Error writing to SSE client", { error: err });
    }
  }
}

// --- AES-GCM encryption-at-rest utilities ---
function getAesKey() {
  const base64 = process.env.MESSAGE_AES_KEY;
  if (!base64) {
    logger.warn("MESSAGE_AES_KEY not set. Generating volatile key (dev only). Messages won't be readable across restarts.");
    return randomBytes(32);
  }
  try {
    const buf = Buffer.from(base64, "base64");
    if (buf.length !== 32) throw new Error("Invalid key length");
    return buf;
  } catch (e) {
    logger.error("Failed to parse MESSAGE_AES_KEY. Expect base64-encoded 32 bytes.");
    process.exit(1);
  }
}

const AES_KEY = getAesKey();

function encryptAtRest(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: authTag.toString("base64")
  };
}

function decryptAtRest(ivB64, ctB64, tagB64) {
  const iv = Buffer.from(ivB64, "base64");
  const ciphertext = Buffer.from(ctB64, "base64");
  const authTag = Buffer.from(tagB64, "base64");
  const decipher = createDecipheriv("aes-256-gcm", AES_KEY, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return plaintext;
}

// Broadcast encryption (group key)
function getGroupKey() {
  const base64 = process.env.GROUP_AES_KEY;
  if (!base64) return null;
  try {
    const buf = Buffer.from(base64, "base64");
    if (buf.length !== 32) return null;
    return buf;
  } catch (_) { return null; }
}

const GROUP_KEY = getGroupKey();

function encryptForBroadcast(plaintext) {
  if (!GROUP_KEY) return { mode: "plaintext", content: plaintext };
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", GROUP_KEY, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    mode: "aes-gcm",
    iv: iv.toString("base64"),
    ciphertext: ct.toString("base64"),
    authTag: tag.toString("base64")
  };
}

// --- Routes ---

// Expose public key for clients to encrypt messages
app.get("/public-key", (req, res) => {
  res.type("text/plain").send(publicKeyPem);
});

// Registration
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
      return res.status(400).json({ error: "Invalid username/password" });
    }
    const user = new User({ username });
    await user.setPassword(password);
    await user.save();
    logger.info("User registered", { username });
    res.json({ success: true });
  } catch (err) {
    logger.error("Register error", { error: err });
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await user.validatePassword(password))) {
      logger.info("Failed login attempt", { username });
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: "1h" });
    logger.info("User logged in", { username });
    const groupKeyB64 = process.env.GROUP_AES_KEY || "";
    res.json({ token, groupKey: groupKeyB64 });
  } catch (err) {
    logger.error("Login error", { error: err });
    res.status(500).json({ error: "Login failed" });
  }
});

// SSE endpoint
app.get("/events", (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();
  try {
    jwt.verify(token, process.env.JWT_SECRET);
  } catch (e) {
    return res.status(401).end();
  }

  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive"
  });
  res.flushHeaders();
  clients.add(res);
  logger.info("SSE client connected", { currentClients: clients.size });

  const interval = setInterval(() => {
    try { res.write(": ping\n\n"); } catch (_) {}
  }, 25000);

  req.on("close", () => {
    clearInterval(interval);
    clients.delete(res);
    logger.info("SSE client disconnected", { currentClients: clients.size });
  });
});

// Send message route
app.post("/send", async (req, res) => {
  const { token, content } = req.body;
  if (!token || !content) return res.status(400).json({ error: "Missing token or content" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const username = payload.username;

    const buffer = Buffer.from(content, "base64");
    let decrypted;
    try {
      decrypted = privateDecrypt(
        {
          key: privateKeyPem,
          padding: require("crypto").constants.RSA_PKCS1_PADDING, // <--- שים לב לשינוי
        },
        buffer
      ).toString("utf8");
    } catch (err) {
      logger.warn("Failed to decrypt incoming message", { username, error: err.message });
      return res.status(400).json({ error: "Failed to decrypt message" });
    }

    const sealed = encryptAtRest(decrypted);
    const message = new Message({
      sender: username,
      iv: sealed.iv,
      ciphertext: sealed.ciphertext,
      authTag: sealed.authTag
    });
    await message.save();

    const enc = encryptForBroadcast(decrypted);
    broadcast({ sender: username, content: enc, timestamp: message.timestamp });
    res.json({ success: true });
  } catch (err) {
    logger.error("Send message error", { error: err });
    res.status(401).json({ error: "Unauthorized or invalid token" });
  }
});

// Get messages (requires Authorization header "Bearer <token>")
app.get("/messages", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Unauthorized" });
  const token = auth.split(" ")[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    const messages = await Message.find().sort({ timestamp: -1 }).limit(100);
    const out = messages.map(m => ({
      sender: m.sender,
      content: (() => { try { return decryptAtRest(m.iv, m.ciphertext, m.authTag); } catch (_) { return "<decryption failed>"; } })(),
      timestamp: m.timestamp
    }));
    res.json(out);
  } catch (err) {
    logger.warn("Unauthorized messages request", { error: err });
    res.status(401).json({ error: "Invalid token" });
  }
});

if (process.env.NODE_ENV !== "test") {
  const pfxPath = process.env.SSL_PFX_PATH || path.join(__dirname, "cert/server.pfx");
  const passphrase = process.env.SSL_PFX_PASS || "1234";
  const sslOptions = { pfx: fs.readFileSync(pfxPath), passphrase };
  const port = process.env.PORT || 3001;
  https.createServer(sslOptions, app).listen(port, () => {
    logger.info(`Secure server listening on https://localhost:${port}`);
  });
}

module.exports = app;
