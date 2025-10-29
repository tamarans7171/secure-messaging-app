// server.js - Optimized for 10,000+ concurrent connections
require("dotenv").config();
const fs = require("fs");
const path = require("path");
// Dev-friendly persistence for the MESSAGE_AES_KEY.
// If DEV_PERSIST_MESSAGE_KEY=1 the server will generate a key when none is provided
// and save it to `data/MESSAGE_AES_KEY`. Intended for local development only.
if (!process.env.MESSAGE_AES_KEY && process.env.DEV_PERSIST_MESSAGE_KEY === '1') {
  try {
    const dataDir = path.join(__dirname, 'data');
    const keyFile = path.join(dataDir, 'MESSAGE_AES_KEY');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

    if (fs.existsSync(keyFile)) {
      const existing = fs.readFileSync(keyFile, 'utf8').trim();
      if (existing) {
        process.env.MESSAGE_AES_KEY = existing;
        console.log('Loaded persisted MESSAGE_AES_KEY from', keyFile);
      }
    } else {
      const crypto = require('crypto');
      const newKey = crypto.randomBytes(32).toString('base64');
      fs.writeFileSync(keyFile, newKey, { encoding: 'utf8', mode: 0o600 });
      process.env.MESSAGE_AES_KEY = newKey;
      console.log('Generated and persisted new MESSAGE_AES_KEY to', keyFile);
    }
  } catch (err) {
    console.warn('DEV_PERSIST_MESSAGE_KEY enabled but failed to persist/load key:', err && err.message);
  }
}
const https = require("https");
const cluster = require("cluster");
const os = require("os");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Redis = require("ioredis");
const { privateDecrypt, generateKeyPairSync, randomBytes, createCipheriv, createDecipheriv } = require("crypto");
const winston = require("winston");
const User = require("./models/User");
const Message = require("./models/Message");

// ========================================
// CLUSTER MODE - Multi-process for scalability
// ========================================
const numCPUs = os.cpus().length;

if (cluster.isMaster && process.env.NODE_ENV !== "test") {
  console.log(`Master ${process.pid} is running`);
  console.log(`Forking ${numCPUs} workers...`);

  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
} else {

// ========================================
// WORKER PROCESS
// ========================================
console.log(`Worker ${process.pid} started`);

const app = express();
app.use(cors());
app.use(express.json());

// --- Optimized Logging (async, buffered) ---
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "warn", // Only warnings/errors in production
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: "logs/error.log", 
      level: "error",
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    new winston.transports.Console({ 
      format: winston.format.simple(),
      level: "info"
    })
  ]
});

// --- MongoDB with Connection Pooling ---
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 50, // ← Support more concurrent queries
  socketTimeoutMS: 45000,
  connectTimeoutMS: 10000,
  serverSelectionTimeoutMS: 10000
})
  .then(() => logger.info("MongoDB connected"))
  .catch(err => {
    logger.error("MongoDB connection error", { error: err });
    process.exit(1);
  });

// --- Redis for Pub/Sub (broadcast across workers) ---
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
const redisSub = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

redis.on("error", (err) => logger.error("Redis error", { error: err.message }));

// --- RSA Key Management ---
let privateKeyPem, publicKeyPem;

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
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" }
  });
  publicKeyPem = publicKey;
  privateKeyPem = privateKey;
  logger.warn("Generated ephemeral RSA keypair on startup");
}

// --- SSE Clients Map (per worker) ---
// Map<clientId, { res, username }>
const clients = new Map(); // Use Map instead of Set for better management
let clientIdCounter = 0;

// Subscribe to Redis channel for cross-worker broadcasting
redisSub.subscribe("chat:broadcast", (err) => {
  if (err) logger.error("Redis subscribe error", { error: err });
});

redisSub.on("message", (channel, message) => {
  if (channel === "chat:broadcast") {
    broadcastToLocalClients(message);
  }
});

function broadcastToLocalClients(payload) {
  // Send to all clients connected to THIS worker
  for (const [id, info] of clients.entries()) {
    const res = info && info.res;
    try {
      if (res && !res.finished) res.write(`data: ${payload}\n\n`);
    } catch (err) {
      logger.error("Error writing to SSE client", { error: err, clientId: id });
      clients.delete(id); // Remove dead connections
    }
  }
}

function broadcast(message) {
  const payload = JSON.stringify(message);
  // Publish to Redis - all workers will receive it
  redis.publish("chat:broadcast", payload, (err) => {
    if (err) logger.error("Redis publish error", { error: err });
  });
}

// --- AES Encryption Functions ---
function getAesKey() {
  const base64 = process.env.MESSAGE_AES_KEY;
  if (!base64) {
    logger.warn("MESSAGE_AES_KEY not set. Using volatile key.");
    return randomBytes(32);
  }
  const buf = Buffer.from(base64, "base64");
  if (buf.length !== 32) throw new Error("Invalid MESSAGE_AES_KEY length");
  return buf;
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
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function getGroupKey() {
  const base64 = process.env.GROUP_AES_KEY;
  if (!base64) return null;
  try {
    const buf = Buffer.from(base64, "base64");
    return buf.length === 32 ? buf : null;
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

// ========================================
// ROUTES
// ========================================

app.get("/public-key", (req, res) => {
  res.type("text/plain").send(publicKeyPem);
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
    const uname = String(username).trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,30}$/.test(uname)) return res.status(400).json({ error: "Invalid username format" });
    if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    // Prevent duplicate users
    const existing = await User.findOne({ username: uname });
    if (existing) return res.status(409).json({ error: "Username already taken" });

    const user = new User({ username: uname });
    await user.setPassword(password);
  await user.save();
  logger.info("User registered", { username: uname });
  // Return 200 for compatibility with tests expecting 200
  res.status(200).json({ success: true });
  } catch (err) {
    logger.error("Register error", { error: err });
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });
    const uname = String(username).trim().toLowerCase();

    const user = await User.findOne({ username: uname });
    if (!user || !(await user.validatePassword(password))) {
      logger.info("Failed login attempt", { username: uname });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!process.env.JWT_SECRET) {
      logger.error('JWT_SECRET is not set');
      return res.status(500).json({ error: 'Server misconfiguration' });
    }

    const token = jwt.sign({ username: uname }, process.env.JWT_SECRET, { expiresIn: "1h", algorithm: 'HS256' });
    logger.info("User logged in", { username: uname });
    res.json({ token });
  } catch (err) {
    logger.error("Login error", { error: err });
    res.status(500).json({ error: "Login failed" });
  }
});
// SSE endpoint - OPTIMIZED
app.get("/events", async (req, res) => {
  // Support token via query param or Authorization header
  const tokenFromQuery = req.query && req.query.token;
  const authHeader = req.headers && req.headers.authorization;
  let token = tokenFromQuery;
  if (!token && authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  }

  if (!token) return res.status(401).json({ error: 'Missing token' });

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (e) {
    logger.warn('Invalid token for SSE connect', { error: e && e.message });
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Optionally verify the user still exists
  const username = payload && payload.username;
  if (!username) return res.status(401).json({ error: 'Invalid token payload' });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'User not found' });
  } catch (err) {
    logger.error('Error verifying SSE user', { error: err });
    return res.status(500).json({ error: 'Server error' });
  }

  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive"
  });
  res.flushHeaders();

  const clientId = ++clientIdCounter;
  clients.set(clientId, { res, username });

  // Send initial ping and a small welcome message containing the authenticated username
  res.write(`: connected\n\n`);
  const welcome = {
    sender: 'system',
    content: { mode: 'plaintext', content: `welcome ${username}` },
    timestamp: new Date()
  };
  res.write(`data: ${JSON.stringify(welcome)}\n\n`);

  logger.info('SSE client connected', { clientId, username });

  req.on("close", () => {
    clients.delete(clientId);
    logger.info('SSE client disconnected', { clientId, username });
  });
});

// Global heartbeat - ONE interval for ALL clients
setInterval(() => {
  const now = Date.now();
  for (const [id, res] of clients.entries()) {
    try {
      res.write(`: heartbeat ${now}\n\n`);
    } catch (err) {
      clients.delete(id);
    }
  }
}, 30000); // Every 30 seconds

app.post("/send", async (req, res) => {
  const { token, content } = req.body;
  if (!token || !content) return res.status(400).json({ error: "Missing token or content" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const username = payload.username;

    const buffer = Buffer.from(content, "base64");
    // Basic validation: RSA-2048 ciphertext should be 256 bytes
    if (!Buffer.isBuffer(buffer) || buffer.length !== 256) {
      logger.warn('Invalid ciphertext length for /send', { username, len: buffer.length });
      return res.status(400).json({ error: 'Invalid ciphertext' });
    }

    let decrypted;
    
    try {
      decrypted = privateDecrypt({
        key: privateKeyPem,
        padding: require("crypto").constants.RSA_PKCS1_PADDING
      }, buffer).toString("utf8");
    } catch (err) {
      logger.warn("Failed to decrypt incoming message", { username, error: err.message });
      return res.status(400).json({ error: "Failed to decrypt message" });
    }

    // Enforce reasonable message length limits to avoid abuse
    const MAX_MESSAGE_CHARS = parseInt(process.env.MAX_MESSAGE_CHARS || '2000', 10);
    if (typeof decrypted !== 'string' || decrypted.length === 0) {
      return res.status(400).json({ error: 'Empty message' });
    }
    if (decrypted.length > MAX_MESSAGE_CHARS) {
      return res.status(413).json({ error: 'Message too large' });
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

app.get("/messages", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Unauthorized" });
  
  const token = auth.split(" ")[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    // Support pagination: ?limit=50 (max 200), ?before=<ISO timestamp>
    const reqLimit = Math.min(parseInt(req.query.limit || '100', 10) || 100, 200);
    const before = req.query.before ? new Date(req.query.before) : null;
    const q = before ? { timestamp: { $lt: before } } : {};
    const messages = await Message.find(q)
      .sort({ timestamp: -1 })
      .limit(reqLimit)
      .lean(); // ← Use lean() for better performance
    
    const out = messages.map(m => {
      try {
        const plaintext = decryptAtRest(m.iv, m.ciphertext, m.authTag);
        return { sender: m.sender, content: plaintext, timestamp: m.timestamp };
      } catch (err) {
        // Return encrypted blob when server cannot decrypt so client can show a placeholder
        return {
          sender: m.sender,
          content: { encrypted: true, iv: m.iv, ciphertext: m.ciphertext, authTag: m.authTag },
          timestamp: m.timestamp
        };
      }
    });
    
    res.json(out);
  } catch (err) {
    logger.warn("Unauthorized messages request");
    res.status(401).json({ error: "Invalid token" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ 
    status: "ok", 
    worker: process.pid,
    clients: clients.size,
    uptime: process.uptime()
  });
});

// ========================================
// START SERVER
// ========================================
if (process.env.NODE_ENV !== "test") {
  const pfxPath = process.env.SSL_PFX_PATH || path.join(__dirname, "cert/server.pfx");
  const passphrase = process.env.SSL_PFX_PASS || "1234";
  const sslOptions = { pfx: fs.readFileSync(pfxPath), passphrase };
  const port = process.env.PORT || 3001;
  
  https.createServer(sslOptions, app).listen(port, () => {
    logger.info(`Worker ${process.pid} listening on https://localhost:${port}`);
  });
}
module.exports = app;

} // end master/worker conditional