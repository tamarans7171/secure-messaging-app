// server.js - Optimized for 10,000+ concurrent connections
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const https = require("https");
const cluster = require("cluster");
const os = require("os");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Redis = require("ioredis");
const { privateDecrypt, generateKeyPairSync, randomBytes, createCipheriv, createDecipheriv, publicEncrypt } = require("crypto");
const { encryptAtRest, decryptAtRest } = require("./crypto-utils");
const winston = require("winston");
const User = require("./models/User");
const Message = require("./models/Message");

// ========================================
// CLUSTER MODE - Multi-process for scalability
// ========================================
const numCPUs = os.cpus().length;

if (cluster.isMaster && require.main === module && process.env.NODE_ENV !== "test") {
  console.log(`Master ${process.pid} is running`);
  console.log(`Forking ${numCPUs} workers...`);

  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
  // Exit the master process after forking workers so the master does not
  // continue to execute worker-only code. `return` is invalid at top-level
  // in CommonJS modules, so use process.exit instead.
  process.exit(0);
}

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
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
    publicKeyPem = publicKey;
    privateKeyPem = privateKey;
  }
} else {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  publicKeyPem = publicKey;
  privateKeyPem = privateKey;
  logger.warn("Generated ephemeral RSA keypair on startup");
}

// --- SSE Clients Map (per worker) ---
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
  for (const [id, res] of clients.entries()) {
    try {
      res.write(`data: ${payload}\n\n`);
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
    // Do NOT return raw group key (server secret). If the client provided a public key
    // in the login request we will wrap the group key with it and return the wrapped value.
    const clientPub = req.body.clientPublicKey;
    if (clientPub && process.env.GROUP_AES_KEY) {
      try {
        // Encrypt the group key with client's public key using OAEP if possible
        const wrapped = publicEncrypt({ key: clientPub, padding: require('crypto').constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(process.env.GROUP_AES_KEY, 'base64'));
        return res.json({ token, wrappedGroupKey: wrapped.toString('base64') });
      } catch (err) {
        // fallback: do not return the raw key
        logger.warn('Failed to wrap group key for client', { error: err.message });
        return res.json({ token });
      }
    }
    res.json({ token });
  } catch (err) {
    logger.error("Login error", { error: err });
    res.status(500).json({ error: "Login failed" });
  }
});

// SSE endpoint - OPTIMIZED
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

  const clientId = ++clientIdCounter;
  clients.set(clientId, res);
  
  // Send initial ping
  res.write(": connected\n\n");

  // NO interval per client! Use a single global interval instead
  // (see global heartbeat below)

  req.on("close", () => {
    clients.delete(clientId);
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
    const messages = await Message.find()
      .sort({ timestamp: -1 })
      .limit(100)
      .lean(); // ← Use lean() for better performance
    
    const out = messages.map(m => ({
      sender: m.sender,
      content: (() => {
        try {
          return decryptAtRest(m.iv, m.ciphertext, m.authTag);
        } catch (_) {
          return "<decryption failed>";
        }
      })(),
      timestamp: m.timestamp
    }));
    
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