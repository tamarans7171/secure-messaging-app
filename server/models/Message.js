// models/Message.js
const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  // AES-256-GCM fields for encryption-at-rest
  iv: { type: String, required: true },           // base64
  ciphertext: { type: String, required: true },   // base64
  authTag: { type: String, required: true },      // base64
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Message", messageSchema);
