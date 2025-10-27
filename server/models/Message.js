// models/Message.js
const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  sender: String,
  content: String, // plaintext in this demo. ב-prod הקפידי להצפין כאן.
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Message", messageSchema);
