require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Message = require("../models/Message");
const { randomBytes, createCipheriv } = require("crypto");

function getAesKey() {
  const b64 = process.env.MESSAGE_AES_KEY;
  if (!b64) return null;
  try {
    const buf = Buffer.from(b64, "base64");
    return buf.length === 32 ? buf : null;
  } catch { return null; }
}

function seal(text, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString("base64"), ciphertext: ct.toString("base64"), authTag: tag.toString("base64") };
}

(async () => {
  const mongo = process.env.MONGO_URL || "mongodb://localhost:27017/secure_messaging";
  await mongoose.connect(mongo);
  console.log("Connected to MongoDB");

  await User.deleteMany({});
  await Message.deleteMany({});

  const users = [
    { username: "alice", password: "Password1!" },
    { username: "bob", password: "Password1!" },
    { username: "charlie", password: "Password1!" }
  ];

  for (const u of users) {
    const user = new User({ username: u.username });
    user.passwordHash = await bcrypt.hash(u.password, 12);
    await user.save();
  }
  console.log("Seeded users: ", users.map(u => u.username).join(", "));

  const key = getAesKey();
  if (!key) {
    console.warn("MESSAGE_AES_KEY not set; skipping message seed (cannot encrypt at rest)");
  } else {
    const seedMessages = [
      { sender: "alice", text: "Hello from Alice" },
      { sender: "bob", text: "Hi Alice, Bob here" },
      { sender: "charlie", text: "Charlie joined the chat" }
    ];
    for (const m of seedMessages) {
      const sealed = seal(m.text, key);
      await Message.create({ sender: m.sender, ...sealed });
    }
    console.log("Seeded messages: ", seedMessages.length);
  }

  await mongoose.disconnect();
  console.log("Done.");
  process.exit(0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});


