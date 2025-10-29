// idempotent seed script for demo purposes
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Message = require('../models/Message');
const { encryptAtRest } = require('../crypto-utils');

async function seed() {
  const mongo = process.env.MONGO_URL || 'mongodb://localhost:27017/secure-chat';
  await mongoose.connect(mongo, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to', mongo);

  // Clean slate for predictable demo seeding
  await User.deleteMany({});
  await Message.deleteMany({});

  const users = [
    { username: 'alice', password: 'Password1!' },
    { username: 'bob', password: 'Password1!' },
    { username: 'charlie', password: 'Password1!' }
  ];

  for (const u of users) {
    const user = new User({ username: u.username });
    await user.setPassword(u.password);
    await user.save();
    console.log('Created user', u.username);
  }

  // Seed messages only when MESSAGE_AES_KEY is available so server can decrypt later
  if (!process.env.MESSAGE_AES_KEY) {
    console.warn('MESSAGE_AES_KEY not set; skipping message seeding (messages must be encrypted at rest)');
  } else {
    const msgs = [
      { sender: 'alice', text: 'Hello Bob!' },
      { sender: 'bob', text: 'Hi Alice, how are you?' },
      { sender: 'charlie', text: 'Hey everyone!' }
    ];
    for (const m of msgs) {
      const sealed = encryptAtRest(m.text);
      await Message.create({ sender: m.sender, iv: sealed.iv, ciphertext: sealed.ciphertext, authTag: sealed.authTag });
      console.log('Saved message from', m.sender);
    }
  }

  console.log('Seeding complete');
  await mongoose.disconnect();
}

seed().catch(err => {
  console.error('Seed failed', err);
  process.exit(1);
});


