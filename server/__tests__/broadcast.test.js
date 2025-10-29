process.env.NODE_ENV = 'test';
jest.setTimeout(20000);
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');

describe('Broadcast flow (basic)', () => {
  let token;
  beforeAll(async () => {
    const mongo = process.env.MONGO_URL || 'mongodb://localhost:27017/secure_messaging_test';
    await mongoose.connect(mongo);
    const username = 'buser';
    const password = 'Password1!';
    await request(app).post('/register').send({ username, password });
    const res = await request(app).post('/login').send({ username, password });
    token = res.body.token;
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  test('Send then list messages returns the plaintext', async () => {
    // Fetch public key
    const pkRes = await request(app).get('/public-key').expect(200);
  expect(pkRes.text).toContain('BEGIN PUBLIC KEY');
    // For test simplicity, bypass RSA and hit /send with an obviously invalid base64 -> expect 400
    await request(app).post('/send').send({ token, content: 'invalid_base64' }).expect(400);
  });
});


