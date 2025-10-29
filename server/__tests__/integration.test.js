process.env.NODE_ENV = 'test';
jest.setTimeout(20000);
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const request = require('supertest');
const mongoose = require('mongoose');
const crypto = require('crypto');
const app = require('../server');

describe('Integration: send -> store -> get', () => {
  beforeAll(async () => {
    const mongo = process.env.MONGO_URL || 'mongodb://localhost:27017/secure_messaging_test';
    await mongoose.connect(mongo);
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  test('full happy path: encrypt with public key, send, stored and retrieved as plaintext', async () => {
    const username = 'intuser';
    const password = 'Password1!';

    // register
    await request(app).post('/register').send({ username, password }).expect(200);

    // login
    const loginRes = await request(app).post('/login').send({ username, password }).expect(200);
    const token = loginRes.body.token;
    expect(token).toBeTruthy();

    // fetch public key
    const pkRes = await request(app).get('/public-key').expect(200);
    const publicKeyPem = pkRes.text;
    expect(publicKeyPem).toContain('BEGIN');

    // encrypt a message using the server public key with PKCS1 padding to match server
    const plaintext = 'integration test message';
    const encryptedBuf = crypto.publicEncrypt({
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(plaintext, 'utf8'));

    const b64 = encryptedBuf.toString('base64');

    // send
    await request(app).post('/send').send({ token, content: b64 }).expect(200);

    // fetch messages
    const msgsRes = await request(app).get('/messages').set('Authorization', `Bearer ${token}`).expect(200);
    expect(Array.isArray(msgsRes.body)).toBe(true);
    const found = msgsRes.body.find(m => m.content === plaintext && m.sender === username);
    expect(found).toBeTruthy();
  }, 20000);
});
