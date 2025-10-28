process.env.NODE_ENV = 'test';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');

describe('Auth flow', () => {
  beforeAll(async () => {
    const mongo = process.env.MONGO_URL || 'mongodb://localhost:27017/secure_messaging_test';
    await mongoose.connect(mongo);
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  test('Register and login returns JWT', async () => {
    const username = 'testuser';
    const password = 'Password1!';
    await request(app).post('/register').send({ username, password }).expect(200);
    const res = await request(app).post('/login').send({ username, password }).expect(200);
    expect(res.body.token).toBeTruthy();
  });
});


