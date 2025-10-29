process.env.NODE_ENV = 'test';
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../server');

describe('SSE endpoint', () => {
  beforeAll(async () => {
    const mongo = process.env.MONGO_URL || 'mongodb://localhost:27017/secure_messaging_test';
    await mongoose.connect(mongo);
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  });

  test('requires token query param', async () => {
    const res = await request(app).get('/events');
    expect(res.statusCode).toBe(401);
  });
});


