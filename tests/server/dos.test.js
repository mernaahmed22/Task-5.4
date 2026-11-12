import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../server/src/app.js';

let mongo;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.CSRF_SECRET = 'test-csrf-secret';
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
}, 60000);

afterAll(async () => {
  await mongoose.disconnect();
  if (mongo) await mongo.stop();
});

describe('Maintenance requests — DoS / rate limiting', () => {
  test('a normal request to the public list succeeds (the happy path)', async () => {
    const res = await request(app).get('/api/maintenance');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.requests)).toBe(true);
  });

  // The core DoS test. One client floods the public endpoint. A secure server
  // rate-limits it (429 after a small number of requests) so a flood cannot
  // exhaust it; a vulnerable server serves every request (200), unbounded.
  test('a flood of requests from one client is rate-limited', async () => {
    const statuses = [];
    for (let i = 0; i < 40; i++) {
      const res = await request(app).get('/api/maintenance');
      statuses.push(res.status);
    }

    // Legitimate traffic is still served early in the window...
    expect(statuses).toContain(200);
    // ...but the flood is throttled with 429 Too Many Requests.
    expect(statuses).toContain(429);
  });
});
