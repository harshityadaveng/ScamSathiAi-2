import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';

test('Health & Root Routes Suite', async (t) => {
  await t.test('GET / returns 200 and root service status', async () => {
    const res = await request(app).get('/');

    assert.equal(res.status, 200);
    assert.equal(res.headers['content-type'].includes('application/json'), true);
    assert.equal(res.body.success, true);
    assert.equal(res.body.message, 'ScamSathi AI API Service');
    assert.equal(typeof res.body.timestamp, 'string');
    assert.ok(!isNaN(Date.parse(res.body.timestamp)));
  });

  await t.test('GET /api/health returns 200 and expected health payload', async () => {
    const res = await request(app).get('/api/health');

    assert.equal(res.status, 200);
    assert.equal(res.headers['content-type'].includes('application/json'), true);
    assert.equal(res.body.success, true);
    assert.equal(res.body.message, 'ScamSathi AI backend is running');
    assert.equal(typeof res.body.timestamp, 'string');
    assert.ok(!isNaN(Date.parse(res.body.timestamp)));
  });

  await t.test('CORS allows local development servers on alternate ports', async () => {
    const res = await request(app)
      .get('/api/health')
      .set('Origin', 'http://localhost:5174');

    assert.equal(res.status, 200);
    assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:5174');
  });

  await t.test('GET /api/unknown-endpoint returns 404 with consistent JSON structure', async () => {
    const res = await request(app).get('/api/unknown-endpoint');

    assert.equal(res.status, 404);
    assert.equal(res.headers['content-type'].includes('application/json'), true);
    assert.equal(res.body.success, false);
    assert.equal(typeof res.body.message, 'string');
    assert.equal(typeof res.body.timestamp, 'string');
  });

  await t.test('POST /api/unknown-endpoint returns 404 with consistent JSON structure', async () => {
    const res = await request(app)
      .post('/api/unknown-endpoint')
      .send({ some: 'data' });

    assert.equal(res.status, 404);
    assert.equal(res.body.success, false);
  });

  await t.test('Security headers (Helmet) are set', async () => {
    const res = await request(app).get('/api/health');

    assert.ok(res.headers['x-dns-prefetch-control']);
    assert.ok(res.headers['x-frame-options']);
    assert.ok(res.headers['x-content-type-options']);
  });
});
