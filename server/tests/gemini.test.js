import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { setMockAiClient } from '../src/services/gemini.service.js';
import { env } from '../src/config/env.js';
import { combineEngineResults } from '../src/utils/engineCombiner.js';

test('Gemini AI Integration & Fallback Suite', async (t) => {
  // Test 1: Valid Gemini structured output
  await t.test('1. Valid Gemini structured output integrates smoothly into analysis response', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            scamType: 'utility_disconnection',
            riskAssessment: 'high',
            summary: 'The message creates psychological urgency by threatening electricity disconnection.',
            threatIndicators: [
              {
                category: 'urgency_coercion',
                severity: 'high',
                evidence: 'Immediate disconnection threat tonight.',
              },
            ],
            safetyAdvice: ['Verify through the official electricity board website.'],
          }),
        }),
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Your electricity will be disconnected tonight. Pay now.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.analysis.engine, 'gemini+rules_v1');
    assert.equal(res.body.analysis.scamType, 'utility_disconnection');
    assert.ok(res.body.analysis.riskScore >= 50);
  });

  // Test 2: Invalid JSON or schema-invalid output gracefully falls back to rules
  await t.test('2. Invalid JSON or schema-invalid output triggers rule-based fallback', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: 'This is not valid JSON string from LLM',
        }),
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Dear consumer, electricity will be disconnected tonight. Call officer at 9876543210.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.engine, 'rules_v1_fallback');
    assert.equal(res.body.analysis.scamType, 'utility_disconnection');
    assert.ok(res.body.analysis.riskScore >= 50);
  });

  // Test 3: Gemini timeout triggers fallback
  await t.test('3. Gemini timeout triggers rule-based fallback without failing request', async () => {
    // Configure mock to delay beyond timeout
    const originalTimeout = env.GEMINI_TIMEOUT_MS;
    env.GEMINI_TIMEOUT_MS = 50; // Temporarily 50ms for fast test

    setMockAiClient({
      models: {
        generateContent: () =>
          new Promise((resolve) =>
            setTimeout(
              () =>
                resolve({
                  text: JSON.stringify({
                    scamType: 'none_detected',
                    riskAssessment: 'low',
                    summary: 'Delayed',
                    threatIndicators: [],
                    safetyAdvice: [],
                  }),
                }),
              200
            )
          ),
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Your electricity power will be cut tonight. Call officer 9876543210.',
        language: 'en',
      });

    env.GEMINI_TIMEOUT_MS = originalTimeout; // Restore

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.engine, 'rules_v1_fallback');
    assert.ok(res.body.analysis.riskScore >= 50);
  });

  // Test 4: Gemini quota or rate-limit failure
  await t.test('4. Gemini rate-limit (429) triggers graceful fallback', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => {
          const err = new Error('Resource exhausted: Quota exceeded');
          err.status = 429;
          throw err;
        },
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Congratulations! You won ₹25 lakh lucky draw. Deposit ₹12,500 fee.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.engine, 'rules_v1_fallback');
    assert.equal(res.body.analysis.scamType, 'lottery_reward');
    assert.ok(res.body.analysis.riskScore >= 50);
  });

  // Test 5 & 6: Missing API Key / AI Disabled configuration
  await t.test('5 & 6. AI disabled or missing API key falls back to rules_v1 cleanly', async () => {
    setMockAiClient(null);
    const originalAiEnabled = env.AI_ENABLED;
    env.AI_ENABLED = false;

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Hi, this is a normal message.',
        language: 'en',
      });

    env.AI_ENABLED = originalAiEnabled;

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.engine, 'rules_v1');
    assert.equal(res.body.analysis.riskLevel, 'low');
  });

  // Test 7: Rule-based fallback after failure
  await t.test('7. Confirms rule-based fallback retains all indicators', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => {
          throw new Error('Network failure');
        },
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'CBI & Police Alert: Digital arrest initiated for illegal drugs parcel.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.engine, 'rules_v1_fallback');
    assert.equal(res.body.analysis.scamType, 'digital_arrest');
    assert.ok(res.body.analysis.riskScore >= 50);
  });

  // Test 8: Sanitized content passed to Gemini rather than raw content
  await t.test('8. Sensitive values like OTP and Bank A/C are masked before passing to Gemini', async () => {
    let capturedPrompt = '';
    setMockAiClient({
      models: {
        generateContent: async ({ contents }) => {
          capturedPrompt = contents;
          return {
            text: JSON.stringify({
              scamType: 'credential_harvesting',
              riskAssessment: 'high',
              summary: 'Credential harvesting message.',
              threatIndicators: [],
              safetyAdvice: ['Never share OTPs.'],
            }),
          };
        },
      },
    });

    await request(app)
      .post('/api/analyze')
      .send({
        content: 'Your OTP is 849201 for A/C no 987654321098. Please share it with customer care.',
        language: 'en',
      });

    // Verify raw OTP and full bank account number never appeared in LLM prompt
    assert.equal(capturedPrompt.includes('849201'), false);
    assert.equal(capturedPrompt.includes('987654321098'), false);
    assert.ok(capturedPrompt.includes('[MASKED_OTP]'));
    assert.ok(capturedPrompt.includes('[MASKED_ACCOUNT_****1098]'));
  });

  // Test 9: Rule-based high-severity indicators preserved during combination
  await t.test('9. Gemini cannot overwrite or erase high-severity rule indicators', () => {
    const ruleResults = {
      riskScore: 68,
      riskLevel: 'high',
      scamType: 'utility_disconnection',
      summary: 'Rule summary',
      threatIndicators: [
        {
          ruleId: 'URGENT_UTILITY_DISCONNECTION',
          category: 'utility_disconnection',
          severity: 'critical',
          evidence: 'Disconnection threat detected by rule engine.',
        },
      ],
      safetyAdvice: ['Official advice.'],
    };

    // AI hallucinates or mistakenly returns low risk
    const aiResults = {
      scamType: 'none_detected',
      riskAssessment: 'low',
      summary: 'Looks fine',
      threatIndicators: [],
      safetyAdvice: [],
    };

    const combined = combineEngineResults(ruleResults, aiResults, null, { urls: [], phoneNumbers: [], upiIds: [] });

    // The critical rule indicator MUST be preserved and score must NOT drop below rule baseline
    assert.equal(combined.threatIndicators.length, 1);
    assert.equal(combined.threatIndicators[0].ruleId, 'URGENT_UTILITY_DISCONNECTION');
    assert.ok(combined.riskScore >= 68);
    assert.equal(combined.scamType, 'utility_disconnection');
  });

  // Test 10: Duplicate indicators are not double-counted
  await t.test('10. Overlapping category indicators from AI and Rules are deduplicated', () => {
    const ruleResults = {
      riskScore: 55,
      riskLevel: 'high',
      scamType: 'utility_disconnection',
      summary: 'Rule summary',
      threatIndicators: [
        {
          ruleId: 'URGENT_UTILITY_DISCONNECTION',
          category: 'utility_disconnection',
          severity: 'critical',
          evidence: 'Rule evidence',
        },
      ],
      safetyAdvice: [],
    };

    const aiResults = {
      scamType: 'utility_disconnection',
      riskAssessment: 'high',
      summary: 'AI summary',
      threatIndicators: [
        {
          category: 'utility_disconnection', // Overlapping category
          severity: 'high',
          evidence: 'AI evidence',
        },
      ],
      safetyAdvice: ['Check bills.'],
    };

    const combined = combineEngineResults(ruleResults, aiResults, null, { urls: [], phoneNumbers: [], upiIds: [] });

    // Combined indicators count should remain 1 (no duplicate utility_disconnection)
    assert.equal(combined.threatIndicators.length, 1);
    assert.equal(combined.riskScore, 55);
  });

  // Test 11: English and Hindi response consistency
  await t.test('11. Hindi request returns consistent schema with Hindi summary and advice', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            scamType: 'utility_disconnection',
            riskAssessment: 'high',
            summary: 'यह संदेश बिजली काटने की झूठी धमकी देकर तात्कालिकता पैदा करता है।',
            threatIndicators: [
              {
                category: 'urgency_coercion',
                severity: 'high',
                evidence: 'आज रात बिजली काटने की धमकी।',
              },
            ],
            safetyAdvice: ['बिजली बोर्ड की आधिकारिक वेबसाइट पर बिल सत्यापित करें।'],
          }),
        }),
      },
    });

    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Your electricity will be disconnected tonight.',
        language: 'hi',
      });

    assert.equal(res.status, 200);
    assert.ok(/[\u0900-\u097F]/.test(res.body.analysis.summary));
    assert.ok(res.body.analysis.safetyAdvice.some((a) => /[\u0900-\u097F]/.test(a)));
  });

  // Cleanup mock after tests
  t.after(() => {
    setMockAiClient(null);
  });
});
