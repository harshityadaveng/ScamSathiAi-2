import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { sanitizeSensitiveData } from '../src/services/privacy.service.js';
import { extractEntities } from '../src/services/entityExtraction.service.js';
import { calculateRiskScore } from '../src/utils/riskScoring.js';

test('Scam Detection & Analysis Suite', async (t) => {
  // Test 1: Normal greeting with no suspicious indicators
  await t.test('1. Normal greeting returns low risk score and no threat indicators', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Hi Ramesh, hope you are doing well! Are we meeting for coffee tomorrow?',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.analysis.riskLevel, 'low');
    assert.ok(res.body.analysis.riskScore <= 24);
    assert.equal(res.body.analysis.threatIndicators.length, 0);
    assert.equal(res.body.analysis.scamType, 'none_detected');
  });

  // Test 2: Urgent utility-disconnection message
  await t.test('2. Urgent utility disconnection message triggers URGENT_UTILITY_DISCONNECTION and high/very_high score', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because previous month bill was not updated. Call officer at 9876543210 immediately.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'URGENT_UTILITY_DISCONNECTION');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'utility_disconnection');
    assert.ok(res.body.analysis.entities.phoneNumbers.includes('9876543210'));
  });

  // Test 3: Message requesting an OTP or banking PIN
  await t.test('3. Message requesting OTP / PIN triggers CREDENTIAL_HARVESTING_OTP', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Dear Customer, please share your 6-digit OTP and UPI PIN with our executive to approve your transaction.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'CREDENTIAL_HARVESTING_OTP');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'credential_harvesting');
  });

  // Test 4: Fake digital-arrest threat
  await t.test('4. Fake digital-arrest threat triggers DIGITAL_ARREST_COERCION', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'This is Mumbai Police & CBI. A parcel in your name was seized with illegal drugs. Connect on Skype video call immediately for digital arrest procedure.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'DIGITAL_ARREST_COERCION');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'digital_arrest');
  });

  // Test 5: Suspicious APK installation request
  await t.test('5. Suspicious APK download triggers SUSPICIOUS_APK_DOWNLOAD', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Update your bank KYC by downloading and installing this app: https://sbi-secure.xyz/update-support.apk',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'SUSPICIOUS_APK_DOWNLOAD');
    assert.equal(hasRule, true);
    assert.ok(res.body.analysis.entities.urls.length > 0);
  });

  // Test 6: Fake prize requiring an advance fee
  await t.test('6. Fake prize requiring advance fee triggers LOTTERY_PRIZE_ADVANCE_FEE', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Congratulations! You won ₹25 lakh in KBC lucky draw. Deposit ₹12,500 registration processing fee to claim prize.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'LOTTERY_PRIZE_ADVANCE_FEE');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'lottery_reward');
  });

  // Test 7: Legitimate message containing one potentially suspicious keyword
  await t.test('7. Legitimate message with single keyword (e.g. electricity, account) does not falsely trigger critical scam', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Hello Dad, please carry our monthly electricity receipt and bank passbook for the municipal verification tomorrow morning.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    // Does not trigger URGENT_UTILITY_DISCONNECTION because there is no threat/disconnection
    const hasDisconnection = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'URGENT_UTILITY_DISCONNECTION');
    assert.equal(hasDisconnection, false);
    assert.ok(res.body.analysis.riskScore <= 49); // Stays in low / caution range
  });

  // Test 8: Empty content and malformed request bodies
  await t.test('8. Validation rejects empty content and malformed bodies with HTTP 400', async () => {
    // Empty content
    const res1 = await request(app)
      .post('/api/analyze')
      .send({ content: '   ' });
    assert.equal(res1.status, 400);
    assert.equal(res1.body.success, false);

    // Missing content field
    const res2 = await request(app)
      .post('/api/analyze')
      .send({ language: 'en' });
    assert.equal(res2.status, 400);
    assert.equal(res2.body.success, false);

    // Invalid language enum
    const res3 = await request(app)
      .post('/api/analyze')
      .send({ content: 'hello', language: 'fr' });
    assert.equal(res3.status, 400);
    assert.equal(res3.body.success, false);
  });

  // Test 9: Score boundaries and the 0–100 limit
  await t.test('9. Risk score stays strictly between 0 and 100 even with stacked rules and entities', async () => {
    // Zero rules -> 0
    const zero = calculateRiskScore([], { urls: [], phoneNumbers: [], upiIds: [] });
    assert.equal(zero.riskScore, 0);
    assert.equal(zero.riskLevel, 'low');

    // Many stacked critical/high rules -> clamped to exactly 100
    const stackedRules = [
      { ruleId: 'R1', severity: 'critical' },
      { ruleId: 'R2', severity: 'critical' },
      { ruleId: 'R3', severity: 'high' },
      { ruleId: 'R4', severity: 'high' },
      { ruleId: 'R5', severity: 'critical' },
    ];
    const maxed = calculateRiskScore(stackedRules, {
      urls: ['http://evil.top', 'http://phish.xyz'],
      phoneNumbers: ['9876543210'],
      upiIds: ['scam@upi'],
    });
    assert.equal(maxed.riskScore, 100);
    assert.equal(maxed.riskLevel, 'very_high');
  });

  // Test 10: URL, phone-number, and UPI-ID extraction
  await t.test('10. Extracts and deduplicates URLs, Indian phone numbers, and UPI IDs without punctuation noise', async () => {
    const text = 'Send ₹500 to rahul@okaxis or 9876543210@paytm. Visit https://sbi-portal.xyz/login. Call +91 9812345678 immediately!';
    const entities = extractEntities(text);

    // URLs without trailing dot
    assert.deepEqual(entities.urls, ['https://sbi-portal.xyz/login']);

    // Indian Phones (normalized)
    assert.ok(entities.phoneNumbers.includes('9812345678'));

    // UPI IDs (and emails excluded)
    assert.ok(entities.upiIds.includes('rahul@okaxis'));
    assert.ok(entities.upiIds.includes('9876543210@paytm'));
  });

  // Test 11: Privacy masking of representative sensitive values
  await t.test('11. Masks sensitive OTPs, Bank Accounts, Cards, and Aadhaar numbers', async () => {
    const raw = 'Your OTP is 492019 for A/C no 123456789012. Card: 4111 2222 3333 4444. Aadhaar: 2345 6789 0123.';
    const result = sanitizeSensitiveData(raw);

    assert.ok(result.sanitizedText.includes('[MASKED_OTP]'));
    assert.ok(result.sanitizedText.includes('[MASKED_ACCOUNT_****9012]'));
    assert.ok(result.sanitizedText.includes('[MASKED_CARD_****4444]'));
    assert.ok(result.sanitizedText.includes('[MASKED_AADHAAR]'));
    assert.ok(result.maskedItemsCount >= 4);
    assert.equal(result.sanitizedText.includes('492019'), false);
    assert.equal(result.sanitizedText.includes('4111 2222 3333 4444'), false);
  });

  // Test 12: Hindi language response support
  await t.test('12. Language parameter "hi" generates Hindi summaries and safety advice', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Dear consumer, your electricity power will be disconnected tonight. Call officer at 9876543210 immediately.',
        language: 'hi',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.summary.length > 0);
    assert.ok(res.body.analysis.threatIndicators[0].evidence.length > 0);
    assert.ok(res.body.analysis.safetyAdvice.length > 0);
    // Verified Hindi character presence in safety advice
    const hasHindi = res.body.analysis.safetyAdvice.some((a) => /[\u0900-\u097F]/.test(a));
    assert.equal(hasHindi, true);
  });

  // Test 13: Fake courier delivery / customs fee scam
  await t.test('13. Fake courier customs charges message triggers COURIER_CUSTOMS_FEE_SCAM', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'India Post: Your package could not be delivered due to wrong address. Pay ₹25 redelivery customs duty fee to reschedule: https://indiapost-update.xyz',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'COURIER_CUSTOMS_FEE_SCAM');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'courier_customs_fraud');
    assert.ok(Array.isArray(res.body.analysis.evidenceExcerpts));
    assert.ok(res.body.analysis.evidenceExcerpts.length > 0);
  });

  // Test 14: Fraudulent UPI Collect PIN request
  await t.test('14. UPI collect request demanding PIN to receive money triggers UPI_COLLECT_PIN_SCAM', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'You received ₹5000 cashback! Open GPay collect request and enter UPI PIN to receive money into your account.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 60);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'UPI_COLLECT_PIN_SCAM');
    assert.equal(hasRule, true);
    assert.ok(['payment_collect_fraud', 'credential_harvesting'].includes(res.body.analysis.scamType));
  });

  // Test 15: Guaranteed return & crypto investment scam
  await t.test('15. Guaranteed high return investment message triggers HIGH_YIELD_INVESTMENT_SCAM', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        content: 'Invest ₹10,000 in our crypto trading fund and get guaranteed returns of 100% profit daily with zero risk. Join VIP signals group.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasRule = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'HIGH_YIELD_INVESTMENT_SCAM');
    assert.equal(hasRule, true);
    assert.equal(res.body.analysis.scamType, 'investment_fraud');
  });

  // Test 16: Personal mobile number spoofing bank alerts vs TRAI DLT header
  await t.test('16. Personal mobile number sending bank account alert triggers PERSONAL_MOBILE_BANK_SPOOF', async () => {
    const res = await request(app)
      .post('/api/analyze')
      .send({
        sender: '9876543210',
        content: 'Dear customer, your SBI account is blocked due to pending KYC. Update immediately.',
        language: 'en',
      });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.senderIntel !== null);
    assert.equal(res.body.analysis.senderIntel.isSuspicious, true);
    const hasSpoof = res.body.analysis.threatIndicators.some((i) => i.ruleId === 'PERSONAL_MOBILE_BANK_SPOOF');
    assert.equal(hasSpoof, true);
  });
});
