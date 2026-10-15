import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { scanUrl } from '../src/services/urlScanner.service.js';
import { clearPipelineCache } from '../src/services/websiteIntelPipeline.service.js';

test('URL Risk Scanner Suite', async (t) => {
  t.beforeEach(() => {
    clearPipelineCache();
  });

  // Test 1: Valid clean HTTP and HTTPS URLs
  await t.test('1. Clean legitimate URL returns low risk indicators and honest verification status', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://example.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(['unknown', 'low'].includes(res.body.analysis.riskLevel));
    assert.equal(res.body.analysis.riskScore, null);
    assert.ok(['insufficient_evidence', 'unable_to_verify', 'no_known_warning_signs'].includes(res.body.analysis.verdict));
    assert.equal(res.body.analysis.indicators.length, 0);
    assert.ok(['not_configured', 'not_checked'].includes(res.body.analysis.reputation.status));
  });

  // Test 2: Empty and malformed inputs
  await t.test('2. Rejects empty and malformed URLs with HTTP 400', async () => {
    const resEmpty = await request(app)
      .post('/api/check-url')
      .send({ url: '   ' });
    assert.equal(resEmpty.status, 400);
    assert.equal(resEmpty.body.success, false);

    const resInvalid = await request(app)
      .post('/api/check-url')
      .send({ url: 'not-a-valid-url-format' });
    assert.equal(resInvalid.status, 400);
    assert.equal(resInvalid.body.success, false);
  });

  // Test 3: Rejection of unsupported protocols (javascript:, file:, data:, ftp:)
  await t.test('3. Rejects dangerous or unsupported URL schemes (javascript:, file:, data:, ftp:)', async () => {
    const protocols = [
      'javascript:alert(1)',
      'data:text/html;base64,PHNjcmlwdD4=',
      'file:///etc/passwd',
      'ftp://files.example.com/data',
    ];

    for (const protoUrl of protocols) {
      const res = await request(app)
        .post('/api/check-url')
        .send({ url: protoUrl });
      assert.equal(res.status, 400, `Expected 400 for ${protoUrl}`);
      assert.equal(res.body.success, false);
    }
  });

  // Test 4: IP-address hostnames
  await t.test('4. Flags raw IP address hostnames with IP_ADDRESS_HOSTNAME', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'http://192.168.1.100/login' });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 25);
    const hasIpRule = res.body.analysis.indicators.some((i) => i.id === 'IP_ADDRESS_HOSTNAME');
    assert.equal(hasIpRule, true);
  });

  // Test 5: URL shorteners
  await t.test('5. Identifies URL shorteners as a caution indicator without classifying as high threat alone', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://bit.ly/3xSample' });

    assert.equal(res.status, 200);
    assert.ok(['unknown', 'low', 'caution'].includes(res.body.analysis.riskLevel));
    const hasShortener = res.body.analysis.indicators.some((i) => i.id === 'URL_SHORTENER_DETECTED');
    assert.equal(hasShortener, true);
  });

  // Test 6: Suspicious brand lookalike on non-official domain
  await t.test('6. Flags protected brand lookalikes on untrusted TLDs', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'http://sbi-netbanking-portal.xyz/verify' });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasLookalike = res.body.analysis.indicators.some((i) => i.id === 'PROTECTED_BRAND_LOOKALIKE');
    const hasHighTld = res.body.analysis.indicators.some((i) => i.id === 'HIGH_ABUSE_TLD');
    assert.equal(hasLookalike, true);
    assert.equal(hasHighTld, true);
  });

  // Test 7: Legitimate official subdomains NOT falsely flagged
  await t.test('7. Legitimate subdomains of official brands are NOT flagged as lookalikes', async () => {
    const legitimateUrls = [
      'https://retail.onlinesbi.sbi/retail/login.htm',
      'https://netbanking.hdfcbank.com/netbanking/',
      'https://myaadhaar.uidai.gov.in/check-aadhaar-status',
    ];

    for (const legitUrl of legitimateUrls) {
      const res = await request(app)
        .post('/api/check-url')
        .send({ url: legitUrl });

      assert.equal(res.status, 200);
      const hasLookalike = res.body.analysis.indicators.some((i) => i.id === 'PROTECTED_BRAND_LOOKALIKE');
      assert.equal(hasLookalike, false, `Legitimate domain ${legitUrl} should not be flagged as lookalike`);
    }
  });

  // Test 8: HTTPS is not treated as proof of safety
  await t.test('8. HTTPS with phishing indicators still receives high risk score', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://hdfc-kyc-update.top/secure-login' });

    assert.equal(res.status, 200);
    // Despite HTTPS, brand lookalike + top TLD + tokens score high
    assert.ok(res.body.analysis.riskScore >= 50);
    assert.notEqual(res.body.analysis.riskLevel, 'low');
  });

  // Test 9: Suspicious direct file download (.apk)
  await t.test('9. Direct .apk download URL receives high threat score', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://files-share.xyz/update-banking.apk' });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    const hasApk = res.body.analysis.indicators.some((i) => i.id === 'DANGEROUS_FILE_DOWNLOAD');
    assert.equal(hasApk, true);
  });

  // Test 10: Score clamping strictly within 0–100
  await t.test('10. Extreme multi-indicator URL stays clamped at 100 max', () => {
    const extremeUrl = 'http://sbi-login.xyz@192.168.1.1:8888/a/b/c/d/e/download.apk';
    const result = scanUrl(extremeUrl);

    assert.ok(result.riskScore <= 100);
    assert.ok(result.riskScore >= 75);
    assert.ok(['high', 'very_high'].includes(result.riskLevel));
  });

  // Test 11: Reputation status is not_configured when no provider configured
  await t.test('11. Reputation status is not_configured when provider is none', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://github.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.checked, false);
    assert.ok(['not_configured', 'not_checked'].includes(res.body.analysis.reputation.status));
  });

  // Test 12: Confusable Unicode homoglyphs (Cyrillic lookalikes)
  await t.test('12. Flags Cyrillic/Greek lookalike homoglyphs with CONFUSABLE_HOMOGLYPH_ATTACK', () => {
    // Contains Cyrillic 'а' (\u0430) and 'о' (\u043e) in "google"
    const homoglyphUrl = 'https://g\u043e\u043egle.com/login';
    const result = scanUrl(homoglyphUrl);
    assert.ok(result.riskScore >= 40);
    const hasHomoglyph = result.indicators.some((i) => i.id === 'CONFUSABLE_HOMOGLYPH_ATTACK');
    assert.equal(hasHomoglyph, true);
  });

  // Test 13: Obfuscated hex-encoded path traversal
  await t.test('13. Flags hex-encoded traversal and null bytes with OBFUSCATED_HEX_TRAVERSAL', () => {
    const traversalUrl = 'https://attacker-portal.net/files%2e%2e%2fadmin';
    const result = scanUrl(traversalUrl);
    assert.ok(result.riskScore >= 35);
    const hasTraversal = result.indicators.some((i) => i.id === 'OBFUSCATED_HEX_TRAVERSAL');
    assert.equal(hasTraversal, true);
  });

  // Test 14: Embedded user-info credentials in URL
  await t.test('14. Flags credentials embedded in authority with EMBEDDED_USERINFO_CREDENTIALS', () => {
    const userinfoUrl = 'https://admin:secret123@portal.phishing-site.xyz/login';
    const result = scanUrl(userinfoUrl);
    assert.ok(result.riskScore >= 35);
    const hasUserinfo = result.indicators.some((i) => i.id === 'EMBEDDED_USERINFO_CREDENTIALS');
    assert.equal(hasUserinfo, true);
  });
});
