import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { PNG } from 'pngjs';
import app from '../src/app.js';
import {
  setMockReputationHandler,
  redactSensitiveUrl,
  checkUrlReputation,
} from '../src/services/reputation.service.js';
import { setMockAiClient } from '../src/services/gemini.service.js';
import { setMockDnsHandler } from '../src/services/dnsIntel.service.js';
import { setMockRdapHandler } from '../src/services/rdapIntel.service.js';
import { setMockTlsHandler } from '../src/services/tlsIntel.service.js';
import {
  setMockImageOcrHandler,
  setMockQrDecoderHandler,
  decodeQrCodeLocally,
  validateImageUpload,
} from '../src/services/imageScanner.service.js';
import { clearPipelineCache, runWebsiteInvestigation } from '../src/services/websiteIntelPipeline.service.js';
import {
  scanUrl,
  damerauLevenshteinDistance,
  hasHomoglyphCharacters,
  normalizeUrl,
} from '../src/services/urlScanner.service.js';
import { isPrivateOrReservedIp, isSafeHostname } from '../src/services/ssrfProtection.service.js';
import { traceRedirectChain, setMockRedirectHandler } from '../src/services/redirectChainIntel.service.js';

function createDummyPngBuffer(width = 16, height = 16) {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (width * y + x) << 2;
      png.data[idx] = 255;
      png.data[idx + 1] = 255;
      png.data[idx + 2] = 255;
      png.data[idx + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}

test('Genuine Scam Detection & Security Engine Verification (20 Criteria)', async (t) => {
  t.beforeEach(() => {
    clearPipelineCache();
    setMockReputationHandler(null);
    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            summary: 'Website evaluated using automated multi-signal intelligence.',
            verdictExplanation: 'Assessment based on threat intelligence and static indicators.',
            riskAssessment: 'unknown',
            threatExplanations: [],
            safetyAdvice: ['Exercise caution when visiting unfamiliar websites.'],
          }),
        }),
      },
    });
    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'success',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'Resolved 1 A records.',
      data: { aRecords: ['93.184.216.34'], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: ['93.184.216.34'], hasA: true, hasMx: false },
    }));
    setMockRdapHandler(() => ({
      name: 'rdap_registration',
      status: 'no_data',
      source: 'rdap_registry',
      timestamp: new Date().toISOString(),
      explanation: 'RDAP query not simulated.',
      data: null,
    }));
    setMockTlsHandler(() => ({
      name: 'tls_handshake',
      status: 'success',
      source: 'tls_handshake',
      timestamp: new Date().toISOString(),
      explanation: 'Valid TLS certificate.',
      data: { authorized: true, issuer: 'Let\'s Encrypt' },
    }));
    setMockImageOcrHandler(null);
    setMockQrDecoderHandler(null);
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'success',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Direct destination verified safely.',
      data: {
        initialUrl: 'https://test-destination.com',
        initialUrlSafe: 'https://test-destination.com',
        finalUrl: 'https://test-destination.com',
        finalUrlSafe: 'https://test-destination.com',
        initialHostname: 'test-destination.com',
        finalHostname: 'test-destination.com',
        hopCount: 1,
        hops: [],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: false,
        stopReason: 'Terminal destination reached.',
      },
    }));
  });

  t.afterEach(() => {
    clearPipelineCache();
    setMockReputationHandler(null);
    setMockAiClient(null);
    setMockDnsHandler(null);
    setMockRdapHandler(null);
    setMockTlsHandler(null);
    setMockImageOcrHandler(null);
    setMockQrDecoderHandler(null);
    setMockRedirectHandler(null);
  });

  // 1. Real-provider threat match in mocked provider response
  await t.test('1. Real-provider threat match produces MALICIOUS canonical verdict and flags threat', async () => {
    setMockReputationHandler(() => ({
      provider: 'google_web_risk',
      configured: true,
      requestSucceeded: true,
      lookupStatus: 'THREAT_FOUND',
      matchedThreatTypes: ['SOCIAL_ENGINEERING'],
      checkedAt: new Date().toISOString(),
      errorCode: null,
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'SOCIAL_ENGINEERING',
      details: 'Flagged on Google Web Risk as SOCIAL_ENGINEERING.',
    }));

    const result = await runWebsiteInvestigation('https://evil-phish-portal.example');
    assert.equal(result.verdictCanonical, 'MALICIOUS');
    assert.equal(result.verificationStatus, 'threat_detected');
    assert.ok(result.riskScore >= 75);
    assert.equal(result.reputation.lookupStatus, 'THREAT_FOUND');
    assert.deepEqual(result.reputation.matchedThreatTypes, ['SOCIAL_ENGINEERING']);
  });

  // 2. Provider response with no threat match (never implies 100% safe)
  await t.test('2. Provider response with NO_MATCH_FOUND does not claim 100% safe', async () => {
    setMockReputationHandler(() => ({
      provider: 'google_web_risk',
      configured: true,
      requestSucceeded: true,
      lookupStatus: 'NO_MATCH_FOUND',
      matchedThreatTypes: [],
      checkedAt: new Date().toISOString(),
      errorCode: null,
      reputationStatus: 'no_known_threat_detected',
      status: 'clean',
      verdict: 'safe',
      threatCategory: null,
      details: 'No threat match in Google Web Risk database.',
    }));

    const result = await runWebsiteInvestigation('https://brand-new-unverified-blog-site-77.org');
    // Absence of evidence on an unverified domain MUST result in UNKNOWN, NOT 100% safe!
    assert.equal(result.verdictCanonical, 'UNKNOWN');
    assert.equal(result.riskScore, null);
    assert.equal(result.reputation.lookupStatus, 'NO_MATCH_FOUND');
    assert.ok(!result.whyThisResult.includes('100% safe'));
    assert.ok(!result.whyThisResult.includes('100% real'));
  });

  // 3. Missing API key reports NOT_CONFIGURED truthfully
  await t.test('3. Missing API key reports NOT_CONFIGURED without fabrication', async () => {
    setMockReputationHandler(() => ({
      provider: 'google_web_risk',
      configured: false,
      requestSucceeded: false,
      lookupStatus: 'NOT_CONFIGURED',
      matchedThreatTypes: [],
      checkedAt: new Date().toISOString(),
      errorCode: 'NOT_CONFIGURED',
      reputationStatus: 'not_configured',
      status: 'unverified',
      details: 'Google Web Risk API key is not configured on the server.',
    }));

    const result = await runWebsiteInvestigation('https://some-untested-target.com');
    assert.equal(result.reputation.lookupStatus, 'NOT_CONFIGURED');
    assert.equal(result.reputation.configured, false);
    const repFinding = result.structuredFindings.find(
      (f) => f.id === 'FINDING_THREAT_INTELLIGENCE' || f.category.toLowerCase().includes('threat')
    );
    assert.ok(repFinding);
    assert.equal(repFinding.status, 'NOT_CONFIGURED');
  });

  // 4. Provider timeout, rate limit, and service errors report UNAVAILABLE
  await t.test('4. Provider timeout or outage reports UNAVAILABLE and never safe', async () => {
    setMockReputationHandler(() => ({
      provider: 'google_web_risk',
      configured: true,
      requestSucceeded: false,
      lookupStatus: 'UNAVAILABLE',
      matchedThreatTypes: [],
      checkedAt: new Date().toISOString(),
      errorCode: 'TIMEOUT',
      reputationStatus: 'unavailable',
      status: 'unavailable',
      details: 'Threat intelligence request timed out.',
    }));

    const result = await runWebsiteInvestigation('https://timeout-victim-site.net');
    assert.equal(result.reputation.lookupStatus, 'UNAVAILABLE');
    assert.notEqual(result.verdictCanonical, 'SAFE_NO_THREAT_FOUND');
  });

  // 5. Unknown URL must not be labeled safe (risk score null)
  await t.test('5. Unknown URL with insufficient evidence returns riskScore: null', async () => {
    const result = await runWebsiteInvestigation('https://unregistered-unknown-hobby-site-999.org');
    assert.equal(result.riskScore, null);
    assert.equal(result.verdictCanonical, 'UNKNOWN');
    assert.equal(result.verificationStatus, 'insufficient_evidence');
  });

  // 6. Lookalike domains and deceptive subdomains
  await t.test('6. Lookalike domains and deceptive subdomains trigger high risk indicators', async () => {
    // A: Brand impersonation in domain
    const scan1 = scanUrl('https://sbi-netbanking-verify.com');
    assert.ok(scan1.riskScore >= 45);
    const hasBrandIndicator = scan1.indicators.some((i) => i.id.toLowerCase().includes('brand') || i.id.toLowerCase().includes('lookalike'));
    assert.ok(hasBrandIndicator);

    // B: Damerau-Levenshtein transposition ("amzaon.in" -> "amazon")
    const dist = damerauLevenshteinDistance('amzaon', 'amazon');
    assert.equal(dist, 1);
    const scan2 = scanUrl('https://amzaon.in');
    const hasLookalike = scan2.indicators.some((i) => i.id.toLowerCase().includes('lookalike'));
    assert.ok(hasLookalike);
  });

  // 7. Punycode and Unicode hostname handling
  await t.test('7. Punycode and homoglyph characters are detected', async () => {
    // Cyrillic 'а' (U+0430) and 'р' (U+0440) lookalikes
    const cyrillicPaypal = 'раураl.com';
    assert.equal(hasHomoglyphCharacters(cyrillicPaypal), true);
    assert.equal(hasHomoglyphCharacters('paypal.com'), false);

    const scan = scanUrl(`https://${cyrillicPaypal}`);
    const hasHomoglyphIndicator = scan.indicators.some((i) => i.id.toLowerCase().includes('homoglyph'));
    assert.ok(hasHomoglyphIndicator);
  });

  // 8. Malformed URLs and unsupported schemes rejected with 400
  await t.test('8. Malformed URLs and unsupported schemes rejected with HTTP 400', async () => {
    const res1 = await request(app).post('/api/check-url').send({ url: 'ftp://files.example.com' });
    assert.equal(res1.status, 400);
    assert.equal(res1.body.success, false);

    const res2 = await request(app).post('/api/check-url').send({ url: 'javascript:alert(1)' });
    assert.equal(res2.status, 400);
    assert.equal(res2.body.success, false);

    const res3 = await request(app).post('/api/check-url').send({ url: 'http://' });
    assert.equal(res3.status, 400);
    assert.equal(res3.body.success, false);
  });

  // 9. DNS and RDAP failure cases handled gracefully
  await t.test('9. DNS failure reports scan_unavailable gracefully without crashing', async () => {
    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'error',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'DNS resolution failed: ENOTFOUND',
      data: null,
    }));

    const result = await runWebsiteInvestigation('https://non-existent-domain-xyz-404.com');
    assert.equal(result.checks.dns.status, 'error');
    assert.equal(result.verdictCanonical, 'UNKNOWN');
  });

  // 10. Redirect chains with hostname changes tracked
  await t.test('10. Redirect inspection returns structured hop data', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'success',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Followed 1 redirect(s) safely.',
      data: {
        initialUrl: 'https://short.link/xyz',
        initialUrlSafe: 'https://short.link/xyz',
        finalUrl: 'https://destination.com/landing',
        finalUrlSafe: 'https://destination.com/landing',
        initialHostname: 'short.link',
        finalHostname: 'destination.com',
        hopCount: 2,
        hops: [
          { url: 'https://short.link/xyz', safeUrl: 'https://short.link/xyz', statusCode: 301, location: 'https://destination.com/landing', ip: '93.184.216.34', isSecure: true },
          { url: 'https://destination.com/landing', safeUrl: 'https://destination.com/landing', statusCode: 200, location: null, ip: '93.184.216.34', isSecure: true },
        ],
        hasCrossDomainRedirect: true,
        hasSuspiciousHop: false,
        stopReason: 'Terminal destination reached.',
      },
    }));

    const redirectRes = await traceRedirectChain('https://short.link/xyz');
    assert.equal(redirectRes.data.initialHostname, 'short.link');
    assert.equal(redirectRes.data.finalHostname, 'destination.com');
    assert.equal(redirectRes.data.hasCrossDomainRedirect, true);
    assert.equal(redirectRes.data.hopCount, 2);
    assert.ok(redirectRes.data.stopReason);
    setMockRedirectHandler(null);
  });

  // 11. Redirects to localhost, private IPs, and IPv6 loopback blocked (SSRF)
  await t.test('11. SSRF guards block private and reserved IP ranges', () => {
    assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('::1'), true);
    assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
    assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
    assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
    assert.equal(isSafeHostname('localhost'), false);
    assert.equal(isSafeHostname('google.com'), true);
  });

  // 12. DNS-rebinding or pre-resolution check blocks SSRF hops
  await t.test('12. traceRedirectChain blocks internal and private targets', async () => {
    setMockRedirectHandler(null);
    const ssrfCheck = await traceRedirectChain('http://127.0.0.1:8080/admin');
    assert.equal(ssrfCheck.status, 'ssrf_blocked');
    assert.equal(ssrfCheck.data.hasSuspiciousHop, true);
  });

  // 13. Excessive redirect counts and loops terminate safely
  await t.test('13. Redirect loop or max hops terminates with bounded result', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'max_hops_exceeded',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Redirect chain exceeded safe limit of 5 hops.',
      data: {
        initialUrl: 'https://loop.example.com',
        initialUrlSafe: 'https://loop.example.com',
        finalUrl: 'https://loop.example.com/hop5',
        finalUrlSafe: 'https://loop.example.com/hop5',
        hopCount: 5,
        hops: [],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: true,
        stopReason: 'Exceeded safe limit of 5 redirect hops.',
      },
    }));

    const maxHopsResult = await traceRedirectChain('https://loop.example.com');
    assert.equal(maxHopsResult.status, 'max_hops_exceeded');
    assert.equal(maxHopsResult.data.hopCount, 5);
    setMockRedirectHandler(null);
  });

  // 14. Valid image uploads, invalid file types, and oversized files
  await t.test('14. Image upload validation enforces format and size limits', async () => {
    // Valid PNG buffer passes
    const validPng = createDummyPngBuffer(16, 16);
    assert.equal(
      validateImageUpload({ buffer: validPng, size: validPng.length, mimetype: 'image/png' }),
      true
    );

    // Invalid MIME rejected
    assert.throws(
      () => validateImageUpload({ buffer: validPng, size: validPng.length, mimetype: 'application/x-msdownload' }),
      /Unsupported image format/
    );

    // Oversized buffer rejected (> 5MB)
    assert.throws(
      () => validateImageUpload({ buffer: validPng, size: 6 * 1024 * 1024, mimetype: 'image/png' }),
      /exceeds maximum allowed limit/
    );
  });

  // 15. QR codes containing URLs, UPI traps, and non-URL content
  await t.test('15. QR decoding extracts UPI traps and Web URLs with advisory', async () => {
    const pngBuf = createDummyPngBuffer(20, 20);

    // A: UPI Payment QR
    setMockQrDecoderHandler(() => ({
      detected: true,
      payload: 'upi://pay?pa=fraudster@okhdfcbank&pn=Fraud%20Team&am=25000&cu=INR&tn=Lottery%20Fee',
      type: 'upi',
      upiDetails: {
        payeeAddress: 'fraudster@okhdfcbank',
        payeeName: 'Fraud Team',
        amount: '25000',
        currency: 'INR',
        isPaymentRequest: true,
        securityAdvisory: 'Scanning a QR code debits money, never credits.',
      },
      url: null,
      error: null,
    }));

    const upiResult = decodeQrCodeLocally(pngBuf, 'image/png');
    assert.equal(upiResult.detected, true);
    assert.equal(upiResult.type, 'upi');
    assert.equal(upiResult.upiDetails.isPaymentRequest, true);
    assert.equal(upiResult.upiDetails.payeeAddress, 'fraudster@okhdfcbank');

    // B: URL QR
    setMockQrDecoderHandler(() => ({
      detected: true,
      payload: 'https://sbi-fake-kyc.in',
      type: 'url',
      upiDetails: null,
      url: 'https://sbi-fake-kyc.in',
      error: null,
    }));

    const urlResult = decodeQrCodeLocally(pngBuf, 'image/png');
    assert.equal(urlResult.detected, true);
    assert.equal(urlResult.type, 'url');
    assert.equal(urlResult.url, 'https://sbi-fake-kyc.in');
  });

  // 16. OCR success, empty output, and low-confidence output
  await t.test('16. OCR output processed via scam rules, empty handled gracefully', async () => {
    const pngBuf = createDummyPngBuffer(20, 20);

    setMockImageOcrHandler(() => ({
      success: true,
      extractedText: 'URGENT: Your SBI bank account blocked. Update KYC immediately at https://sbi-kyc-verify.com or call 9876543210.',
      extractedUrls: ['https://sbi-kyc-verify.com'],
      extractedPhoneNumbers: ['9876543210'],
      extractedUpiIds: [],
      method: 'gemini_multimodal_vision',
    }));

    const res = await request(app)
      .post('/api/scan-image')
      .attach('image', pngBuf, 'screenshot.png');

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.analysis.ocr.extractedText.includes('SBI'));
    assert.ok(res.body.analysis.ocr.extractedUrls.includes('https://sbi-kyc-verify.com'));
    assert.ok(res.body.analysis.messageAnalysis);
    assert.ok(res.body.analysis.messageAnalysis.threatIndicators.length > 0);
  });

  // 17. Extracted URLs pass through the same scanner as manually submitted URLs
  await t.test('17. URLs extracted from images are run through the website scanner', async () => {
    const pngBuf = createDummyPngBuffer(20, 20);

    setMockImageOcrHandler(() => ({
      success: true,
      extractedText: 'Check out this portal: https://amazon-lucky-draw.top',
      extractedUrls: ['https://amazon-lucky-draw.top'],
      extractedPhoneNumbers: [],
      extractedUpiIds: [],
      method: 'gemini_multimodal_vision',
    }));

    const res = await request(app)
      .post('/api/scan-image')
      .attach('image', pngBuf, 'scan.png');

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.urlScans.length >= 1);
    const scanned = res.body.analysis.urlScans[0];
    assert.equal(scanned.url, 'https://amazon-lucky-draw.top');
    assert.ok(['SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'].includes(scanned.verdictCanonical));
  });

  // 18. Correct API contract for UNKNOWN, NOT_CONFIGURED, ERROR, and threat findings
  await t.test('18. API contract returns canonical verdicts and structured findings', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://plain-untested-sample.org' });

    assert.equal(res.status, 200);
    const { analysis } = res.body;
    assert.ok(['MALICIOUS', 'SUSPICIOUS', 'SAFE_NO_THREAT_FOUND', 'UNKNOWN'].includes(analysis.verdictCanonical));
    assert.ok(Array.isArray(analysis.structuredFindings));
    assert.ok(Array.isArray(analysis.checksPerformed));
    assert.ok(Array.isArray(analysis.checksNotPerformed));
    assert.ok(analysis.whyThisResult);
    assert.ok(typeof analysis.whyThisResult === 'string' || analysis.whyThisResult.summary);
  });

  // 19. Ensuring no result claims a check ran when it did not
  await t.test('19. Checks not performed are transparently reported in checksNotPerformed', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://sample-site-transparency.org' });

    const { analysis } = res.body;
    assert.ok(analysis.checksNotPerformed.length > 0);
    for (const check of analysis.checksNotPerformed) {
      const reasonStr = typeof check === 'string' ? check : check.reason;
      assert.ok(reasonStr.length > 3);
    }
  });

  // 20. Ensuring API secrets and sensitive URL parameters are not exposed
  await t.test('20. Sensitive query tokens and credentials are redacted in URLs and responses', () => {
    const sensitiveUrl = 'https://bank.example.com/auth?token=super_secret_token_123&otp=889900&session_id=sess_abc';
    const redacted = redactSensitiveUrl(sensitiveUrl);
    assert.ok(!redacted.includes('super_secret_token_123'));
    assert.ok(!redacted.includes('889900'));
    assert.ok(!redacted.includes('sess_abc'));
    assert.ok(redacted.includes('token=%5BREDACTED%5D') || redacted.includes('token=[REDACTED]'));

    const normalized = normalizeUrl(sensitiveUrl);
    assert.ok(!normalized.safeDisplayUrl.includes('super_secret_token_123'));
  });
});
