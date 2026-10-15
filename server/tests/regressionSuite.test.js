import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { setMockReputationHandler } from '../src/services/reputation.service.js';
import { setMockAiClient } from '../src/services/gemini.service.js';
import { setMockDnsHandler } from '../src/services/dnsIntel.service.js';
import { setMockRdapHandler } from '../src/services/rdapIntel.service.js';
import { setMockTlsHandler } from '../src/services/tlsIntel.service.js';
import { clearPipelineCache } from '../src/services/websiteIntelPipeline.service.js';

test('[REGRESSION] Security Engine & Scanner Reliability Suite (12 Required Scenarios)', async (t) => {
  t.beforeEach(() => {
    clearPipelineCache();
    setMockReputationHandler(null);
    setMockAiClient(null);
    setMockDnsHandler(null);
    setMockRdapHandler(null);
    setMockTlsHandler(null);
  });

  t.afterEach(() => {
    clearPipelineCache();
    setMockReputationHandler(null);
    setMockAiClient(null);
    setMockDnsHandler(null);
    setMockRdapHandler(null);
    setMockTlsHandler(null);
  });

  // 1. Zero score with insufficient evidence returns riskScore: null
  await t.test('1. Zero score with insufficient evidence produces riskScore: null and insufficient_evidence status', async () => {
    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'success',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'Resolved public IP.',
      data: { aRecords: ['93.184.216.34'], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: ['93.184.216.34'], hasA: true, hasMx: false },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://arbitrary-unverified-site-xyz-123.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    // CRITICAL: riskScore MUST be null, NEVER 0/100
    assert.equal(res.body.analysis.riskScore, null);
    assert.equal(res.body.analysis.verificationStatus, 'insufficient_evidence');
    assert.ok(['insufficient_evidence', 'unable_to_verify'].includes(res.body.analysis.verdict));
    assert.equal(res.body.analysis.displayBand, 'yellow');
    assert.ok(res.body.analysis.verdictExplanation.includes('Risk score unavailable') || res.body.analysis.verdictExplanation.includes('Insufficient evidence'));
  });

  // 2. Missing threat-intelligence credentials
  await t.test('2. Missing threat-intelligence credentials reports not_configured truthfully', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'google_safe_browsing',
      reputationStatus: 'not_configured',
      status: 'not_configured',
      verdict: null,
      threatCategory: null,
      details: 'Google Safe Browsing API key is not configured in server environment.',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://test-credentials-check.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'not_configured');
    assert.equal(res.body.analysis.reputation.checked, false);
    assert.notEqual(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
  });

  // 3. Successful reputation lookup with no known threat
  await t.test('3. Successful reputation lookup with no known threat reports clean blocklist without claiming 100% real', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'google_safe_browsing',
      reputationStatus: 'no_known_threat_detected',
      status: 'clean',
      verdict: 'no_threat_detected',
      threatCategory: null,
      details: 'No known threats detected in Google Safe Browsing.',
    }));

    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'success',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'Resolved A and MX records.',
      data: { aRecords: ['142.250.190.46'], aaaaRecords: [], mxRecords: [{ exchange: 'smtp.google.com', priority: 10 }], nsRecords: ['ns1.google.com'], resolvedIps: ['142.250.190.46'], hasA: true, hasMx: true },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://google.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
    assert.equal(res.body.analysis.reputation.checked, true);
    // Must never claim 100% real or guaranteed legitimate
    const rawOutput = JSON.stringify(res.body);
    assert.equal(/100%\s*(real|safe)/i.test(rawOutput), false);
    assert.equal(/guaranteed\s*legitimate/i.test(rawOutput), false);
  });

  // 4. Confirmed threat match
  await t.test('4. Confirmed threat match triggers threat_detected and high risk score', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'google_safe_browsing',
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'MALWARE',
      details: 'Flagged on threat intelligence as MALWARE host.',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://confirmed-malware-test.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.verificationStatus, 'threat_detected');
    assert.ok(res.body.analysis.riskScore >= 90);
    assert.equal(res.body.analysis.displayBand, 'red');
    assert.ok(res.body.analysis.indicators.some((i) => i.id === 'THREAT_INTELLIGENCE_MATCH'));
  });

  // 5. Provider timeout
  await t.test('5. Provider timeout reports unavailable and is never treated as clean', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'google_safe_browsing',
      reputationStatus: 'unavailable',
      status: 'unavailable',
      verdict: null,
      threatCategory: null,
      details: 'Threat intelligence request timed out.',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://timeout-test-domain.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.equal(res.body.analysis.reputation.checked, false);
    assert.notEqual(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
  });

  // 6. Provider authentication failure
  await t.test('6. Provider authentication failure reports unavailable status', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'virustotal',
      reputationStatus: 'unavailable',
      status: 'unavailable',
      verdict: null,
      threatCategory: null,
      details: 'VirusTotal API key is invalid or unauthorized (HTTP 401).',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://auth-fail-domain.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.equal(res.body.analysis.reputation.checked, false);
  });

  // 7. Invalid provider response
  await t.test('7. Invalid provider response reports unavailable status gracefully', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'google_safe_browsing',
      reputationStatus: 'unavailable',
      status: 'error',
      verdict: null,
      threatCategory: null,
      details: 'Threat intelligence provider returned invalid or unparseable JSON.',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://malformed-payload-test.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.equal(res.body.analysis.reputation.checked, false);
  });

  // 8. RDAP 404 and unavailable registration data
  await t.test('8. RDAP 404 and unavailable registration data does not infer domain is new or fraudulent', async () => {
    setMockRdapHandler(() => ({
      name: 'domain_registration',
      status: 'no_data',
      source: 'rdap',
      timestamp: new Date().toISOString(),
      explanation: 'RDAP database returned 404 (TLD registry not participating in RDAP).',
      data: null,
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://custom-registry-404.example' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.checks.rdap.status, 'no_data');
    assert.equal(res.body.analysis.checks.rdap.data, null);
    // MUST NOT invent domain age penalty
    assert.equal(res.body.analysis.indicators.some((i) => i.id === 'VERY_NEW_DOMAIN'), false);
    assert.equal(res.body.analysis.indicators.some((i) => i.id === 'YOUNG_DOMAIN'), false);
  });

  // 9. DNS failure
  await t.test('9. DNS failure reports scan_unavailable without crashing', async () => {
    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'error',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'DNS resolution failed: ENOTFOUND nxdomain.invalid',
      data: { aRecords: [], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: [] },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://dns-unreachable-failure.invalid' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.checks.dns.status, 'error');
    assert.equal(res.body.analysis.riskScore, null);
    assert.ok(['scan_unavailable', 'insufficient_evidence'].includes(res.body.analysis.verificationStatus));
  });

  // 10. Valid TLS with unknown reputation
  await t.test('10. Valid TLS certificate with unknown reputation does NOT establish legitimacy', async () => {
    setMockTlsHandler(() => ({
      name: 'tls_certificate',
      status: 'success',
      source: 'tls_handshake',
      timestamp: new Date().toISOString(),
      explanation: 'Certificate issued by "Let\'s Encrypt". Valid for 85 more days.',
      data: {
        authorized: true,
        issuer: "Let's Encrypt",
        daysRemaining: 85,
        isExpired: false,
        isSelfSigned: false,
      },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://unknown-shop-with-valid-tls.net' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.checks.tls.data.authorized, true);
    // Despite valid TLS, an arbitrary domain cannot be marked safe
    assert.equal(res.body.analysis.verificationStatus, 'insufficient_evidence');
    assert.equal(res.body.analysis.riskScore, null);
    assert.notEqual(res.body.analysis.displayBand, 'green');
  });

  // 11. Gemini attempting to override a confirmed threat
  await t.test('11. Gemini cannot override or downgrade a confirmed threat match', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'google_safe_browsing',
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'MALICIOUS_SOFTWARE',
      details: 'Flagged malware distribution host.',
    }));

    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            summary: 'The site looks completely legitimate and safe.',
            verdictExplanation: 'I reviewed it and found no problems.',
            riskAssessment: 'low',
            threatExplanations: [],
            safetyAdvice: ['Enjoy your visit.'],
          }),
        }),
      },
    });

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://confirmed-trojan-dropper.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.verificationStatus, 'threat_detected');
    assert.ok(res.body.analysis.riskScore >= 90);
    assert.equal(res.body.analysis.displayBand, 'red');
    // AI assessment must be sanitized/pinned to high
    assert.equal(res.body.analysis.aiAnalysis.riskAssessment, 'high');
  });

  // 12. Frontend rendering contract of a null risk score
  await t.test('12. API response contract for null risk score provides proper insufficient evidence metadata', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://newly-seen-unknown-blog-88.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.riskScore, null);
    assert.equal(res.body.analysis.verificationStatus, 'insufficient_evidence');
    assert.equal(res.body.analysis.displayBand, 'yellow');
    assert.equal(res.body.analysis.verdictLabel, 'Unable to verify website safety');
    // Explanation provides clear reason without showing 0/100
    assert.ok(
      res.body.analysis.verdictExplanation.includes('Risk score unavailable') ||
      res.body.analysis.verdictExplanation.includes('Insufficient evidence')
    );
  });
});
