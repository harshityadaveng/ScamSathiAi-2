import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { setMockReputationHandler } from '../src/services/reputation.service.js';
import { setMockAiClient } from '../src/services/gemini.service.js';
import { setMockDnsHandler, checkDnsIntel } from '../src/services/dnsIntel.service.js';
import { setMockRdapHandler, checkRdapIntel } from '../src/services/rdapIntel.service.js';
import { setMockTlsHandler, checkTlsIntel } from '../src/services/tlsIntel.service.js';
import { clearPipelineCache } from '../src/services/websiteIntelPipeline.service.js';
import { scanUrl } from '../src/services/urlScanner.service.js';
import { isPrivateOrReservedIp, isSafeHostname } from '../src/services/ssrfProtection.service.js';

test('[SIMULATED] Website Intelligence Pipeline & Threat Detection Suite', async (t) => {
  t.beforeEach(() => {
    clearPipelineCache();
  });

  t.afterEach(() => {
    // Reset all mock handlers
    setMockReputationHandler(null);
    setMockAiClient(null);
    setMockDnsHandler(null);
    setMockRdapHandler(null);
    setMockTlsHandler(null);
    clearPipelineCache();
  });

  // 1. Confirmed threat match (Simulated)
  await t.test('[SIMULATED] 1. A confirmed threat-intelligence match triggers threat_detected and high risk', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'google_safe_browsing',
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'SOCIAL_ENGINEERING',
      details: 'Flagged on Google Safe Browsing as SOCIAL_ENGINEERING phishing site.',
    }));

    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'success',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'Resolved 1 A records.',
      data: { aRecords: ['93.184.216.34'], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: ['93.184.216.34'], hasA: true, hasMx: false },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://malicious-confirmed-phish.xyz' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.analysis.riskScore >= 90);
    assert.equal(res.body.analysis.verificationStatus, 'threat_detected');
    assert.equal(res.body.analysis.displayBand, 'red');
    assert.equal(res.body.analysis.reputation.reputationStatus, 'confirmed_threat');
    assert.ok(res.body.analysis.indicators.some((i) => i.id === 'THREAT_INTELLIGENCE_MATCH'));
  });

  // 2. Clean reputation response on authoritative domain (Simulated)
  await t.test('[SIMULATED] 2. A successful reputation lookup with no known threat on authoritative domain', async () => {
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

    setMockRdapHandler(() => ({
      name: 'domain_registration',
      status: 'success',
      source: 'rdap',
      timestamp: new Date().toISOString(),
      explanation: 'Registered in 1997.',
      data: { registrationDate: '1997-09-15T04:00:00Z', ageDays: 10000, ageYears: 27.4, registrar: 'MarkMonitor Inc.', isYoungDomain: false, isVeryNewDomain: false },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://google.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
    assert.ok(['checks_completed_no_known_threat', 'limited_checks_completed'].includes(res.body.analysis.verificationStatus));
    assert.equal(res.body.analysis.verdictLabel, 'Low risk indicators');
    // Ensure no unsupported claims
    assert.notEqual(res.body.analysis.verdictLabel.toLowerCase(), 'verified safe');
    assert.notEqual(res.body.analysis.verdictLabel.toLowerCase(), '100% real');
  });

  // 3. Missing reputation API key (Simulated)
  await t.test('[SIMULATED] 3. Missing reputation credentials reports not_configured truthfully', async () => {
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
      .send({ url: 'https://example.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'not_configured');
    assert.equal(res.body.analysis.reputation.checked, false);
  });

  // 4. Reputation API timeout (Simulated)
  await t.test('[SIMULATED] 4. Reputation-provider timeout reports unavailable and never clean', async () => {
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
      .send({ url: 'https://example.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.notEqual(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
  });

  // 5. Provider authentication failure (Simulated)
  await t.test('[SIMULATED] 5. Provider authentication failure (HTTP 401/403) reports unavailable', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'google_safe_browsing',
      reputationStatus: 'unavailable',
      status: 'unavailable',
      verdict: null,
      threatCategory: null,
      details: 'Threat intelligence provider responded with error (HTTP 403 Forbidden).',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://auth-failure-test.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.equal(res.body.analysis.reputation.checked, false);
    assert.notEqual(res.body.analysis.reputation.reputationStatus, 'no_known_threat_detected');
  });

  // 6. Invalid provider response (Simulated)
  await t.test('[SIMULATED] 6. Invalid provider response (malformed body or unexpected status) reports unavailable', async () => {
    setMockReputationHandler(() => ({
      checked: false,
      provider: 'google_safe_browsing',
      reputationStatus: 'unavailable',
      status: 'unavailable',
      verdict: null,
      threatCategory: null,
      details: 'Failed to communicate with threat intelligence provider (Malformed payload).',
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://malformed-response-test.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.reputation.reputationStatus, 'unavailable');
    assert.equal(res.body.analysis.reputation.checked, false);
  });

  // 7. Missing RDAP information (Simulated)
  await t.test('[SIMULATED] 7. Missing RDAP information returns no_data status gracefully', async () => {
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
      .send({ url: 'https://unsupported-tld.example' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.analysis.checks.rdap.status, 'no_data');
  });

  // 8. DNS lookup failure (Simulated)
  await t.test('[SIMULATED] 8. DNS lookup failure reports unavailable status without crashing', async () => {
    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'unavailable',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'DNS resolution query timed out.',
      data: { aRecords: [], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: [] },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://dns-failure-simulated.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.analysis.checks.dns.status, 'unavailable');
  });

  // 9. TLS inspection failure (Simulated)
  await t.test('[SIMULATED] 9. TLS inspection failure reports unavailable status', async () => {
    setMockTlsHandler(() => ({
      name: 'tls_certificate',
      status: 'unavailable',
      source: 'tls_handshake',
      timestamp: new Date().toISOString(),
      explanation: 'TLS connection to port 443 timed out.',
      data: null,
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://tls-failure-simulated.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.analysis.checks.tls.status, 'unavailable');
  });

  // 10. Gemini returning an unsupported or fabricated safe verdict (Simulated)
  await t.test('[SIMULATED] 10. Gemini returning an unsupported or fabricated safe verdict is sanitized', async () => {
    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            summary: 'This website is 100% real and verified safe.',
            verdictExplanation: 'Authentic website with no issues.',
            riskAssessment: 'low',
            threatExplanations: [],
            safetyAdvice: ['Enjoy shopping.'],
          }),
        }),
      },
    });

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://random-unknown-shop-123.com' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.verificationStatus, 'insufficient_evidence');
    assert.ok(['insufficient_evidence', 'unable_to_verify'].includes(res.body.analysis.verdict));
    assert.equal(res.body.analysis.riskScore, null);
    assert.equal(res.body.analysis.summary.includes('100% real'), false);
    assert.equal(res.body.analysis.summary.includes('verified safe'), false);
  });

  // 11. A lookalike domain triggering a heuristic (Simulated)
  await t.test('[SIMULATED] 11. A lookalike domain triggering brand impersonation and high abuse TLD', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://sbi-netbanking-portal.xyz/login' });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 50);
    assert.ok(res.body.analysis.indicators.some((i) => i.id === 'PROTECTED_BRAND_LOOKALIKE'));
    assert.ok(res.body.analysis.indicators.some((i) => i.id === 'HIGH_ABUSE_TLD'));
  });

  // 12. An unknown domain with insufficient evidence (Simulated)
  await t.test('[SIMULATED] 12. An unknown domain with insufficient evidence returns unable_to_verify', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://plain-unknown-site-999.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.verificationStatus, 'insufficient_evidence');
    assert.ok(['insufficient_evidence', 'unable_to_verify'].includes(res.body.analysis.verdict));
    assert.equal(res.body.analysis.riskScore, null);
    assert.equal(res.body.analysis.displayBand, 'yellow');
  });

  // 13. Confirmed threat that Gemini attempts to dismiss (Simulated)
  await t.test('[SIMULATED] 13. Confirmed threat match cannot be dismissed or overridden by Gemini AI', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'google_safe_browsing',
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'MALWARE',
      details: 'Flagged malware distribution host.',
    }));

    setMockAiClient({
      models: {
        generateContent: async () => ({
          text: JSON.stringify({
            summary: 'Looks like a regular portal, no risk.',
            verdictExplanation: 'I think it is safe.',
            riskAssessment: 'low',
            threatExplanations: [],
            safetyAdvice: ['Be careful.'],
          }),
        }),
      },
    });

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://trojan-delivery.top' });

    assert.equal(res.status, 200);
    assert.ok(res.body.analysis.riskScore >= 90);
    assert.equal(res.body.analysis.verificationStatus, 'threat_detected');
    assert.equal(res.body.analysis.displayBand, 'red');
  });

  // 14. SSRF attempts using private IPs and localhost are blocked (Simulated)
  await t.test('[SIMULATED] 14. SSRF attempts using private IPs and cloud metadata are blocked', async () => {
    assert.equal(isSafeHostname('localhost'), false);
    assert.equal(isSafeHostname('127.0.0.1'), false);
    assert.equal(isSafeHostname('169.254.169.254'), false);
    assert.equal(isSafeHostname('sub.internal'), false);
    assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
    assert.equal(isPrivateOrReservedIp('172.16.5.1'), true);
    assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);

    setMockDnsHandler(() => ({
      name: 'dns_resolution',
      status: 'error',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: 'Domain resolved to private or reserved IP address (SSRF blocked).',
      data: { aRecords: [], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: ['169.254.169.254'], ssrfBlocked: true },
    }));

    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'http://metadata-attacker.org' });

    assert.equal(res.status, 200);
    assert.equal(res.body.analysis.checks.dns.data.ssrfBlocked, true);
    assert.ok(res.body.analysis.indicators.some((i) => i.id === 'SSRF_TARGET_BLOCKED'));
  });

  // 15. API response never claims 100% real or guaranteed legitimate
  await t.test('[SIMULATED] 15. Full API response contains no claims of 100% real or guaranteed legitimate', async () => {
    const res = await request(app)
      .post('/api/check-url')
      .send({ url: 'https://wikipedia.org' });

    const rawBody = JSON.stringify(res.body);
    assert.equal(/100%\s*(real|safe)/i.test(rawBody), false);
    assert.equal(/guaranteed\s*legitimate/i.test(rawBody), false);
    assert.equal(/authentic\s*website/i.test(rawBody), false);
  });
});

test('[LIVE] Live Integration Testing (Legitimate Domains & Safe Scenarios)', async (t) => {
  // 1. Live DNS resolution against google.com
  await t.test('[LIVE] 1. Live DNS query against google.com resolves genuine public A records', async () => {
    const dnsReport = await checkDnsIntel('google.com');
    assert.equal(dnsReport.status, 'success');
    assert.ok(Array.isArray(dnsReport.data.aRecords));
    assert.ok(dnsReport.data.aRecords.length > 0);
    assert.equal(dnsReport.data.ssrfBlocked, false);
  });

  // 2. Live RDAP lookup against google.com
  await t.test('[LIVE] 2. Live RDAP lookup against google.com retrieves authentic registration dates from public registry', async () => {
    const rdapReport = await checkRdapIntel('google.com');
    assert.equal(rdapReport.status, 'success');
    assert.ok(rdapReport.data.registrationDate !== null);
    assert.ok(rdapReport.data.ageDays > 365 * 10); // Over 10 years old
    assert.equal(rdapReport.data.isVeryNewDomain, false);
  });

  // 3. Live TLS handshake against google.com port 443
  await t.test('[LIVE] 3. Live TLS handshake against google.com port 443 validates genuine authorized certificate', async () => {
    const tlsReport = await checkTlsIntel('google.com');
    assert.equal(tlsReport.status, 'success');
    assert.equal(tlsReport.data.authorized, true);
    assert.ok(tlsReport.data.issuer.length > 0);
    assert.ok(tlsReport.data.daysRemaining > 0);
  });

  // 4. Live local heuristic evaluation (typosquatting detection without outbound network calls)
  await t.test('[LIVE] 4. Live local heuristic engine detects typosquatting (gooogle.com) without outbound network calls', async () => {
    const heuristic = scanUrl('https://www.gooogle.com');
    assert.ok(heuristic.riskScore >= 40);
    assert.ok(heuristic.indicators.some((i) => i.id === 'TYPOSQUATTING_BRAND_LOOKALIKE'));
  });

  // 5. Live SSRF protection against localhost and cloud metadata
  await t.test('[LIVE] 5. Live SSRF protection blocks loopback (127.0.0.1) and AWS metadata (169.254.169.254)', async () => {
    assert.equal(isSafeHostname('127.0.0.1'), false);
    assert.equal(isSafeHostname('localhost'), false);
    assert.equal(isSafeHostname('169.254.169.254'), false);
    assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
    assert.equal(isPrivateOrReservedIp('192.168.0.1'), true);
  });
});
