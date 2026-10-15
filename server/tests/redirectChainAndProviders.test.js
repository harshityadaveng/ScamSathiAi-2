import test from 'node:test';
import assert from 'node:assert/strict';
import { traceRedirectChain, setMockRedirectHandler } from '../src/services/redirectChainIntel.service.js';
import { checkUrlReputation, setMockReputationHandler } from '../src/services/reputation.service.js';
import {
  validateTraiSenderHeader,
  normalizePhoneNumber,
  analyzeSenderIntel,
  setMockPhoneHandler,
} from '../src/services/phoneIntel.service.js';

test('[SIMULATED] Redirect Chain Intelligence Suite', async (t) => {
  t.afterEach(() => {
    setMockRedirectHandler(null);
  });

  // 1. Single hop / direct destination without redirects
  await t.test('1. Direct target returns 1 hop and success status', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'success',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'No redirection; destination URL reached directly.',
      data: {
        initialUrl: 'https://example.com',
        finalUrl: 'https://example.com',
        hopCount: 1,
        hops: [{ url: 'https://example.com', statusCode: 200, location: null, ip: '93.184.216.34', isSecure: true }],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: false,
      },
    }));

    const result = await traceRedirectChain('https://example.com');
    assert.equal(result.status, 'success');
    assert.equal(result.data.hopCount, 1);
    assert.equal(result.data.hasCrossDomainRedirect, false);
  });

  // 2. Cross-domain redirect detection
  await t.test('2. Multi-hop redirection across different domains is flagged', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'success',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Followed 2 redirects safely. Terminal URL: legitimate-bank.com (Cross-domain redirection detected).',
      data: {
        initialUrl: 'http://bit.ly/mock-link',
        finalUrl: 'https://legitimate-bank.com/portal',
        hopCount: 3,
        hops: [
          { url: 'http://bit.ly/mock-link', statusCode: 301, location: 'https://tracker.net/go' },
          { url: 'https://tracker.net/go', statusCode: 302, location: 'https://legitimate-bank.com/portal' },
          { url: 'https://legitimate-bank.com/portal', statusCode: 200, location: null },
        ],
        hasCrossDomainRedirect: true,
        hasSuspiciousHop: false,
      },
    }));

    const result = await traceRedirectChain('http://bit.ly/mock-link');
    assert.equal(result.status, 'success');
    assert.equal(result.data.hopCount, 3);
    assert.equal(result.data.hasCrossDomainRedirect, true);
  });

  // 3. Redirect loop detection
  await t.test('3. Detects redirect loops without hanging', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'redirect_loop',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Redirect loop detected at hop 3.',
      data: {
        initialUrl: 'https://loop.example/a',
        finalUrl: 'https://loop.example/a',
        hopCount: 3,
        hops: [],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: true,
      },
    }));

    const result = await traceRedirectChain('https://loop.example/a');
    assert.equal(result.status, 'redirect_loop');
    assert.equal(result.data.hasSuspiciousHop, true);
  });

  // 4. SSRF block during redirect hop
  await t.test('4. Server blocks redirect attempt targeting internal IP or loopback', async () => {
    setMockRedirectHandler(() => ({
      name: 'redirect_chain',
      status: 'ssrf_blocked',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: 'Redirect hop blocked by SSRF policy: Resolved IP 127.0.0.1 is private or reserved',
      data: {
        initialUrl: 'http://evil-redirector.com/link',
        finalUrl: 'http://127.0.0.1/internal-status',
        hopCount: 2,
        hops: [{ url: 'http://127.0.0.1/internal-status', statusCode: 0, error: 'SSRF_BLOCKED' }],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: true,
      },
    }));

    const result = await traceRedirectChain('http://evil-redirector.com/link');
    assert.equal(result.status, 'ssrf_blocked');
    assert.equal(result.data.hasSuspiciousHop, true);
  });
});

test('[SIMULATED] VirusTotal Threat Intel Provider Suite', async (t) => {
  t.afterEach(() => {
    setMockReputationHandler(null);
  });

  // 1. VirusTotal flagged response
  await t.test('1. VirusTotal malicious detection produces confirmed_threat', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'virustotal',
      reputationStatus: 'confirmed_threat',
      status: 'flagged',
      verdict: 'malicious',
      threatCategory: 'VIRUSTOTAL_MALICIOUS_DETECTION',
      details: 'Flagged by 5 security vendor(s) on VirusTotal as malicious (suspicious: 1).',
      stats: { malicious: 5, suspicious: 1, harmless: 80 },
    }));

    const rep = await checkUrlReputation('https://malicious-virustotal-test.com');
    assert.equal(rep.reputationStatus, 'confirmed_threat');
    assert.equal(rep.verdict, 'malicious');
    assert.equal(rep.status, 'flagged');
    assert.ok(rep.stats.malicious >= 5);
  });

  // 2. VirusTotal clean lookup
  await t.test('2. VirusTotal clean lookup produces no_known_threat_detected', async () => {
    setMockReputationHandler(() => ({
      checked: true,
      provider: 'virustotal',
      reputationStatus: 'no_known_threat_detected',
      status: 'clean',
      verdict: 'no_threat_detected',
      threatCategory: null,
      details: 'No malicious detections reported across 85 security vendor lookups on VirusTotal.',
      stats: { malicious: 0, suspicious: 0, harmless: 85 },
    }));

    const rep = await checkUrlReputation('https://google.com');
    assert.equal(rep.reputationStatus, 'no_known_threat_detected');
    assert.equal(rep.verdict, 'no_threat_detected');
    assert.equal(rep.stats.malicious, 0);
  });
});

test('Phone & TRAI Sender Intelligence Suite', async (t) => {
  t.afterEach(() => {
    setMockPhoneHandler(null);
  });

  // 1. TRAI DLT Registered Header parsing
  await t.test('1. Valid TRAI DLT 6-alpha header format is correctly recognized', () => {
    const check1 = validateTraiSenderHeader('VK-HDFCBK');
    assert.equal(check1.isTraiHeader, true);
    assert.equal(check1.prefix, 'VK');
    assert.equal(check1.entityCode, 'HDFCBK');

    const check2 = validateTraiSenderHeader('AD-SBIINB');
    assert.equal(check2.isTraiHeader, true);
    assert.equal(check2.entityCode, 'SBIINB');

    const check3 = validateTraiSenderHeader('PAYTMB');
    assert.equal(check3.isTraiHeader, true);
    assert.equal(check3.entityCode, 'PAYTMB');
  });

  // 2. Non-TRAI format (personal string)
  await t.test('2. Random nicknames or irregular sender names are not marked as TRAI headers', () => {
    const invalid1 = validateTraiSenderHeader('JohnDoe');
    assert.equal(invalid1.isTraiHeader, false);

    const invalid2 = validateTraiSenderHeader('9876543210');
    assert.equal(invalid2.isTraiHeader, false);
  });

  // 3. Indian Phone number normalization
  await t.test('3. Indian mobile phone numbers are normalized to E.164 (+91)', () => {
    const res1 = normalizePhoneNumber('9876543210');
    assert.equal(res1.isValid, true);
    assert.equal(res1.normalized, '+919876543210');
    assert.equal(res1.isPersonalMobile, true);

    const res2 = normalizePhoneNumber('+91 98765 43210');
    assert.equal(res2.isValid, true);
    assert.equal(res2.normalized, '+919876543210');

    const res3 = normalizePhoneNumber('09876543210');
    assert.equal(res3.isValid, true);
    assert.equal(res3.normalized, '+919876543210');
  });

  // 4. Personal mobile number sending bank KYC alert is flagged as spoofing
  await t.test('4. Personal mobile number claiming to be bank alert triggers red flag spoofing', async () => {
    const analysis = await analyzeSenderIntel('9876543210', {
      hasBankingClaims: true,
      hasDisconnectionClaims: false,
    });

    assert.equal(analysis.checked, true);
    assert.equal(analysis.isSuspicious, true);
    assert.equal(analysis.reputationStatus, 'suspicious_sender');
    assert.ok(analysis.indicators.some((i) => i.id === 'PERSONAL_MOBILE_BANK_SPOOF'));
  });

  // 5. TRAI registered header sending bank alert is verified format
  await t.test('5. TRAI registered header sending bank alert is recognized as valid enterprise format', async () => {
    const analysis = await analyzeSenderIntel('VK-HDFCBK', {
      hasBankingClaims: true,
      hasDisconnectionClaims: false,
    });

    assert.equal(analysis.checked, true);
    assert.equal(analysis.isSuspicious, false);
    assert.equal(analysis.reputationStatus, 'verified_format');
  });
});
