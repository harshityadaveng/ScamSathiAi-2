import { env } from '../config/env.js';

let mockReputationHandler = null;

/**
 * Allows injecting a mock reputation handler for unit tests.
 * Pass null to restore real implementation.
 */
export function setMockReputationHandler(handler) {
  mockReputationHandler = handler;
}

/**
 * Redacts sensitive query parameters from a URL for safe logging and reporting.
 * @param {string} rawUrl
 * @returns {string} Redacted URL
 */
export function redactSensitiveUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const parsed = new URL(rawUrl);
    const SENSITIVE_KEYS = new Set([
      'token', 'key', 'apikey', 'api_key', 'secret', 'password', 'pass', 'auth',
      'otp', 'pin', 'cvv', 'card', 'session', 'sessionid', 'session_id', 'access_token',
      'authorization', 'account', 'pwd'
    ]);
    for (const [key] of parsed.searchParams.entries()) {
      const lower = key.toLowerCase();
      if (
        SENSITIVE_KEYS.has(lower) ||
        lower.includes('token') ||
        lower.includes('secret') ||
        lower.includes('password')
      ) {
        parsed.searchParams.set(key, '[REDACTED]');
      }
    }
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Builds a standardized reputation report adhering to the common adapter contract.
 */
function buildAdapterResult({
  provider,
  configured,
  requestSucceeded,
  lookupStatus,
  matchedThreatTypes = [],
  errorCode = null,
  reputationStatus,
  status,
  verdict = null,
  threatCategory = null,
  details,
  stats = null,
}) {
  const checkedAt = new Date().toISOString();
  return {
    provider,
    configured,
    requestSucceeded,
    lookupStatus,
    matchedThreatTypes,
    checkedAt,
    errorCode,
    // Backwards-compatible fields for pipeline and UI
    checked: requestSucceeded && lookupStatus !== 'NOT_CONFIGURED' && lookupStatus !== 'UNAVAILABLE',
    reputationStatus,
    status,
    verdict,
    threatCategory,
    details,
    stats,
    timestamp: checkedAt,
  };
}

/**
 * Checks a normalized URL against external threat intelligence using a pluggable adapter.
 * Supports:
 * - google_web_risk (Google Web Risk Lookup API) [Preferred]
 * - google_safe_browsing (Google Safe Browsing v4)
 * - virustotal (VirusTotal v3)
 *
 * Requirements:
 * - Never visits arbitrary target URLs or downloads scripts.
 * - Read credentials only from server-side environment variables.
 * - Handles timeouts, rate limits (429), auth failures (401/403), malformed responses.
 * - Distinguishes THREAT_FOUND, NO_MATCH_FOUND, UNAVAILABLE, and NOT_CONFIGURED.
 * - A clean lookup does NOT guarantee website legitimacy.
 * - Outages or unconfigured providers NEVER yield a clean verdict.
 *
 * @param {string} normalizedUrl - Clean HTTP/HTTPS URL
 * @returns {Promise<object>} Standardized provider adapter result
 */
export async function checkUrlReputation(normalizedUrl) {
  if (mockReputationHandler) {
    const mockRes = await mockReputationHandler(normalizedUrl);
    const repStatus =
      mockRes.reputationStatus ||
      (mockRes.status === 'flagged' || mockRes.verdict === 'malicious' || mockRes.lookupStatus === 'THREAT_FOUND'
        ? 'confirmed_threat'
        : mockRes.status === 'clean' || mockRes.verdict === 'no_threat_detected' || mockRes.lookupStatus === 'NO_MATCH_FOUND'
        ? 'no_known_threat_detected'
        : mockRes.status === 'not_configured' || mockRes.lookupStatus === 'NOT_CONFIGURED'
        ? 'not_configured'
        : 'unavailable');

    const lookupStatus =
      mockRes.lookupStatus ||
      (repStatus === 'confirmed_threat'
        ? 'THREAT_FOUND'
        : repStatus === 'no_known_threat_detected'
        ? 'NO_MATCH_FOUND'
        : repStatus === 'not_configured'
        ? 'NOT_CONFIGURED'
        : 'UNAVAILABLE');

    const matchedThreats =
      mockRes.matchedThreatTypes ||
      (mockRes.threatCategory ? [mockRes.threatCategory] : []);

    return buildAdapterResult({
      provider: mockRes.provider || 'mock_provider',
      configured: mockRes.configured ?? (repStatus !== 'not_configured'),
      requestSucceeded: mockRes.requestSucceeded ?? (repStatus === 'confirmed_threat' || repStatus === 'no_known_threat_detected'),
      lookupStatus,
      matchedThreatTypes: matchedThreats,
      errorCode: mockRes.errorCode || null,
      reputationStatus: repStatus,
      status: mockRes.status || (repStatus === 'confirmed_threat' ? 'flagged' : repStatus === 'no_known_threat_detected' ? 'clean' : repStatus),
      verdict: mockRes.verdict || (repStatus === 'confirmed_threat' ? 'malicious' : repStatus === 'no_known_threat_detected' ? 'no_threat_detected' : null),
      threatCategory: mockRes.threatCategory || (matchedThreats[0] || null),
      details: mockRes.details || 'Mock reputation response.',
      stats: mockRes.stats || null,
    });
  }

  const provider = env.URL_REPUTATION_PROVIDER;

  // 1. Provider not configured or set to 'none'
  if (!provider || provider === 'none') {
    return buildAdapterResult({
      provider: null,
      configured: false,
      requestSucceeded: false,
      lookupStatus: 'NOT_CONFIGURED',
      reputationStatus: 'not_configured',
      status: 'not_configured',
      details: 'External reputation verification is not configured on this server.',
    });
  }

  // 2. Google Web Risk Lookup API
  if (provider === 'google_web_risk' || provider === 'webrisk') {
    const apiKey = env.GOOGLE_WEB_RISK_API_KEY;
    if (!apiKey || apiKey.trim() === '') {
      return buildAdapterResult({
        provider: 'google_web_risk',
        configured: false,
        requestSucceeded: false,
        lookupStatus: 'NOT_CONFIGURED',
        reputationStatus: 'not_configured',
        status: 'not_configured',
        details: 'Google Web Risk API key is not configured in server environment.',
      });
    }

    try {
      const controller = new AbortController();
      const timeoutMs = env.WEB_RISK_TIMEOUT_MS || 5000;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      // Google Web Risk Lookup API v1: uris.search endpoint
      const threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'];
      const queryParams = new URLSearchParams();
      for (const t of threatTypes) queryParams.append('threatTypes', t);
      queryParams.set('uri', normalizedUrl);
      queryParams.set('key', apiKey.trim());

      const endpoint = `https://webrisk.googleapis.com/v1/uris:search?${queryParams.toString()}`;

      const response = await fetch(endpoint, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 401 || response.status === 403) {
        console.warn(`[ReputationService] Google Web Risk authorization error: HTTP ${response.status}`);
        return buildAdapterResult({
          provider: 'google_web_risk',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'AUTH_ERROR',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: 'Google Web Risk API key is invalid or unauthorized.',
        });
      }

      if (response.status === 429) {
        console.warn('[ReputationService] Google Web Risk rate limit exceeded (HTTP 429)');
        return buildAdapterResult({
          provider: 'google_web_risk',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'RATE_LIMITED',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: 'Google Web Risk request quota or rate limit exceeded.',
        });
      }

      if (!response.ok) {
        console.warn(`[ReputationService] Google Web Risk returned HTTP ${response.status}`);
        return buildAdapterResult({
          provider: 'google_web_risk',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'SERVICE_ERROR',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: `Google Web Risk service returned an error (HTTP ${response.status}).`,
        });
      }

      let data;
      try {
        data = await response.json();
      } catch {
        return buildAdapterResult({
          provider: 'google_web_risk',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'MALFORMED_RESPONSE',
          reputationStatus: 'unavailable',
          status: 'error',
          details: 'Google Web Risk returned an unparseable response.',
        });
      }

      // Check if threat was detected
      if (data && data.threat && Array.isArray(data.threat.threatTypes) && data.threat.threatTypes.length > 0) {
        const detectedThreats = data.threat.threatTypes;
        const primaryThreat = detectedThreats[0];
        return buildAdapterResult({
          provider: 'google_web_risk',
          configured: true,
          requestSucceeded: true,
          lookupStatus: 'THREAT_FOUND',
          matchedThreatTypes: detectedThreats,
          reputationStatus: 'confirmed_threat',
          status: 'flagged',
          verdict: 'malicious',
          threatCategory: primaryThreat,
          details: `Flagged on Google Web Risk threat database as ${detectedThreats.join(', ')}.`,
        });
      }

      // No match found (clean blocklist)
      return buildAdapterResult({
        provider: 'google_web_risk',
        configured: true,
        requestSucceeded: true,
        lookupStatus: 'NO_MATCH_FOUND',
        matchedThreatTypes: [],
        reputationStatus: 'no_known_threat_detected',
        status: 'clean',
        verdict: 'no_threat_detected',
        threatCategory: null,
        details: 'No known threats detected by Google Web Risk. (Note: Clean blocklist does not guarantee website legitimacy).',
      });
    } catch (err) {
      const isTimeout = err.name === 'AbortError';
      console.warn(`[ReputationService] Google Web Risk request failed: ${isTimeout ? 'Timeout' : err.message}`);
      return buildAdapterResult({
        provider: 'google_web_risk',
        configured: true,
        requestSucceeded: false,
        lookupStatus: 'UNAVAILABLE',
        errorCode: isTimeout ? 'TIMEOUT' : 'SERVICE_ERROR',
        reputationStatus: 'unavailable',
        status: 'unavailable',
        details: isTimeout
          ? 'Google Web Risk threat intelligence request timed out.'
          : 'Failed to communicate with Google Web Risk API.',
      });
    }
  }

  // 3. Google Safe Browsing v4 Lookup
  if (provider === 'google_safe_browsing' || provider === 'safebrowsing') {
    const apiKey = env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey || apiKey.trim() === '') {
      return buildAdapterResult({
        provider: 'google_safe_browsing',
        configured: false,
        requestSucceeded: false,
        lookupStatus: 'NOT_CONFIGURED',
        reputationStatus: 'not_configured',
        status: 'not_configured',
        details: 'Google Safe Browsing API key is not configured in server environment.',
      });
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), env.SAFE_BROWSING_TIMEOUT_MS);

      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey.trim())}`;
      const requestBody = {
        client: {
          clientId: 'scamsathi-ai',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: normalizedUrl }],
        },
      };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        console.warn(`[ReputationService] Google Safe Browsing returned HTTP ${response.status}`);
        const isAuthError = response.status === 401 || response.status === 403;
        const isRateLimit = response.status === 429;
        return buildAdapterResult({
          provider: 'google_safe_browsing',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: isAuthError ? 'AUTH_ERROR' : isRateLimit ? 'RATE_LIMITED' : 'SERVICE_ERROR',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: isAuthError
            ? 'Google Safe Browsing API key is invalid or unauthorized.'
            : isRateLimit
            ? 'Google Safe Browsing rate limit exceeded.'
            : `Threat intelligence provider responded with error (HTTP ${response.status}).`,
        });
      }

      let data;
      try {
        data = await response.json();
      } catch {
        return buildAdapterResult({
          provider: 'google_safe_browsing',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'MALFORMED_RESPONSE',
          reputationStatus: 'unavailable',
          status: 'error',
          details: 'Threat intelligence provider returned invalid or unparseable response.',
        });
      }

      // Check if matches were found
      if (Array.isArray(data.matches) && data.matches.length > 0) {
        const threatTypes = Array.from(new Set(data.matches.map((m) => m.threatType || 'MALICIOUS_ACTIVITY')));
        const primaryThreat = threatTypes[0];
        return buildAdapterResult({
          provider: 'google_safe_browsing',
          configured: true,
          requestSucceeded: true,
          lookupStatus: 'THREAT_FOUND',
          matchedThreatTypes: threatTypes,
          reputationStatus: 'confirmed_threat',
          status: 'flagged',
          verdict: 'malicious',
          threatCategory: primaryThreat,
          details: `Flagged on Google Safe Browsing threat database as ${threatTypes.join(', ')}.`,
        });
      }

      // No matches found (clean blocklist)
      return buildAdapterResult({
        provider: 'google_safe_browsing',
        configured: true,
        requestSucceeded: true,
        lookupStatus: 'NO_MATCH_FOUND',
        matchedThreatTypes: [],
        reputationStatus: 'no_known_threat_detected',
        status: 'clean',
        verdict: 'no_threat_detected',
        threatCategory: null,
        details: 'No known threats detected by Google Safe Browsing blocklist. (Note: Clean blocklist does not guarantee website legitimacy).',
      });
    } catch (err) {
      const isTimeout = err.name === 'AbortError';
      console.warn(`[ReputationService] Google Safe Browsing failed: ${isTimeout ? 'Timeout' : err.message}`);
      return buildAdapterResult({
        provider: 'google_safe_browsing',
        configured: true,
        requestSucceeded: false,
        lookupStatus: 'UNAVAILABLE',
        errorCode: isTimeout ? 'TIMEOUT' : 'SERVICE_ERROR',
        reputationStatus: 'unavailable',
        status: 'unavailable',
        details: isTimeout
          ? 'Threat intelligence request timed out.'
          : 'Failed to communicate with threat intelligence provider.',
      });
    }
  }

  // 4. VirusTotal v3 URL Lookup
  if (provider === 'virustotal') {
    const apiKey = env.VIRUSTOTAL_API_KEY;

    if (!apiKey || apiKey.trim() === '') {
      return buildAdapterResult({
        provider: 'virustotal',
        configured: false,
        requestSucceeded: false,
        lookupStatus: 'NOT_CONFIGURED',
        reputationStatus: 'not_configured',
        status: 'not_configured',
        details: 'VirusTotal API key is not configured in server environment.',
      });
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), env.VIRUSTOTAL_TIMEOUT_MS || 5000);

      const urlId = Buffer.from(normalizedUrl).toString('base64url');
      const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey.trim(),
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 404) {
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: true,
          lookupStatus: 'NO_MATCH_FOUND',
          matchedThreatTypes: [],
          reputationStatus: 'no_known_threat_detected',
          status: 'clean',
          verdict: 'no_threat_detected',
          threatCategory: null,
          details: 'No existing scan records found on VirusTotal. (Unscanned domains are not guaranteed legitimate).',
        });
      }

      if (response.status === 401 || response.status === 403) {
        console.warn(`[ReputationService] VirusTotal authentication/quota failure: HTTP ${response.status}`);
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'AUTH_ERROR',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: 'VirusTotal API key is invalid or unauthorized.',
        });
      }

      if (response.status === 429) {
        console.warn('[ReputationService] VirusTotal rate limit exceeded (HTTP 429)');
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'RATE_LIMITED',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: 'VirusTotal request quota or rate limit exceeded.',
        });
      }

      if (!response.ok) {
        console.warn(`[ReputationService] VirusTotal returned HTTP ${response.status}`);
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'SERVICE_ERROR',
          reputationStatus: 'unavailable',
          status: 'unavailable',
          details: `Threat intelligence provider responded with error (HTTP ${response.status}).`,
        });
      }

      let json;
      try {
        json = await response.json();
      } catch {
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: false,
          lookupStatus: 'UNAVAILABLE',
          errorCode: 'MALFORMED_RESPONSE',
          reputationStatus: 'unavailable',
          status: 'error',
          details: 'Threat intelligence provider returned invalid or unparseable response.',
        });
      }

      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = (stats.harmless || 0) + (stats.undetected || 0);

      if (malicious > 0 || suspicious >= 2) {
        return buildAdapterResult({
          provider: 'virustotal',
          configured: true,
          requestSucceeded: true,
          lookupStatus: 'THREAT_FOUND',
          matchedThreatTypes: ['VIRUSTOTAL_MALICIOUS_DETECTION'],
          reputationStatus: 'confirmed_threat',
          status: 'flagged',
          verdict: 'malicious',
          threatCategory: 'VIRUSTOTAL_MALICIOUS_DETECTION',
          details: `Flagged by ${malicious} security vendor(s) on VirusTotal as malicious (suspicious: ${suspicious}).`,
          stats: { malicious, suspicious, harmless },
        });
      }

      return buildAdapterResult({
        provider: 'virustotal',
        configured: true,
        requestSucceeded: true,
        lookupStatus: 'NO_MATCH_FOUND',
        matchedThreatTypes: [],
        reputationStatus: 'no_known_threat_detected',
        status: 'clean',
        verdict: 'no_threat_detected',
        threatCategory: null,
        details: `No malicious detections reported across ${harmless} security vendor lookups on VirusTotal.`,
        stats: { malicious, suspicious, harmless },
      });
    } catch (err) {
      const isTimeout = err.name === 'AbortError';
      console.warn(`[ReputationService] VirusTotal failed: ${isTimeout ? 'Timeout' : err.message}`);
      return buildAdapterResult({
        provider: 'virustotal',
        configured: true,
        requestSucceeded: false,
        lookupStatus: 'UNAVAILABLE',
        errorCode: isTimeout ? 'TIMEOUT' : 'SERVICE_ERROR',
        reputationStatus: 'unavailable',
        status: 'unavailable',
        details: isTimeout
          ? 'VirusTotal threat intelligence request timed out.'
          : 'Failed to communicate with VirusTotal API.',
      });
    }
  }

  // Unsupported or other provider
  return buildAdapterResult({
    provider,
    configured: false,
    requestSucceeded: false,
    lookupStatus: 'NOT_CONFIGURED',
    reputationStatus: 'not_configured',
    status: 'not_configured',
    details: `Reputation provider "${provider}" is not recognized or initialized.`,
  });
}
