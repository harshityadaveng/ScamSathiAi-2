import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import { isSafeHostname, isPrivateOrReservedIp } from './ssrfProtection.service.js';
import { redactSensitiveUrl } from './reputation.service.js';

let mockRedirectHandler = null;

/**
 * Injects a mock redirect handler for testing.
 * @param {Function|null} handler
 */
export function setMockRedirectHandler(handler) {
  mockRedirectHandler = handler;
}

const MAX_HOPS = 5;
const REQUEST_TIMEOUT_MS = 4000;

/**
 * Performs a single safe, metadata-only HTTP/HTTPS request without following redirects automatically.
 * Validates target IP address before connecting to prevent SSRF.
 *
 * @param {string} targetUrl
 * @param {string} method - 'HEAD' or 'GET'
 * @returns {Promise<{ statusCode: number, headers: object, resolvedIp: string }>}
 */
async function fetchSingleHop(targetUrl, method = 'HEAD') {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    throw new Error(`INVALID_URL: ${err.message}`);
  }

  // Scheme validation: strictly http or https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`UNSUPPORTED_SCHEME: ${parsed.protocol}`);
  }

  const hostname = parsed.hostname;

  // SSRF validation on hostname
  if (!isSafeHostname(hostname)) {
    const err = new Error(`SSRF_BLOCKED: Hostname ${hostname} is disallowed by security policy`);
    err.code = 'SSRF_BLOCKED';
    throw err;
  }

  // Pre-resolve hostname IP and validate against private ranges
  let resolvedIp = null;
  try {
    const lookupRes = await dns.lookup(hostname);
    resolvedIp = lookupRes.address;
    if (isPrivateOrReservedIp(resolvedIp)) {
      const err = new Error(`SSRF_BLOCKED: Resolved IP ${resolvedIp} is private or reserved`);
      err.code = 'SSRF_BLOCKED';
      throw err;
    }
  } catch (err) {
    if (err.code === 'SSRF_BLOCKED') throw err;
    // If DNS resolution fails, throw as DNS failure
    const dnsErr = new Error(`DNS_RESOLUTION_FAILED: ${err.message}`);
    dnsErr.code = 'ENOTFOUND';
    throw dnsErr;
  }

  const client = parsed.protocol === 'https:' ? https : http;
  const options = {
    method,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    headers: {
      'User-Agent': 'ScamSathiAI-SecurityScanner/2.0 (Security Intelligence Fetcher)',
      Accept: '*/*',
      Connection: 'close',
    },
    timeout: REQUEST_TIMEOUT_MS,
  };

  return new Promise((resolve, reject) => {
    let timedOut = false;
    const req = client.request(options, (res) => {
      // Consume minimal body to free socket
      res.resume();
      resolve({
        statusCode: res.statusCode || 0,
        headers: res.headers || {},
        resolvedIp,
      });
    });

    req.on('timeout', () => {
      timedOut = true;
      req.destroy();
      const err = new Error('FETCH_TIMEOUT');
      err.code = 'ETIMEDOUT';
      reject(err);
    });

    req.on('error', (err) => {
      if (!timedOut) reject(err);
    });

    req.end();
  });
}

/**
 * Traces server-side HTTP/HTTPS redirect chains safely hop-by-hop.
 * Validates SSRF on every hop, prevents redirect loops, and limits chain depth.
 *
 * @param {string} initialUrl
 * @returns {Promise<object>} Structured redirect chain report
 */
export async function traceRedirectChain(initialUrl) {
  if (mockRedirectHandler) {
    return mockRedirectHandler(initialUrl);
  }

  const timestamp = new Date().toISOString();
  const hops = [];
  const visitedUrls = new Set();
  let currentUrl = initialUrl;
  let status = 'success';
  let explanation = 'No redirection; destination URL reached directly.';

  try {
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      if (visitedUrls.has(currentUrl)) {
        status = 'redirect_loop';
        explanation = `Redirect loop detected at hop ${hop + 1} (${currentUrl}).`;
        break;
      }
      visitedUrls.add(currentUrl);

      let hopRes;
      try {
        hopRes = await fetchSingleHop(currentUrl, 'HEAD');
        // If server rejects HEAD with 405 Method Not Allowed, try GET with instant abort
        if (hopRes.statusCode === 405) {
          hopRes = await fetchSingleHop(currentUrl, 'GET');
        }
      } catch (err) {
        if (err.code === 'SSRF_BLOCKED') {
          hops.push({
            url: currentUrl,
            statusCode: 0,
            location: null,
            ip: null,
            error: err.message,
          });
          return {
            name: 'redirect_chain',
            status: 'ssrf_blocked',
            source: 'redirect_fetcher',
            timestamp,
            explanation: `Redirect hop blocked by SSRF policy: ${err.message}`,
            data: {
              initialUrl,
              finalUrl: currentUrl,
              hopCount: hops.length,
              hops,
              hasCrossDomainRedirect: false,
              hasSuspiciousHop: true,
            },
          };
        }
        // Network or DNS error on hop
        hops.push({
          url: currentUrl,
          statusCode: 0,
          location: null,
          ip: null,
          error: err.message,
        });
        return {
          name: 'redirect_chain',
          status: 'error',
          source: 'redirect_fetcher',
          timestamp,
          explanation: `Failed to inspect URL at hop ${hop + 1}: ${err.message}`,
          data: {
            initialUrl,
            finalUrl: currentUrl,
            hopCount: hops.length,
            hops,
            hasCrossDomainRedirect: false,
            hasSuspiciousHop: false,
          },
        };
      }

      const isRedirect = [301, 302, 303, 307, 308].includes(hopRes.statusCode);
      const location = hopRes.headers.location || null;

      hops.push({
        url: currentUrl,
        safeUrl: redactSensitiveUrl(currentUrl),
        statusCode: hopRes.statusCode,
        location,
        ip: hopRes.resolvedIp,
        isSecure: currentUrl.startsWith('https://'),
      });

      if (!isRedirect || !location) {
        // Reached terminal destination
        break;
      }

      // Resolve relative redirect locations
      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).href;
      } catch {
        status = 'invalid_location';
        explanation = `Invalid redirect location header received: ${location}`;
        break;
      }

      currentUrl = nextUrl;

      if (hop === MAX_HOPS - 1) {
        status = 'max_hops_exceeded';
        explanation = `Redirect chain exceeded safe limit of ${MAX_HOPS} hops.`;
      }
    }

    const initialHost = new URL(initialUrl).hostname.toLowerCase();
    const finalUrl = hops.length > 0 ? hops[hops.length - 1].url : initialUrl;
    const finalHost = hops.length > 0 ? new URL(finalUrl).hostname.toLowerCase() : initialHost;
    const hasCrossDomainRedirect = initialHost !== finalHost;

    if (hops.length > 1) {
      explanation = `Followed ${hops.length - 1} redirect(s) safely. Terminal URL: ${finalHost}${hasCrossDomainRedirect ? ' (Cross-domain redirection detected)' : ''}.`;
    }

    const stopReason =
      status === 'ssrf_blocked'
        ? 'Redirect hop blocked by SSRF security policy.'
        : status === 'max_hops_exceeded'
        ? `Exceeded safe limit of ${MAX_HOPS} redirect hops.`
        : status === 'redirect_loop'
        ? 'Redirect loop detected.'
        : status === 'invalid_location'
        ? 'Invalid Location header encountered.'
        : 'Terminal destination reached.';

    return {
      name: 'redirect_chain',
      status,
      source: 'redirect_fetcher',
      timestamp,
      explanation,
      data: {
        initialUrl,
        initialUrlSafe: redactSensitiveUrl(initialUrl),
        finalUrl,
        finalUrlSafe: redactSensitiveUrl(finalUrl),
        initialHostname: initialHost,
        finalHostname: finalHost,
        hopCount: hops.length,
        hops,
        hasCrossDomainRedirect,
        hasSuspiciousHop: status === 'ssrf_blocked' || status === 'redirect_loop' || status === 'max_hops_exceeded',
        stopReason,
      },
    };
  } catch (outerErr) {
    return {
      name: 'redirect_chain',
      status: 'error',
      source: 'redirect_fetcher',
      timestamp,
      explanation: `Redirect evaluation failed: ${outerErr.message}`,
      data: {
        initialUrl,
        finalUrl: initialUrl,
        hopCount: hops.length,
        hops,
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: false,
      },
    };
  }
}
