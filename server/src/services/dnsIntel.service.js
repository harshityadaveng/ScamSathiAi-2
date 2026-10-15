import dnsSync from 'node:dns';
import dns from 'node:dns/promises';
import { isSafeHostname, isPrivateOrReservedIp } from './ssrfProtection.service.js';

// Ensure public resolvers are configured for reliable resolution across environments
try {
  dnsSync.setServers(['8.8.8.8', '1.1.1.1']);
} catch {
  // fallback
}

let mockDnsHandler = null;

/**
 * Injects a mock DNS handler for testing.
 * @param {Function|null} handler
 */
export function setMockDnsHandler(handler) {
  mockDnsHandler = handler;
}

/**
 * Safely resolves DNS records (A, AAAA, MX, NS) for a given hostname.
 * Applies SSRF filters to resolved IP addresses.
 *
 * @param {string} hostname
 * @returns {Promise<object>} Structured DNS check report
 */
export async function checkDnsIntel(hostname) {
  if (mockDnsHandler) {
    return mockDnsHandler(hostname);
  }

  const timestamp = new Date().toISOString();

  // 1. Validate hostname syntax and SSRF blacklist
  if (!isSafeHostname(hostname)) {
    return {
      name: 'dns_resolution',
      status: 'error',
      source: 'dns_resolver',
      timestamp,
      explanation: 'Hostname blocked by security policy (prohibited localhost or internal address).',
      data: {
        aRecords: [],
        aaaaRecords: [],
        mxRecords: [],
        nsRecords: [],
        resolvedIps: [],
        hasA: false,
        hasMx: false,
        ssrfBlocked: true,
      },
    };
  }

  try {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('DNS_TIMEOUT')), 8000)
    );

    // Helper to query DNS with per-query timeout and OS lookup fallback
    const queryWithTimeout = (promise, ms = 3000) =>
      Promise.race([
        promise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('QUERY_TIMEOUT')), ms)),
      ]);

    const queryWithFallback = async (queryFn, lookupType) => {
      try {
        return await queryWithTimeout(queryFn(), 3500);
      } catch (err) {
        // Fallback to OS resolver getaddrinfo for A/AAAA records
        if (lookupType === 'A' || lookupType === 'AAAA') {
          try {
            const addresses = await dns.lookup(hostname, { all: true });
            if (lookupType === 'A') {
              return addresses.filter((a) => a.family === 4).map((a) => a.address);
            } else {
              return addresses.filter((a) => a.family === 6).map((a) => a.address);
            }
          } catch {
            return [];
          }
        }
        return [];
      }
    };

    const queriesPromise = Promise.allSettled([
      queryWithFallback(() => dns.resolve4(hostname), 'A'),
      queryWithFallback(() => dns.resolve6(hostname), 'AAAA'),
      queryWithFallback(() => dns.resolveMx(hostname), 'MX'),
      queryWithFallback(() => dns.resolveNs(hostname), 'NS'),
    ]);

    const results = await Promise.race([queriesPromise, timeoutPromise]);

    const aRecords = results[0].status === 'fulfilled' ? results[0].value : [];
    const aaaaRecords = results[1].status === 'fulfilled' ? results[1].value : [];
    const mxRecords = results[2].status === 'fulfilled' ? results[2].value : [];
    const nsRecords = results[3].status === 'fulfilled' ? results[3].value : [];

    const allIps = [...aRecords, ...aaaaRecords];

    // SSRF validation on resolved IPs:
    const hasPrivateIp = allIps.some((ip) => isPrivateOrReservedIp(ip));
    if (hasPrivateIp) {
      return {
        name: 'dns_resolution',
        status: 'error',
        source: 'dns_resolver',
        timestamp,
        explanation: 'Domain resolved to private or reserved IP address (SSRF blocked).',
        data: {
          aRecords: [],
          aaaaRecords: [],
          mxRecords: [],
          nsRecords: [],
          resolvedIps: [],
          hasA: false,
          hasMx: false,
          ssrfBlocked: true,
        },
      };
    }

    const hasA = aRecords.length > 0;
    const hasMx = mxRecords.length > 0;
    const hasAnyRecords = allIps.length > 0 || nsRecords.length > 0 || mxRecords.length > 0;

    return {
      name: 'dns_resolution',
      status: hasAnyRecords ? 'success' : 'no_data',
      source: 'dns_resolver',
      timestamp,
      explanation: hasAnyRecords
        ? `Resolved ${aRecords.length} A records, ${mxRecords.length} MX records, ${nsRecords.length} NS records.`
        : 'No public DNS records found for this hostname.',
      data: {
        aRecords,
        aaaaRecords,
        mxRecords: mxRecords.map((m) => ({ exchange: m.exchange, priority: m.priority })),
        nsRecords,
        resolvedIps: allIps,
        hasA,
        hasMx,
        ssrfBlocked: false,
      },
    };
  } catch (err) {
    const isTimeout = err.message === 'DNS_TIMEOUT';
    return {
      name: 'dns_resolution',
      status: isTimeout ? 'unavailable' : 'error',
      source: 'dns_resolver',
      timestamp,
      explanation: isTimeout ? 'DNS resolution query timed out.' : `DNS resolution failed: ${err.message}`,
      data: {
        aRecords: [],
        aaaaRecords: [],
        mxRecords: [],
        nsRecords: [],
        resolvedIps: [],
        hasA: false,
        hasMx: false,
        ssrfBlocked: false,
      },
    };
  }
}
