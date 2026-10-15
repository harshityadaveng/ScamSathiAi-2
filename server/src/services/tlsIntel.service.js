import tls from 'node:tls';
import net from 'node:net';
import dns from 'node:dns/promises';
import { isSafeHostname, isPrivateOrReservedIp } from './ssrfProtection.service.js';

let mockTlsHandler = null;

/**
 * Injects a mock TLS handler for testing.
 * @param {Function|null} handler
 */
export function setMockTlsHandler(handler) {
  mockTlsHandler = handler;
}

/**
 * Safely inspects TLS certificate metadata on port 443 without downloading page content.
 * Enforces strict SSRF protection by resolving and checking the destination IP first.
 *
 * @param {string} hostname
 * @returns {Promise<object>} Structured TLS check report
 */
export async function checkTlsIntel(hostname) {
  if (mockTlsHandler) {
    return mockTlsHandler(hostname);
  }

  const timestamp = new Date().toISOString();

  // 1. SSRF hostname validation
  if (!isSafeHostname(hostname)) {
    return {
      name: 'tls_certificate',
      status: 'error',
      source: 'tls_handshake',
      timestamp,
      explanation: 'Target blocked by security policy (prohibited localhost or internal address).',
      data: null,
    };
  }

  // 2. Resolve IP and re-check for SSRF before opening socket
  let targetIp = null;
  try {
    if (net.isIP(hostname)) {
      targetIp = hostname;
    } else {
      let addresses = [];
      try {
        const lookupRes = await dns.lookup(hostname, { all: true });
        addresses = lookupRes.map((r) => r.address);
      } catch {
        addresses = await dns.resolve4(hostname).catch(() => []);
      }

      if (!addresses || addresses.length === 0) {
        return {
          name: 'tls_certificate',
          status: 'no_data',
          source: 'tls_handshake',
          timestamp,
          explanation: 'Could not resolve IP address for TLS handshake.',
          data: null,
        };
      }
      targetIp = addresses[0];
    }

    if (isPrivateOrReservedIp(targetIp)) {
      return {
        name: 'tls_certificate',
        status: 'error',
        source: 'tls_handshake',
        timestamp,
        explanation: 'Destination IP address is in a private or reserved range (SSRF blocked).',
        data: null,
      };
    }
  } catch (err) {
    return {
      name: 'tls_certificate',
      status: 'error',
      source: 'tls_handshake',
      timestamp,
      explanation: `Pre-connection IP resolution failed: ${err.message}`,
      data: null,
    };
  }

  // 3. Connect to port 443 with strict 2500ms timeout
  return new Promise((resolve) => {
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        if (socket) socket.destroy();
        resolve({
          name: 'tls_certificate',
          status: 'unavailable',
          source: 'tls_handshake',
          timestamp,
          explanation: 'TLS connection to port 443 timed out (server may not support HTTPS).',
          data: null,
        });
      }
    }, 4500);

    let socket;
    try {
      socket = tls.connect(
        {
          host: targetIp,
          servername: hostname,
          port: 443,
          rejectUnauthorized: false, // We inspect the cert metadata even if self-signed/untrusted
          timeout: 4500,
        },
        () => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timer);

          try {
            const cert = socket.getPeerCertificate(false);
            const authorized = socket.authorized;
            const authError = socket.authorizationError || null;
            socket.destroy();

            if (!cert || Object.keys(cert).length === 0) {
              return resolve({
                name: 'tls_certificate',
                status: 'no_data',
                source: 'tls_handshake',
                timestamp,
                explanation: 'TLS handshake succeeded, but server presented an empty peer certificate.',
                data: null,
              });
            }

            const validFrom = cert.valid_from;
            const validTo = cert.valid_to;
            const toDate = new Date(validTo).getTime();
            const daysRemaining = Math.floor((toDate - Date.now()) / (1000 * 60 * 60 * 24));
            const isExpired = daysRemaining < 0;

            const issuer = cert.issuer ? cert.issuer.O || cert.issuer.CN || 'Unknown Issuer' : 'Unknown Issuer';
            const subject = cert.subject ? cert.subject.CN || hostname : hostname;

            resolve({
              name: 'tls_certificate',
              status: 'success',
              source: 'tls_handshake',
              timestamp,
              explanation: `Certificate issued by "${issuer}". Valid for ${daysRemaining} more days.`,
              data: {
                authorized: authorized === true,
                authorizationError: authError,
                issuer,
                subject,
                validFrom,
                validTo,
                daysRemaining,
                isExpired,
                isSelfSigned: authError === 'DEPTH_ZERO_SELF_SIGNED_CERT',
              },
            });
          } catch (parseErr) {
            resolve({
              name: 'tls_certificate',
              status: 'error',
              source: 'tls_handshake',
              timestamp,
              explanation: `Failed to extract TLS certificate metadata: ${parseErr.message}`,
              data: null,
            });
          }
        }
      );

      socket.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve({
            name: 'tls_certificate',
            status: 'unavailable',
            source: 'tls_handshake',
            timestamp,
            explanation: `TLS handshake failed: ${err.message}`,
            data: null,
          });
        }
      });
    } catch (err) {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({
          name: 'tls_certificate',
          status: 'error',
          source: 'tls_handshake',
          timestamp,
          explanation: `TLS initialization error: ${err.message}`,
          data: null,
        });
      }
    }
  });
}
