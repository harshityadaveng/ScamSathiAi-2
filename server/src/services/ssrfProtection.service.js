import net from 'node:net';

/**
 * SSRF Protection Utility
 * Validates hostnames and IP addresses to prevent Server-Side Request Forgery (SSRF).
 * Blocks loopback, private RFC1918, link-local, multicast, and cloud metadata addresses.
 */

// Banned hostnames
const BANNED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

/**
 * Checks if a hostname or domain name targets localhost, internal, or metadata services.
 * @param {string} hostname
 * @returns {boolean} True if safe, false if blocked
 */
export function isSafeHostname(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const lower = hostname.toLowerCase().trim();

  if (BANNED_HOSTNAMES.has(lower)) return false;
  if (lower.endsWith('.localhost') || lower.endsWith('.local') || lower.endsWith('.internal') || lower.endsWith('.arpa')) {
    return false;
  }

  // Check if hostname is an IP string directly
  if (net.isIP(lower)) {
    return !isPrivateOrReservedIp(lower);
  }

  return true;
}

/**
 * Checks if an IP address falls within private, loopback, link-local, or reserved ranges.
 * @param {string} ip
 * @returns {boolean} True if private/reserved/blocked, false if public
 */
export function isPrivateOrReservedIp(ip) {
  if (!ip || !net.isIP(ip)) return true; // Invalid IP is treated as unsafe

  // IPv4 checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
      return true;
    }

    const [a, b, c, d] = parts;

    // 0.0.0.0/8 (Current network)
    if (a === 0) return true;

    // 10.0.0.0/8 (Private network RFC 1918)
    if (a === 10) return true;

    // 100.64.0.0/10 (Shared address space RFC 6598)
    if (a === 100 && b >= 64 && b <= 127) return true;

    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;

    // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Cloud Metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;

    // 172.16.0.0/12 (Private network RFC 1918: 172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;

    // 192.0.0.0/24 & 192.0.2.0/24 (IETF protocol assignments & TEST-NET-1)
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;

    // 192.168.0.0/16 (Private network RFC 1918)
    if (a === 192 && b === 168) return true;

    // 198.18.0.0/15 (Benchmarking)
    if (a === 198 && (b === 18 || b === 19)) return true;

    // 198.51.100.0/24 (TEST-NET-2)
    if (a === 198 && b === 51 && c === 100) return true;

    // 203.0.113.0/24 (TEST-NET-3)
    if (a === 203 && b === 0 && c === 113) return true;

    // 224.0.0.0/4 (Multicast)
    if (a >= 224 && a <= 239) return true;

    // 240.0.0.0/4 (Reserved for future use) & 255.255.255.255 (Broadcast)
    if (a >= 240) return true;

    return false;
  }

  // IPv6 checks
  if (net.isIPv6(ip)) {
    const norm = ip.toLowerCase();
    // ::1 (Loopback)
    if (norm === '::1' || norm === '0:0:0:0:0:0:0:1') return true;
    // :: (Unspecified)
    if (norm === '::' || norm === '0:0:0:0:0:0:0:0') return true;
    // fc00::/7 (Unique local address)
    if (norm.startsWith('fc') || norm.startsWith('fd')) return true;
    // fe80::/10 (Link-local unicast)
    if (norm.startsWith('fe8') || norm.startsWith('fe9') || norm.startsWith('fea') || norm.startsWith('feb')) return true;
    // ::ffff:0:0/96 (IPv4-mapped IPv6)
    if (norm.includes('::ffff:')) {
      const v4Part = norm.split('::ffff:')[1];
      if (v4Part && net.isIPv4(v4Part)) {
        return isPrivateOrReservedIp(v4Part);
      }
      return true;
    }
    return false;
  }

  return true;
}
