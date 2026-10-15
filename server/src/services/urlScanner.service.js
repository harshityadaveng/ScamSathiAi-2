import { redactSensitiveUrl } from './reputation.service.js';

/**
 * URL Scanner Service
 * Performs static structural, lexical, brand-lookalike, homoglyph, and typosquatting heuristics on URLs.
 * Never executes scripts, scrapes target pages, or follows external redirects.
 */

// Known URL shortener hostnames (signal, not proof alone)
const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'bl.ink', 'tiny.cc',
  'rebrand.ly', 'v.gd', 'clck.ru', 's.id', 'trib.al'
]);

// High-abuse TLDs frequently observed in phishing and disposable domains
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'vip',
  'fit', 'work', 'click', 'download', 'bid', 'link', 'country',
  'buzz', 'rest', 'surf', 'live', 'club', 'online', 'site', 'cam', 'quest'
]);

// Suspicious direct executable or installer downloads
const MALICIOUS_EXTENSIONS = /\.(apk|exe|bat|scr|vbs|iso|cmd|msi|ps1|jar|hta)$/i;

// Protected brands with brand keywords and verified official domains
export const PROTECTED_BRANDS = [
  {
    name: 'State Bank of India (SBI)',
    keywords: ['sbi', 'onlinesbi', 'yonosbi'],
    officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank'],
  },
  {
    name: 'HDFC Bank',
    keywords: ['hdfc', 'hdfcbank'],
    officialDomains: ['hdfcbank.com', 'hdfc.com'],
  },
  {
    name: 'ICICI Bank',
    keywords: ['icici', 'icicibank'],
    officialDomains: ['icicibank.com', 'icici.com'],
  },
  {
    name: 'Axis Bank',
    keywords: ['axis', 'axisbank'],
    officialDomains: ['axisbank.com'],
  },
  {
    name: 'Kotak Mahindra Bank',
    keywords: ['kotak', 'kotakbank'],
    officialDomains: ['kotak.com', 'kotakbank.com'],
  },
  {
    name: 'Punjab National Bank (PNB)',
    keywords: ['pnb', 'pnbindia'],
    officialDomains: ['pnbindia.in'],
  },
  {
    name: 'Bank of Baroda',
    keywords: ['bankofbaroda', 'bobworld'],
    officialDomains: ['bankofbaroda.in'],
  },
  {
    name: 'Canara Bank',
    keywords: ['canara', 'canarabank'],
    officialDomains: ['canarabank.com'],
  },
  {
    name: 'IndusInd Bank',
    keywords: ['indusind', 'indusindbank'],
    officialDomains: ['indusind.com'],
  },
  {
    name: 'Union Bank of India',
    keywords: ['unionbank', 'unionbankofindia'],
    officialDomains: ['unionbankofindia.co.in'],
  },
  {
    name: 'Paytm',
    keywords: ['paytm'],
    officialDomains: ['paytm.com', 'paytmbank.com'],
  },
  {
    name: 'PhonePe',
    keywords: ['phonepe'],
    officialDomains: ['phonepe.com'],
  },
  {
    name: 'Google & Google Pay',
    keywords: ['google', 'gmail', 'gpay', 'googlepay'],
    officialDomains: ['google.com', 'google.co.in', 'gmail.com', 'pay.google.com'],
  },
  {
    name: 'Amazon India & Global',
    keywords: ['amazon'],
    officialDomains: ['amazon.in', 'amazon.com'],
  },
  {
    name: 'Flipkart',
    keywords: ['flipkart'],
    officialDomains: ['flipkart.com'],
  },
  {
    name: 'Meesho',
    keywords: ['meesho'],
    officialDomains: ['meesho.com'],
  },
  {
    name: 'India Post / Speed Post',
    keywords: ['indiapost', 'speedpost'],
    officialDomains: ['indiapost.gov.in', 'postoffices.gov.in'],
  },
  {
    name: 'Blue Dart Express',
    keywords: ['bluedart'],
    officialDomains: ['bluedart.com'],
  },
  {
    name: 'Delhivery',
    keywords: ['delhivery'],
    officialDomains: ['delhivery.com'],
  },
  {
    name: 'DTDC Courier',
    keywords: ['dtdc'],
    officialDomains: ['dtdc.in'],
  },
  {
    name: 'FedEx',
    keywords: ['fedex'],
    officialDomains: ['fedex.com'],
  },
  {
    name: 'DHL',
    keywords: ['dhl'],
    officialDomains: ['dhl.com'],
  },
  {
    name: 'Reliance Jio',
    keywords: ['jio', 'myjio'],
    officialDomains: ['jio.com'],
  },
  {
    name: 'Airtel',
    keywords: ['airtel', 'airtelthanks'],
    officialDomains: ['airtel.in', 'airtel.com'],
  },
  {
    name: 'Vodafone Idea (Vi)',
    keywords: ['myvi'],
    officialDomains: ['myvi.in'],
  },
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'office365', 'onedrive'],
    officialDomains: ['microsoft.com', 'live.com', 'office.com'],
  },
  {
    name: 'Apple',
    keywords: ['apple', 'icloud'],
    officialDomains: ['apple.com', 'icloud.com'],
  },
  {
    name: 'Netflix',
    keywords: ['netflix'],
    officialDomains: ['netflix.com'],
  },
  {
    name: 'PayPal',
    keywords: ['paypal'],
    officialDomains: ['paypal.com'],
  },
  {
    name: 'UIDAI / Aadhaar',
    keywords: ['uidai', 'myaadhaar', 'eaadhaar', 'aadhaar'],
    officialDomains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'],
  },
  {
    name: 'Income Tax Department',
    keywords: ['incometax', 'incometaxindia'],
    officialDomains: ['incometax.gov.in'],
  },
  {
    name: 'EPFO India',
    keywords: ['epfo', 'epfindia'],
    officialDomains: ['epfindia.gov.in'],
  },
  {
    name: 'IRCTC',
    keywords: ['irctc'],
    officialDomains: ['irctc.co.in'],
  },
  {
    name: 'National Cyber Crime Portal',
    keywords: ['cybercrime'],
    officialDomains: ['cybercrime.gov.in'],
  },
  {
    name: 'Reserve Bank of India (RBI)',
    keywords: ['rbi'],
    officialDomains: ['rbi.org.in'],
  },
  {
    name: 'NPCI (BHIM / UPI)',
    keywords: ['npci', 'bhimupi'],
    officialDomains: ['npci.org.in', 'bhimupi.org.in'],
  },
  {
    name: 'Parivahan / mParivahan',
    keywords: ['parivahan'],
    officialDomains: ['parivahan.gov.in'],
  },
];

// Curated list of established authoritative domains for limited checks
const ADDITIONAL_AUTHORITATIVE_DOMAINS = new Set([
  'github.com',
  'wikipedia.org',
  'cloudflare.com',
  'whatsapp.com',
  'telegram.org',
  'youtube.com',
  'linkedin.com',
  'twitter.com',
  'x.com',
  'facebook.com',
  'instagram.com',
  'stackoverflow.com',
  'mozilla.org',
  'w3.org',
  'who.int',
  'rbi.org.in',
  'npci.org.in',
]);

/**
 * Extracts root registered domain (e.g. google.com from sub.google.com, amazon.in from www.amazon.in)
 */
export function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;
  const doubleTlds = new Set([
    'co.in', 'gov.in', 'org.in', 'net.in', 'edu.in', 'ac.in', 'res.in',
    'co.uk', 'org.uk', 'com.au', 'net.au', 'com.sg', 'co.nz', 'co.za'
  ]);
  const lastTwo = parts.slice(-2).join('.');
  if (doubleTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Checks if a hostname or registered domain belongs to a recognized authoritative institution
 */
export function isAuthoritativeDomain(hostname, registeredDomain) {
  if (!hostname) return false;
  const normHost = hostname.toLowerCase();
  const regDomain = (registeredDomain || extractRegisteredDomain(normHost)).toLowerCase();

  // Government & National Informatics Centre domains
  if (regDomain.endsWith('.gov.in') || regDomain.endsWith('.nic.in')) {
    return true;
  }

  // Check official domains of protected brands
  for (const brand of PROTECTED_BRANDS) {
    for (const official of brand.officialDomains) {
      if (regDomain === official || normHost === official || normHost.endsWith(`.${official}`)) {
        return true;
      }
    }
  }

  // Additional globally established platforms
  if (ADDITIONAL_AUTHORITATIVE_DOMAINS.has(regDomain) || ADDITIONAL_AUTHORITATIVE_DOMAINS.has(normHost)) {
    return true;
  }

  return false;
}

/**
 * Checks if a hostname belongs to an official brand domain (or is a valid subdomain thereof)
 */
function isOfficialDomainOrSubdomain(hostname, officialDomains) {
  const normHost = hostname.toLowerCase();
  for (const official of officialDomains) {
    if (normHost === official || normHost.endsWith(`.${official}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Computes Damerau-Levenshtein edit distance between two strings (handles transpositions).
 */
export function damerauLevenshteinDistance(s1, s2) {
  if (s1 === s2) return 0;
  if (!s1.length) return s2.length;
  if (!s2.length) return s1.length;
  const len1 = s1.length;
  const len2 = s2.length;
  const d = Array.from({ length: len1 + 1 }, () => new Array(len2 + 1).fill(0));
  for (let i = 0; i <= len1; i++) d[i][0] = i;
  for (let j = 0; j <= len2; j++) d[0][j] = j;
  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );
      if (i > 1 && j > 1 && s1[i - 1] === s2[j - 2] && s1[i - 2] === s2[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
      }
    }
  }
  return d[len1][len2];
}

/**
 * Levenshtein distance for backwards compatibility
 */
export function levenshteinDistance(s1, s2) {
  return damerauLevenshteinDistance(s1, s2);
}

/**
 * Checks if string contains Cyrillic or Greek confusable homoglyphs.
 */
export function hasHomoglyphCharacters(str) {
  if (!str) return false;
  return /[\u0400-\u04FF\u0370-\u03FF]/.test(str);
}

/**
 * Normalizes common leetspeak substitutions to detect typosquatting
 */
export function normalizeLeetspeak(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
}

/**
 * Parses and safely normalizes URL components.
 * Validates scheme, rejects malformed URLs, and redacts sensitive query parameters.
 */
export function normalizeUrlDetails(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new Error('MALFORMED_URL: URL must be a non-empty string.');
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (err) {
    throw new Error(`MALFORMED_URL: Invalid URL format (${err.message}).`);
  }

  // Scheme validation: strictly http or https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`UNSUPPORTED_SCHEME: Scheme "${parsed.protocol}" is not supported. Only HTTP and HTTPS are permitted.`);
  }

  const hostname = parsed.hostname.toLowerCase();
  const registeredDomain = extractRegisteredDomain(hostname);
  const isHttps = parsed.protocol === 'https:';

  let cleanUrl = `${parsed.protocol}//${hostname}`;
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    cleanUrl += `:${parsed.port}`;
  }
  cleanUrl += parsed.pathname;
  if (parsed.search) cleanUrl += parsed.search;

  const safeDisplayUrl = redactSensitiveUrl(cleanUrl);

  return {
    rawUrl,
    cleanUrl,
    safeDisplayUrl,
    full: cleanUrl,
    hostname,
    registeredDomain,
    protocol: parsed.protocol,
    isHttps,
    pathname: parsed.pathname,
    port: parsed.port || (isHttps ? '443' : '80'),
    search: parsed.search,
  };
}

export const normalizeUrl = normalizeUrlDetails;

export function matchBrandKeyword(hostname, kw) {
  if (kw.length <= 3) {
    const regex = new RegExp(`(^|[.\\-_0-9])${kw}([.\\-_0-9]|$)`, 'i');
    return regex.test(hostname);
  }
  return hostname.includes(kw);
}

/**
 * Scans a normalized URL against heuristic rules.
 * @param {string} rawUrl - Absolute HTTP/HTTPS URL
 * @returns {object} Analysis result
 */
export function scanUrl(rawUrl) {
  const details = normalizeUrlDetails(rawUrl);
  const hostname = details.hostname;
  const pathname = details.pathname;
  const registeredDomain = details.registeredDomain;
  const indicators = [];
  let score = 0;

  // 1. Check IP Hostname (IPv4 / IPv6)
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  if (isIpv4 || isIpv6) {
    indicators.push({
      id: 'IP_ADDRESS_HOSTNAME',
      category: 'Domain Structure',
      severity: 'high',
      source: 'url_heuristics',
      description: 'The URL uses a raw IP address instead of a registered domain name, a common phishing pattern.',
    });
    score += 40;
  }

  // 2. Check Misleading '@' or embedded credentials in authority
  const parsed = new URL(rawUrl);
  if (rawUrl.includes('@') || parsed.username || parsed.password) {
    indicators.push({
      id: 'EMBEDDED_USERINFO_CREDENTIALS',
      category: 'URL Obfuscation',
      severity: 'high',
      source: 'url_heuristics',
      description: 'The URL embeds authentication credentials or "@" symbol in the authority segment, often used in phishing lures.',
    });
    score += 40;
  }

  // 3. Check Suspicious Direct File Download (.apk, .exe, etc.)
  if (MALICIOUS_EXTENSIONS.test(pathname)) {
    const ext = pathname.match(MALICIOUS_EXTENSIONS)[1].toUpperCase();
    indicators.push({
      id: 'DANGEROUS_FILE_DOWNLOAD',
      category: 'File Download Risk',
      severity: 'high',
      source: 'url_heuristics',
      description: `The URL links directly to an executable/application file (${ext}), posing potential malware risks.`,
    });
    score += 45;
  }

  // 4. Deceptive Brand Subdomain Spoofing
  for (const brand of PROTECTED_BRANDS) {
    for (const official of brand.officialDomains) {
      if (hostname.includes(official) && registeredDomain !== official && !isOfficialDomainOrSubdomain(hostname, brand.officialDomains)) {
        indicators.push({
          id: 'DECEPTIVE_BRAND_SUBDOMAIN',
          category: 'Brand Impersonation',
          severity: 'high',
          source: 'url_heuristics',
          description: `The domain embeds an official domain "${official}" inside an unrelated third-party root domain (${registeredDomain}).`,
        });
        score += 45;
        break;
      }
    }
  }

  // 5. Check Protected Brand Lookalikes in Hostname
  for (const brand of PROTECTED_BRANDS) {
    const brandMatched = brand.keywords.some((kw) => matchBrandKeyword(hostname, kw));
    if (brandMatched) {
      const isLegit = isOfficialDomainOrSubdomain(hostname, brand.officialDomains);
      if (!isLegit) {
        indicators.push({
          id: 'PROTECTED_BRAND_LOOKALIKE',
          category: 'Brand Impersonation',
          severity: 'high',
          source: 'url_heuristics',
          description: `The domain mimics "${brand.name}" but does not belong to verified official domains (${brand.officialDomains.join(', ')}).`,
        });
        score += 45;
        break;
      }
    }
  }

  // 6. Check Typosquatting / Homoglyph / Damerau-Levenshtein Edit-Distance Substitutions in Hostname
  if (!indicators.some((i) => i.id === 'PROTECTED_BRAND_LOOKALIKE')) {
    const leetNormalized = normalizeLeetspeak(hostname);
    const squeezed = hostname.replace(/(.)\1+/g, '$1$1'); // e.g. gooogle -> google
    const mainLabel = registeredDomain.split('.')[0]; // e.g. gooogle from gooogle.com

    for (const brand of PROTECTED_BRANDS) {
      if (isOfficialDomainOrSubdomain(hostname, brand.officialDomains)) continue;

      let isTypo = false;
      for (const kw of brand.keywords) {
        if (kw.length < 4) continue;
        if (leetNormalized.includes(kw)) {
          isTypo = true;
          break;
        }
        if (squeezed.includes(kw)) {
          isTypo = true;
          break;
        }
        if (damerauLevenshteinDistance(mainLabel, kw) === 1) {
          isTypo = true;
          break;
        }
      }

      if (isTypo) {
        indicators.push({
          id: 'TYPOSQUATTING_BRAND_LOOKALIKE',
          category: 'Typosquatting Risk',
          severity: 'high',
          source: 'url_heuristics',
          description: `The domain uses typosquatting or character variations mimicking "${brand.name}".`,
        });
        score += 40;
        break;
      }
    }
  }

  // 7. Check High-Abuse TLDs
  const domainParts = hostname.split('.');
  const tld = domainParts[domainParts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    indicators.push({
      id: 'HIGH_ABUSE_TLD',
      category: 'Top-Level Domain',
      severity: 'medium',
      source: 'url_heuristics',
      description: `Uses a top-level domain (.${tld}) with elevated rates of abuse and disposable registration.`,
    });
    score += 20;
  }

  // 8. Check Known URL Shortener
  if (KNOWN_SHORTENERS.has(hostname)) {
    indicators.push({
      id: 'URL_SHORTENER_DETECTED',
      category: 'URL Obfuscation',
      severity: 'low',
      source: 'url_heuristics',
      description: 'The URL uses a shortening service that conceals the final target address.',
    });
    score += 15;
  }

  // 9. Check Excessive Subdomains (>= 4 dots)
  if (domainParts.length >= 5) {
    indicators.push({
      id: 'EXCESSIVE_SUBDOMAINS',
      category: 'Domain Structure',
      severity: 'medium',
      source: 'url_heuristics',
      description: 'The domain features multiple nested subdomains, frequently used to obscure the root domain.',
    });
    score += 18;
  }

  // 10. Check Excessive Hyphens in Hostname (>= 3 hyphens)
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    indicators.push({
      id: 'EXCESSIVE_HYPHENS',
      category: 'Domain Structure',
      severity: 'medium',
      source: 'url_heuristics',
      description: `Contains ${hyphenCount} hyphens in the hostname, a pattern frequently seen in phishing name generation.`,
    });
    score += 20;
  }

  // 11. Check Non-Standard Port
  if (details.port && details.port !== '80' && details.port !== '443') {
    indicators.push({
      id: 'NON_STANDARD_PORT',
      category: 'Network Port',
      severity: 'medium',
      source: 'url_heuristics',
      description: `The URL specifies a non-standard port (:${details.port}) rather than default web ports 80/443.`,
    });
    score += 15;
  }

  // 12. Check Punycode / IDN Homograph
  if (hostname.includes('xn--')) {
    indicators.push({
      id: 'PUNYCODE_ENCODING',
      category: 'Homograph Attack',
      severity: 'medium',
      source: 'url_heuristics',
      description: 'The hostname uses internationalized Punycode encoding, often used in visual homograph attacks.',
    });
    score += 25;
  }

  // 13. Cyrillic / Greek Confusable Homoglyphs in Hostname (mixed script lookalike)
  const cyrillicConfusables = /[\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0423\u0425\u0370-\u03FF]/;
  if (cyrillicConfusables.test(hostname) || (hostname.includes('xn--') && cyrillicConfusables.test(decodeURI(rawUrl)))) {
    indicators.push({
      id: 'CONFUSABLE_HOMOGLYPH_ATTACK',
      category: 'Homograph Attack',
      severity: 'high',
      source: 'url_heuristics',
      description: 'The domain contains visual confusable characters (Cyrillic/Greek lookalikes) resembling Latin characters.',
    });
    score += 45;
  }

  // 14. Suspicious Phishing Keywords in Hostname on Unofficial Domain
  const phishingKeywords = [
    'login', 'signin', 'verify', 'verification', 'update', 'kyc', 'secure',
    'security', 'banking', 'netbanking', 'wallet', 'auth', 'otp', 'claim',
    'reward', 'prize', 'winner', 'account-update', 'recover', 'suspended',
    'redelivery', 'parcel-held', 'delivery-fee', 'refund'
  ];
  const matchedKeywords = phishingKeywords.filter((kw) => hostname.includes(kw));
  if (matchedKeywords.length >= 2 && !isAuthoritativeDomain(hostname, registeredDomain)) {
    indicators.push({
      id: 'SUSPICIOUS_PHISHING_KEYWORDS',
      category: 'Domain Semantics',
      severity: 'high',
      source: 'url_heuristics',
      description: `Domain contains multiple security/phishing keywords (${matchedKeywords.slice(0, 3).join(', ')}) on an unverified domain.`,
    });
    score += 35;
  }

  // 15. Check Excessive Length (> 120 chars)
  if (rawUrl.length > 120) {
    indicators.push({
      id: 'EXCESSIVE_URL_LENGTH',
      category: 'URL Obfuscation',
      severity: 'low',
      source: 'url_heuristics',
      description: 'The URL is unusually long, which can be an indicator of obfuscation or token stuffing.',
    });
    score += 10;
  }

  // 16. Sensitive action keywords in URL path on non-authoritative domain
  const pathTokens = pathname.toLowerCase();
  const hasLogin = /\b(?:login|signin|verify|update|kyc|banking|secure|netbanking|wallet|otp|pan)\b/.test(pathTokens);
  if (hasLogin && indicators.length > 0 && !indicators.some((i) => i.id === 'SUSPICIOUS_PATH_TOKENS')) {
    indicators.push({
      id: 'SUSPICIOUS_PATH_TOKENS',
      category: 'Path Heuristics',
      severity: 'medium',
      source: 'url_heuristics',
      description: 'Contains sensitive action keywords (login/verify/kyc) in the path within an unverified domain.',
    });
    score += 15;
  }

  // 17. Encoded Path Traversal or Null Byte Obfuscation
  if (/%2e%2e|%2f|%5c|%00/i.test(rawUrl)) {
    indicators.push({
      id: 'OBFUSCATED_HEX_TRAVERSAL',
      category: 'URL Obfuscation',
      severity: 'high',
      source: 'url_heuristics',
      description: 'The URL contains hex-encoded path traversal or null byte sequences (%2e%2e, %00).',
    });
    score += 35;
  }

  // 18. User-info embedded credentials in URL
  if (rawUrl.includes('@') && !indicators.some((i) => i.id === 'MISLEADING_AT_SYMBOL')) {
    indicators.push({
      id: 'EMBEDDED_USERINFO_CREDENTIALS',
      category: 'URL Obfuscation',
      severity: 'high',
      source: 'url_heuristics',
      description: 'The URL embeds authentication credentials in the authority segment, often used in phishing lures.',
    });
    score += 35;
  }

  // Deduplicate indicators by id
  const uniqueIndicators = Array.from(new Map(indicators.map((i) => [i.id, i])).values());

  // Clamp score (0 to 100)
  const riskScore = Math.min(100, Math.max(0, score));

  // Determine Risk Level (low: 0-24, caution: 25-49, suspicious: 50-74, high: 75-100)
  let riskLevel = 'low';
  let verdict = 'no_known_warning_signs';
  let verdictLabel = 'Low risk indicators';
  let displayBand = 'green';

  if (riskScore >= 75) {
    riskLevel = 'high';
    verdict = 'critical_threat_indicators';
    verdictLabel = 'High risk';
    displayBand = 'red';
  } else if (riskScore >= 50) {
    riskLevel = 'suspicious';
    verdict = 'suspicious_indicators_found';
    verdictLabel = 'Suspicious';
    displayBand = 'orange';
  } else if (riskScore >= 25) {
    riskLevel = 'caution';
    verdict = 'caution_advised';
    verdictLabel = 'Caution';
    displayBand = 'yellow';
  }

  const isAuthoritative = isAuthoritativeDomain(hostname, registeredDomain);
  let verificationStatus = 'insufficient_evidence';

  if (riskScore >= 75) {
    verificationStatus = 'verified_threat';
  } else if (isAuthoritative && riskScore < 25) {
    verificationStatus = 'limited_checks_completed';
    verdict = 'no_known_warning_signs';
    verdictLabel = 'Low risk indicators';
    displayBand = 'green';
  } else {
    verificationStatus = 'insufficient_evidence';
    if (riskScore < 25) {
      verdict = 'unable_to_verify';
      verdictLabel = 'Unable to verify website safety';
      displayBand = 'yellow';
    }
  }

  // Practical safety advice
  const safetyAdvice = [];
  if (uniqueIndicators.some((i) => i.id === 'DANGEROUS_FILE_DOWNLOAD')) {
    safetyAdvice.push('Never download or install application (.APK/.EXE) files outside official app stores like Google Play.');
  }
  if (uniqueIndicators.some((i) => i.id === 'PROTECTED_BRAND_LOOKALIKE' || i.id === 'DECEPTIVE_BRAND_SUBDOMAIN' || i.id === 'TYPOSQUATTING_BRAND_LOOKALIKE')) {
    safetyAdvice.push('Do not enter netbanking credentials, passwords, or PINs. Access the official website or verified banking app directly.');
  }
  if (uniqueIndicators.some((i) => i.id === 'URL_SHORTENER_DETECTED')) {
    safetyAdvice.push('Do not proceed through shortened links sent by unverified contacts via SMS or WhatsApp.');
  }
  if (uniqueIndicators.some((i) => i.id === 'IP_ADDRESS_HOSTNAME')) {
    safetyAdvice.push('Legitimate financial institutions and services never host customer portals on raw IP addresses.');
  }

  if (uniqueIndicators.length === 0) {
    if (isAuthoritative) {
      safetyAdvice.push('Completed standard structural and brand checks for recognized domain. No warning signs detected.');
      safetyAdvice.push('Always confirm the domain name in your browser address bar before entering passwords or payment details.');
    } else {
      safetyAdvice.push('No known warning signs were detected by local rules, but safety cannot be verified for this uncatalogued domain.');
      safetyAdvice.push('Exercise caution before entering passwords or payment details on unfamiliar sites.');
    }
  } else {
    safetyAdvice.push('Always independently verify the destination domain before submitting passwords or personal info.');
  }

  return {
    url: rawUrl,
    safeDisplayUrl: details.safeDisplayUrl,
    normalizedUrl: {
      full: details.cleanUrl,
      hostname: details.hostname,
      registeredDomain: details.registeredDomain,
      protocol: details.protocol,
      isHttps: details.isHttps,
      pathname: details.pathname,
    },
    riskScore,
    riskLevel,
    verdict,
    verdictLabel,
    displayBand,
    verificationStatus,
    isAuthoritativeDomain: isAuthoritative,
    indicators: uniqueIndicators,
    reputation: {
      checked: false,
      provider: null,
      reputationStatus: 'not_configured',
      status: 'not_configured',
      verdict: null,
      threatCategory: null,
      details: 'Reputation check not yet executed.',
    },
    safetyAdvice,
    engine: 'url_rules_v1',
  };
}
