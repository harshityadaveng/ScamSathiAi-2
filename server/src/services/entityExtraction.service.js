/**
 * Entity Extraction Service
 * Extracts and deduplicates URLs, Indian phone numbers, and UPI IDs without network requests.
 */

// Well-known Indian UPI handles & provider patterns
const COMMON_UPI_HANDLES = new Set([
  'upi', 'paytm', 'ybl', 'ibl', 'axl', 'okaxis', 'okhdfcbank', 'okicici', 'oksbi',
  'sbi', 'hdfcbank', 'icici', 'kotak', 'axisbank', 'barodampay', 'cnrb', 'pnb',
  'unionbank', 'idfcbank', 'federal', 'aubank', 'indus', 'yesbank', 'airtel',
  'freecharge', 'mobikwik', 'jio', 'postbank', 'timepay', 'pingpay'
]);

// Top-level domains that indicate an email address rather than a UPI ID
const EMAIL_TLDS = new Set(['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'io', 'co', 'ai', 'info', 'biz']);

// Regex for URLs (http/https or domains with common TLDs)
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|\b[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|in|org|net|xyz|top|info|biz|co|app|live|online|tk|ml|ga|cf|gq|site|club|vip|icu|shop|store)(?:\/[^\s<>"'{}|\\^`]*)?/gi;

// Regex for Indian Phone Numbers:
// Formats: +91 9876543210, +91-9876543210, 09876543210, 9876543210, +91 98765 43210
const INDIAN_PHONE_REGEX = /(?:(?:\+91|91|0)[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})\b/g;

// Regex for UPI ID (alphanumeric, dot, underscore, dash + @ + handle)
const UPI_REGEX = /\b([a-zA-Z0-9._\-]+)@([a-zA-Z0-9_\-]+)\b/g;

/**
 * Strips trailing sentence punctuation from extracted URLs.
 */
function cleanUrl(rawUrl) {
  let url = rawUrl.trim();
  // Strip trailing punctuation: . , ; ! ? ) ] ' "
  url = url.replace(/[.,;:!?)\],'"”’]+$/, '');
  return url;
}

/**
 * Normalizes Indian phone number to 10-digit standard format
 */
function normalizePhone(rawPhone) {
  const digits = rawPhone.replace(/\D/g, '');
  if (digits.length === 10) return digits;
  if (digits.length === 11 && digits.startsWith('0')) return digits.slice(1);
  if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
  return digits;
}

/**
 * Extracts entities from text.
 * @param {string} text - Input text
 * @returns {{ urls: string[], phoneNumbers: string[], upiIds: string[] }}
 */
export function extractEntities(text) {
  if (!text || typeof text !== 'string') {
    return { urls: [], phoneNumbers: [], upiIds: [] };
  }

  const urls = new Set();
  const phoneNumbers = new Set();
  const upiIds = new Set();

  // 1. Extract URLs
  let match;
  const urlMatches = text.match(URL_REGEX) || [];
  for (const raw of urlMatches) {
    const cleaned = cleanUrl(raw);
    if (cleaned.length > 3) {
      urls.add(cleaned);
    }
  }

  // 2. Extract Indian Phone Numbers
  const phoneRegex = new RegExp(INDIAN_PHONE_REGEX);
  while ((match = phoneRegex.exec(text)) !== null) {
    const fullMatch = match[0];
    const normalized = normalizePhone(fullMatch);
    if (normalized.length === 10 && /^[6-9]\d{9}$/.test(normalized)) {
      phoneNumbers.add(normalized);
    }
  }

  // 3. Extract UPI IDs (ensuring we don't pick up standard email addresses)
  const upiRegex = new RegExp(UPI_REGEX);
  while ((match = upiRegex.exec(text)) !== null) {
    const [fullUpi, username, handle] = match;
    const lowerHandle = handle.toLowerCase();

    // If handle has a dot (e.g. gmail.com) or matches an email TLD, skip
    if (lowerHandle.includes('.')) {
      const parts = lowerHandle.split('.');
      const tld = parts[parts.length - 1];
      if (EMAIL_TLDS.has(tld)) {
        continue; // It's an email address, not a UPI ID
      }
    }

    // Check if it matches known UPI handles or user-provided UPI syntax
    if (
      COMMON_UPI_HANDLES.has(lowerHandle) ||
      fullUpi.toLowerCase().includes('upi') ||
      /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{3,}$/.test(fullUpi)
    ) {
      upiIds.add(fullUpi.toLowerCase());
    }
  }

  return {
    urls: Array.from(urls),
    phoneNumbers: Array.from(phoneNumbers),
    upiIds: Array.from(upiIds),
  };
}
