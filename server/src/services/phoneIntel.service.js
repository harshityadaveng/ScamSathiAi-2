import { env } from '../config/env.js';

let mockPhoneHandler = null;

/**
 * Injects a mock phone intelligence handler for testing.
 * @param {Function|null} handler
 */
export function setMockPhoneHandler(handler) {
  mockPhoneHandler = handler;
}

/**
 * Standard TRAI Telecom Service Provider prefixes for Indian SMS headers
 */
const TRAI_OPERATOR_PREFIXES = new Set([
  'AX', 'AD', 'AP', 'AZ', 'BP', 'BZ', 'BT', 'BW', 'CP', 'CZ', 'CT', 'DM',
  'DZ', 'GA', 'GP', 'GZ', 'IM', 'IX', 'JD', 'JP', 'JZ', 'MB', 'MG', 'MZ',
  'NX', 'NZ', 'OP', 'OZ', 'RD', 'RZ', 'TA', 'TD', 'TM', 'TZ', 'VD', 'VK',
  'VM', 'VP', 'VR', 'VZ', 'WB', 'WZ'
]);

/**
 * Validates and parses Indian TRAI DLT SMS sender headers.
 * Standard format: 2-character provider circle + '-' + 6-character registered entity code.
 * Example: VK-HDFCBK, AD-SBIINB, BP-PAYTM
 *
 * @param {string} sender
 * @returns {object} Validation details
 */
export function validateTraiSenderHeader(sender) {
  if (!sender || typeof sender !== 'string') {
    return { isTraiHeader: false, isValid: false, reason: 'Empty or missing sender string' };
  }

  const clean = sender.trim().toUpperCase();

  // Pattern 1: 2-char prefix + '-' + 6-char header (e.g., VK-HDFCBK)
  const prefixedMatch = /^([A-Z]{2})-([A-Z]{6})$/.exec(clean);
  if (prefixedMatch) {
    const [, prefix, entityCode] = prefixedMatch;
    const isKnownPrefix = TRAI_OPERATOR_PREFIXES.has(prefix);
    return {
      isTraiHeader: true,
      isValid: true,
      senderType: 'trai_dlt_registered_header',
      prefix,
      entityCode,
      isRecognizedOperatorCircle: isKnownPrefix,
      explanation: `Valid 6-character TRAI DLT enterprise SMS sender header with operator prefix "${prefix}".`,
    };
  }

  // Pattern 2: Standalone 6-character alphanumeric header (e.g., HDFCBK, SBISMS, PAYTMB)
  if (/^[A-Z]{6}$/.test(clean)) {
    return {
      isTraiHeader: true,
      isValid: true,
      senderType: 'trai_dlt_entity_code',
      prefix: null,
      entityCode: clean,
      isRecognizedOperatorCircle: true,
      explanation: `Standard 6-character enterprise SMS code "${clean}".`,
    };
  }

  return {
    isTraiHeader: false,
    isValid: false,
    senderType: 'non_trai_format',
    explanation: 'Sender string does not follow the standard TRAI 6-character enterprise SMS format.',
  };
}

/**
 * Normalizes and validates phone numbers, with specific support for Indian mobile numbers (+91).
 *
 * @param {string} rawPhone
 * @returns {object} Validation result with normalized E.164 number
 */
export function normalizePhoneNumber(rawPhone) {
  if (!rawPhone || typeof rawPhone !== 'string') {
    return {
      isValid: false,
      normalized: null,
      country: null,
      type: 'invalid',
      error: 'Empty or missing phone input',
    };
  }

  // Strip non-digit characters except leading plus
  let sanitized = rawPhone.trim().replace(/[^\d+]/g, '');

  // Handle leading zeros or 91 country code
  let nationalNumber = sanitized;
  let countryCode = 'unknown';

  if (sanitized.startsWith('+91')) {
    nationalNumber = sanitized.slice(3);
    countryCode = 'IN';
  } else if (sanitized.startsWith('91') && sanitized.length === 12) {
    nationalNumber = sanitized.slice(2);
    countryCode = 'IN';
  } else if (sanitized.startsWith('0') && sanitized.length === 11) {
    nationalNumber = sanitized.slice(1);
    countryCode = 'IN';
  } else if (sanitized.length === 10 && /^[6-9]/.test(sanitized)) {
    // Standard 10-digit Indian mobile number
    nationalNumber = sanitized;
    countryCode = 'IN';
  }

  // Indian mobile validation: 10 digits starting with 6, 7, 8, or 9
  const isIndianMobile = countryCode === 'IN' && /^[6-9]\d{9}$/.test(nationalNumber);

  if (isIndianMobile) {
    return {
      isValid: true,
      raw: rawPhone,
      normalized: `+91${nationalNumber}`,
      nationalNumber,
      country: 'IN',
      type: 'indian_mobile',
      isPersonalMobile: true,
      explanation: 'Valid Indian mobile phone number (10-digit, telecom prefix 6-9).',
    };
  }

  // General E.164 check for international numbers (+ followed by 7-15 digits)
  if (/^\+[1-9]\d{6,14}$/.test(sanitized)) {
    return {
      isValid: true,
      raw: rawPhone,
      normalized: sanitized,
      nationalNumber: sanitized.slice(1),
      country: countryCode,
      type: 'international_e164',
      isPersonalMobile: false,
      explanation: 'Valid international E.164 phone number format.',
    };
  }

  return {
    isValid: false,
    raw: rawPhone,
    normalized: null,
    country: null,
    type: 'invalid_format',
    error: 'Phone number does not match recognized Indian or international formats.',
  };
}

/**
 * Checks sender / phone intelligence.
 * Detects whether a personal mobile number was used to send an institutional bank/KYC/disconnection alert.
 *
 * @param {string} senderInput - Raw sender string or phone number
 * @param {object} context - Optional context { hasBankingClaims, hasDisconnectionClaims }
 * @returns {Promise<object>} Sender intelligence report
 */
export async function analyzeSenderIntel(senderInput, context = {}) {
  if (mockPhoneHandler) {
    return mockPhoneHandler(senderInput, context);
  }

  const timestamp = new Date().toISOString();

  if (!senderInput || typeof senderInput !== 'string' || senderInput.trim() === '') {
    return {
      checked: false,
      status: 'not_provided',
      reputationStatus: 'not_provided',
      sender: null,
      explanation: 'No sender header or phone number was provided for analysis.',
    };
  }

  const cleanInput = senderInput.trim();

  // Check 1: Is this a TRAI DLT header?
  const traiCheck = validateTraiSenderHeader(cleanInput);
  if (traiCheck.isTraiHeader) {
    return {
      checked: true,
      status: 'passed',
      reputationStatus: 'verified_format',
      sender: cleanInput,
      senderType: 'trai_dlt_header',
      details: traiCheck,
      isSuspicious: false,
      explanation: `Sender matches TRAI DLT registered enterprise header format (${traiCheck.entityCode}).`,
      indicators: [],
    };
  }

  // Check 2: Is this a phone number?
  const phoneDetails = normalizePhoneNumber(cleanInput);

  if (phoneDetails.isValid) {
    const indicators = [];
    let isSuspicious = false;

    // Critical Red Flag: Personal mobile number sending bank KYC / account block / utility cut alert
    if (phoneDetails.isPersonalMobile && (context.hasBankingClaims || context.hasDisconnectionClaims)) {
      isSuspicious = true;
      indicators.push({
        id: 'PERSONAL_MOBILE_BANK_SPOOF',
        severity: 'critical',
        category: 'Sender Impersonation',
        description: `Official bank/utility alerts are sent exclusively via TRAI 6-alpha headers. This message originates from a personal 10-digit mobile number (${phoneDetails.normalized}).`,
      });
    }

    return {
      checked: true,
      status: isSuspicious ? 'finding' : 'passed',
      reputationStatus: isSuspicious ? 'suspicious_sender' : 'format_valid_unverified_reputation',
      sender: phoneDetails.normalized,
      senderType: phoneDetails.type,
      details: {
        normalized: phoneDetails.normalized,
        country: phoneDetails.country,
        type: phoneDetails.type,
        isPersonalMobile: phoneDetails.isPersonalMobile,
      },
      isSuspicious,
      indicators,
      explanation: isSuspicious
        ? 'Impersonation detected: Financial or utility alerts sent from a personal mobile number.'
        : 'Valid phone number format. Note: External reputation lookup is not configured for individual numbers.',
    };
  }

  // Non-standard sender string (e.g. unknown email or nickname)
  return {
    checked: true,
    status: 'finding',
    reputationStatus: 'unverified_sender',
    sender: cleanInput,
    senderType: 'unverified_string',
    details: { raw: cleanInput },
    isSuspicious: false,
    indicators: [],
    explanation: 'Sender does not match standard TRAI SMS headers or recognized phone number formats.',
  };
}
