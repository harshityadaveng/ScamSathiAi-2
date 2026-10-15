/**
 * Privacy Service
 * Context-aware masking for sensitive personal and financial identifiers.
 * Masks OTPs, bank account numbers, payment cards, and Aadhaar numbers.
 */

// 1. Payment Cards: 13 to 19 digits, possibly separated by spaces or dashes
const CARD_REGEX = /\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b(?:\d{4}[-\s]?){4}\d{1,3}\b/g;

// 2. Aadhaar Numbers: 12 digits, frequently formatted as 4-4-4 digits
const AADHAAR_FORMATTED_REGEX = /\b[2-9]\d{3}\s\d{4}\s\d{4}\b/g;
const AADHAAR_CONTEXT_REGEX = /\b(?:aadhaar|uidai|adhar|uid)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{12})\b/gi;

// 3. Bank Account Numbers: Context of account/A/c followed by 9-18 digits
const BANK_ACCOUNT_REGEX = /\b(?:a\/c|acct|acc|account|khata)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{9,18})\b/gi;

// 4. OTP / Verification Codes: Context of otp/code followed by 4-8 digits
const OTP_REGEX = /\b(?:otp|one\s*time\s*password|verification\s*code|security\s*code|login\s*code)\s*(?:is|:|-)?\s*(\d{4,8})\b/gi;
const OTP_REVERSE_REGEX = /\b(\d{4,8})\s*(?:is\s*your\s*(?:one\s*time\s*password|otp|verification\s*code))\b/gi;

// 5. CVV: Context of CVV/CVC followed by 3-4 digits
const CVV_REGEX = /\b(?:cvv|cvc|security\s*digits?)\s*[:\-]?\s*(\d{3,4})\b/gi;

/**
 * Sanitizes input text by masking context-identified sensitive data.
 * @param {string} text - The raw input text
 * @returns {{ sanitizedText: string, maskedItemsCount: number, maskedCategories: string[] }}
 */
export function sanitizeSensitiveData(text) {
  if (!text || typeof text !== 'string') {
    return { sanitizedText: '', maskedItemsCount: 0, maskedCategories: [] };
  }

  let sanitized = text;
  let count = 0;
  const categories = new Set();

  // 1. Mask CVV
  sanitized = sanitized.replace(CVV_REGEX, (match, cvv) => {
    count++;
    categories.add('cvv');
    return match.replace(cvv, '[MASKED_CVV]');
  });

  // 2. Mask Payment Cards (verify length between 13 and 19 digits)
  sanitized = sanitized.replace(CARD_REGEX, (match) => {
    const rawDigits = match.replace(/[-\s]/g, '');
    if (rawDigits.length >= 13 && rawDigits.length <= 19) {
      count++;
      categories.add('payment_card');
      const last4 = rawDigits.slice(-4);
      return `[MASKED_CARD_****${last4}]`;
    }
    return match;
  });

  // 3. Mask Aadhaar Formatted (xxxx xxxx xxxx)
  sanitized = sanitized.replace(AADHAAR_FORMATTED_REGEX, () => {
    count++;
    categories.add('aadhaar');
    return '[MASKED_AADHAAR]';
  });

  // 3b. Mask Aadhaar with context (12 consecutive digits)
  sanitized = sanitized.replace(AADHAAR_CONTEXT_REGEX, (match, num) => {
    count++;
    categories.add('aadhaar');
    return match.replace(num, '[MASKED_AADHAAR]');
  });

  // 4. Mask Bank Account Numbers
  sanitized = sanitized.replace(BANK_ACCOUNT_REGEX, (match, num) => {
    count++;
    categories.add('bank_account');
    const last4 = num.slice(-4);
    return match.replace(num, `[MASKED_ACCOUNT_****${last4}]`);
  });

  // 5. Mask OTP Codes
  sanitized = sanitized.replace(OTP_REGEX, (match, otp) => {
    count++;
    categories.add('otp');
    return match.replace(otp, '[MASKED_OTP]');
  });

  sanitized = sanitized.replace(OTP_REVERSE_REGEX, (match, otp) => {
    count++;
    categories.add('otp');
    return match.replace(otp, '[MASKED_OTP]');
  });

  return {
    sanitizedText: sanitized,
    maskedItemsCount: count,
    maskedCategories: Array.from(categories),
  };
}
