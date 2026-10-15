import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import jpeg from 'jpeg-js';
import { GoogleGenAI } from '@google/genai';
import { env } from '../config/env.js';
import { runWebsiteInvestigation } from './websiteIntelPipeline.service.js';
import { evaluateScamRules, determineScamType, generateSafetyAdvice } from './scamDetection.service.js';
import { extractEntities } from './entityExtraction.service.js';
import { calculateRiskScore } from '../utils/riskScoring.js';

let mockImageOcrHandler = null;
let mockQrDecoderHandler = null;

export function setMockImageOcrHandler(handler) {
  mockImageOcrHandler = handler;
}

export function setMockQrDecoderHandler(handler) {
  mockQrDecoderHandler = handler;
}

const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_PIXELS = 16 * 1000 * 1000; // 16 Megapixels (4000x4000)
const ALLOWED_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);

/**
 * Validates uploaded image file buffer and metadata.
 */
export function validateImageUpload(file) {
  if (!file || !file.buffer) {
    throw new Error('No image file provided.');
  }

  if (file.size > MAX_IMAGE_SIZE_BYTES) {
    throw new Error(`File size exceeds maximum allowed limit of ${MAX_IMAGE_SIZE_BYTES / (1024 * 1024)}MB.`);
  }

  const mime = (file.mimetype || '').toLowerCase();
  if (!ALLOWED_MIME_TYPES.has(mime)) {
    throw new Error(`Unsupported image format "${mime}". Allowed formats: PNG, JPEG, WebP.`);
  }

  return true;
}

/**
 * Decodes QR code from raw image buffer using pure JavaScript decoders.
 * Runs completely locally on the server without calling external services.
 *
 * @param {Buffer} buffer
 * @param {string} mimeType
 * @returns {{ detected: boolean, payload: string|null, type: string, upiDetails: object|null, url: string|null, error: string|null }}
 */
export function decodeQrCodeLocally(buffer, mimeType) {
  if (mockQrDecoderHandler) {
    return mockQrDecoderHandler(buffer, mimeType);
  }

  try {
    let width = 0;
    let height = 0;
    let rgbaData = null;

    if (mimeType === 'image/png') {
      const png = PNG.sync.read(buffer);
      width = png.width;
      height = png.height;
      rgbaData = png.data;
    } else if (mimeType === 'image/jpeg' || mimeType === 'image/jpg') {
      const decoded = jpeg.decode(buffer, { useTArray: true });
      width = decoded.width;
      height = decoded.height;
      rgbaData = decoded.data;
    } else {
      // For formats without raw pixel decoding, QR extraction is skipped
      return {
        detected: false,
        payload: null,
        type: 'none',
        upiDetails: null,
        url: null,
        error: null,
        message: 'Direct QR decoding is supported for PNG and JPEG formats.',
      };
    }

    if (width * height > MAX_PIXELS) {
      return {
        detected: false,
        payload: null,
        type: 'none',
        upiDetails: null,
        url: null,
        error: 'DECOMPRESSION_LIMIT_EXCEEDED',
        message: 'Image dimensions exceed safety limits.',
      };
    }

    const qrResult = jsQR(new Uint8ClampedArray(rgbaData), width, height);
    if (!qrResult || !qrResult.data) {
      return {
        detected: false,
        payload: null,
        type: 'none',
        upiDetails: null,
        url: null,
        error: null,
        message: 'No QR code pattern detected in the image.',
      };
    }

    const payload = qrResult.data.trim();

    // Check if QR code is a UPI payment URI
    if (/^upi:\/\/pay\?/i.test(payload)) {
      try {
        const parsedUpi = new URL(payload);
        const params = parsedUpi.searchParams;
        const pa = params.get('pa') || '';
        const pn = params.get('pn') || '';
        const am = params.get('am') || null;
        const cu = params.get('cu') || 'INR';
        const tn = params.get('tn') || '';

        return {
          detected: true,
          payload,
          type: 'upi',
          upiDetails: {
            payeeAddress: pa,
            payeeName: pn,
            amount: am,
            currency: cu,
            note: tn,
            isPaymentRequest: true,
            securityAdvisory:
              'Warning: Scanning this QR code initiates an OUTGOING PAYMENT from your account. In Indian banking (UPI), QR codes are used ONLY to SEND money. Scanning a QR code will NEVER credit money or deposit a refund/lottery prize into your account.',
          },
          url: null,
          error: null,
          message: 'UPI payment QR code detected.',
        };
      } catch {
        // Fallback if UPI URL parsing fails
      }
    }

    // Check if QR code contains a Web URL
    if (/^https?:\/\//i.test(payload)) {
      return {
        detected: true,
        payload,
        type: 'url',
        upiDetails: null,
        url: payload,
        error: null,
        message: 'Website URL detected in QR code.',
      };
    }

    // Generic text QR code
    return {
      detected: true,
      payload,
      type: 'text',
      upiDetails: null,
      url: null,
      error: null,
      message: 'Text payload detected in QR code.',
    };
  } catch (err) {
    return {
      detected: false,
      payload: null,
      type: 'none',
      upiDetails: null,
      url: null,
      error: err.message,
      message: 'Failed to parse image for QR code decoding.',
    };
  }
}

/**
 * Extracts visible text, message content, and URLs from an image using Gemini Multimodal Vision.
 *
 * @param {Buffer} buffer
 * @param {string} mimeType
 * @param {'en' | 'hi'} language
 * @returns {Promise<{ status: string, extractedText: string, detectedUrls: string[], detectedPhones: string[], confidence: string, details: string }>}
 */
export async function extractTextWithOcr(buffer, mimeType, language = 'en') {
  if (mockImageOcrHandler) {
    return mockImageOcrHandler(buffer, mimeType, language);
  }

  if (!env.AI_ENABLED || !env.GEMINI_API_KEY) {
    return {
      status: 'not_configured',
      extractedText: '',
      detectedUrls: [],
      detectedPhones: [],
      confidence: 'none',
      details: 'Gemini AI Vision OCR is not configured in the server environment.',
    };
  }

  try {
    const ai = new GoogleGenAI({ apiKey: env.GEMINI_API_KEY });
    const base64Data = buffer.toString('base64');

    const prompt = `You are a cybersecurity OCR specialist. Extract all visible text, messages, URLs, links, and phone numbers from this screenshot.
Respond strictly in JSON format matching this schema:
{
  "extractedText": "full plain text of the message or page",
  "urls": ["any extracted URLs or domain names"],
  "phoneNumbers": ["any extracted phone numbers"],
  "hasLegibleText": true or false
}
If there is no legible text or the image is blank, return empty string for extractedText and hasLegibleText: false.`;

    const modelName = env.GEMINI_MODEL || 'gemini-3.8-flash';
    const response = await ai.models.generateContent({
      model: modelName,
      contents: [
        {
          role: 'user',
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType,
                data: base64Data,
              },
            },
          ],
        },
      ],
      config: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    });

    const candidate = response?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!candidate) {
      return {
        status: 'no_text_detected',
        extractedText: '',
        detectedUrls: [],
        detectedPhones: [],
        confidence: 'low',
        details: 'No legible text was detected in the provided image.',
      };
    }

    let parsed;
    try {
      parsed = JSON.parse(candidate);
    } catch {
      return {
        status: 'no_text_detected',
        extractedText: candidate.trim(),
        detectedUrls: [],
        detectedPhones: [],
        confidence: 'medium',
        details: 'Text extracted without structured metadata.',
      };
    }

    const text = (parsed.extractedText || '').trim();
    if (!text || parsed.hasLegibleText === false) {
      return {
        status: 'no_text_detected',
        extractedText: '',
        detectedUrls: [],
        detectedPhones: [],
        confidence: 'low',
        details: 'No legible text detected in the image.',
      };
    }

    return {
      status: 'completed',
      extractedText: text,
      detectedUrls: Array.isArray(parsed.urls) ? parsed.urls : [],
      detectedPhones: Array.isArray(parsed.phoneNumbers) ? parsed.phoneNumbers : [],
      confidence: 'high',
      details: 'Text successfully extracted via vision analysis.',
    };
  } catch (err) {
    console.warn('[ImageScanner] OCR Vision error:', err.message);
    return {
      status: 'error',
      extractedText: '',
      detectedUrls: [],
      detectedPhones: [],
      confidence: 'none',
      details: `OCR processing failed: ${err.message}`,
    };
  }
}

/**
 * Executes full evidence investigation on an uploaded screenshot or QR code.
 *
 * @param {object} file - Uploaded file from multer ({ buffer, mimetype, size, originalname })
 * @param {'en' | 'hi'} language
 * @returns {Promise<object>} Complete image scan report
 */
export async function scanImageUpload(file, language = 'en') {
  validateImageUpload(file);

  const mimeType = file.mimetype.toLowerCase();
  const buffer = file.buffer;

  // 1. Decode QR code locally (pure JS)
  const qrResult = decodeQrCodeLocally(buffer, mimeType);

  // 2. Perform OCR text extraction
  const ocrResult = await extractTextWithOcr(buffer, mimeType, language);

  // 3. Aggregate extracted URLs
  const candidateUrls = new Set();
  if (qrResult.detected && qrResult.url) {
    candidateUrls.add(qrResult.url);
  }
  const ocrUrls = ocrResult.detectedUrls || ocrResult.extractedUrls || [];
  if (Array.isArray(ocrUrls)) {
    for (const u of ocrUrls) {
      if (u && typeof u === 'string' && u.trim().length > 3) {
        candidateUrls.add(u.trim());
      }
    }
  }

  // 4. Run extracted URLs through the real website intelligence pipeline
  const urlScans = [];
  for (const rawTarget of candidateUrls) {
    try {
      const formattedUrl = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
      const urlReport = await runWebsiteInvestigation(formattedUrl);
      urlScans.push({
        url: rawTarget,
        normalizedUrl: urlReport.normalizedUrl.full,
        hostname: urlReport.hostname,
        verdict: urlReport.verdict,
        verdictCanonical: urlReport.verdictCanonical || (urlReport.verdict === 'known_threat' ? 'MALICIOUS' : 'UNKNOWN'),
        riskScore: urlReport.riskScore,
        verificationStatus: urlReport.verificationStatus,
        indicators: urlReport.indicators,
        safetyAdvice: urlReport.safetyAdvice,
      });
    } catch (urlErr) {
      urlScans.push({
        url: rawTarget,
        error: urlErr.message,
        verdict: 'scan_unavailable',
        verdictCanonical: 'UNKNOWN',
        riskScore: null,
      });
    }
  }

  // 5. Run extracted text through message scam detection pipeline
  let messageAnalysis = null;
  if (ocrResult.extractedText && ocrResult.extractedText.length > 5) {
    const text = ocrResult.extractedText;
    const entities = extractEntities(text);
    const ruleThreatIndicators = evaluateScamRules(text, entities, language);
    const { riskScore, riskLevel } = calculateRiskScore(ruleThreatIndicators, entities);
    const scamType = determineScamType(ruleThreatIndicators);
    const safetyAdvice = generateSafetyAdvice(ruleThreatIndicators, entities, language);

    messageAnalysis = {
      extractedText: text,
      entities,
      threatIndicators: ruleThreatIndicators,
      riskScore,
      riskLevel,
      scamType,
      safetyAdvice,
    };
  }

  // 6. Compute overall unified verdict
  let overallVerdict = 'UNKNOWN';
  let overallRiskScore = null;
  let summary = '';

  const hasMaliciousUrl = urlScans.some((u) => u.verdict === 'known_threat' || u.verdictCanonical === 'MALICIOUS');
  const hasSuspiciousUrl = urlScans.some((u) => u.verdict === 'high_risk' || u.verdict === 'suspicious' || u.verdictCanonical === 'SUSPICIOUS');
  const hasCriticalMessageScam = messageAnalysis && (messageAnalysis.riskLevel === 'very_high' || messageAnalysis.riskLevel === 'high');
  const isUpiCollectTrap = qrResult.detected && qrResult.type === 'upi';

  if (hasMaliciousUrl || hasCriticalMessageScam) {
    overallVerdict = 'MALICIOUS';
    overallRiskScore = 90;
    summary =
      language === 'hi'
        ? 'स्क्रीनशॉट में उच्च जोखिम धोखाधड़ी या दुर्भावनापूर्ण वेबसाइट पाई गई है।'
        : 'Confirmed critical threat or scam pattern detected in the uploaded image.';
  } else if (hasSuspiciousUrl || isUpiCollectTrap || (messageAnalysis && messageAnalysis.threatIndicators.length > 0)) {
    overallVerdict = 'SUSPICIOUS';
    overallRiskScore = isUpiCollectTrap ? 65 : (messageAnalysis?.riskScore || 50);
    summary = isUpiCollectTrap
      ? (language === 'hi'
          ? 'यूपीआई भुगतान क्यूआर कोड पाया गया। सावधान: क्यूआर कोड स्कैन करने से पैसे कटते हैं, मिलते नहीं।'
          : 'UPI payment QR code detected. Warning: Scanning a QR code debits money from your account, never credits it.')
      : (language === 'hi'
          ? 'स्क्रीनशॉट में संदिग्ध चेतावनी संकेतक पाए गए हैं।'
          : 'Suspicious indicators detected in the screenshot contents.');
  } else if (urlScans.length > 0 && urlScans.every((u) => u.verdictCanonical === 'SAFE_NO_THREAT_FOUND')) {
    overallVerdict = 'SAFE_NO_THREAT_FOUND';
    overallRiskScore = 0;
    summary =
      language === 'hi'
        ? 'छवि में केवल सत्यापित आधिकारिक लिंक पाए गए।'
        : 'Only recognized authoritative domain links detected with clean indicators.';
  } else {
    overallVerdict = 'UNKNOWN';
    overallRiskScore = null;
    summary =
      language === 'hi'
        ? 'अपर्याप्त साक्ष्य — छवि में कोई ज्ञात दुर्भावनापूर्ण पैटर्न या क्यूआर लिंक नहीं मिला।'
        : 'Unable to verify safety — insufficient evidence or no malicious patterns identified.';
  }

  return {
    imageInfo: {
      fileName: file.originalname || 'uploaded_image',
      mimeType,
      sizeBytes: file.size,
    },
    qrCode: qrResult,
    ocr: ocrResult,
    messageAnalysis,
    urlScans,
    overallVerdict,
    overallRiskScore,
    summary,
    privacyNotice: 'Analyzed in volatile memory. Uploaded images are never permanently saved or shared.',
    analyzedAt: new Date().toISOString(),
  };
}
