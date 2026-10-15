/**
 * ScamSathi AI - Frontend API Client Service
 * Connects React Frontend to the Express + Gemini Backend with robust timeout and status handling.
 */

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
const DEFAULT_TIMEOUT_MS = 25000;

/**
 * Fetch wrapper with AbortController timeout and friendly network error messages
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return res;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Analysis request timed out. Please try again.');
    }
    if (err instanceof TypeError && err.message?.includes('Failed to fetch')) {
      throw new Error('Could not connect to ScamSathi backend. Please ensure the server is running and try again.');
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Checks server health and Gemini AI status
 * @returns {Promise<{ online: boolean, message: string, timestamp?: string }>}
 */
export async function checkServerHealth() {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    }, 6000);
    if (!res.ok) return { online: false, message: `HTTP ${res.status}` };
    const data = await res.json().catch(() => ({}));
    return { online: true, message: data.message || 'OK', timestamp: data.timestamp };
  } catch (err) {
    return { online: false, message: err.message || 'Network Error' };
  }
}

/**
 * Analyzes a suspicious text message using Gemini AI & rule engine
 * @param {string} content - Raw user message or SMS
 * @param {'en' | 'hi'} language - Preferred response language
 * @returns {Promise<object>} Analysis payload
 */
export async function analyzeMessage(content, language = 'en') {
  const response = await fetchWithTimeout(`${API_BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      content: content.trim(),
      language,
      inputType: 'message',
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    if (response.status === 429) {
      throw new Error(errorData.message || 'Rate limit or AI quota reached. Please wait a moment and retry.');
    }
    if (response.status >= 500) {
      throw new Error(errorData.message || 'Server encountered an internal error. Please try again.');
    }
    throw new Error(errorData.message || `Analysis request failed (HTTP ${response.status})`);
  }

  const json = await response.json().catch(() => null);
  if (!json || !json.success || !json.analysis) {
    throw new Error('Received malformed response from ScamSathi backend.');
  }

  return json.analysis;
}

/**
 * Scans a URL for phishing, brand lookalikes, and scam indicators
 * @param {string} url - Target URL to inspect
 * @returns {Promise<object>} URL risk analysis payload
 */
export async function checkUrlRisk(url) {
  const formattedUrl = /^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;

  const response = await fetchWithTimeout(`${API_BASE_URL}/api/check-url`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      url: formattedUrl,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    if (response.status === 429) {
      throw new Error(errorData.message || 'Rate limit reached. Please wait a moment and retry.');
    }
    if (response.status >= 500) {
      throw new Error(errorData.message || 'Server encountered an internal error during website inspection.');
    }
    throw new Error(errorData.message || `URL check failed (HTTP ${response.status})`);
  }

  const json = await response.json().catch(() => null);
  if (!json || !json.success || !json.analysis) {
    throw new Error('Received malformed response from ScamSathi backend.');
  }

  return json.analysis;
}

/**
 * Scans an uploaded screenshot, image, or QR code
 * @param {File} file - Image file (PNG, JPEG, WebP)
 * @param {'en' | 'hi'} language - Preferred language
 * @returns {Promise<object>} Image and QR risk analysis payload
 */
export async function scanImageFile(file, language = 'en') {
  const formData = new FormData();
  formData.append('image', file);
  formData.append('language', language);

  const response = await fetchWithTimeout(`${API_BASE_URL}/api/scan-image`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    if (response.status === 429) {
      throw new Error(errorData.message || 'Rate limit reached. Please wait a moment and retry.');
    }
    if (response.status >= 500) {
      throw new Error(errorData.message || 'Server encountered an internal error during image inspection.');
    }
    throw new Error(errorData.message || `Image scan failed (HTTP ${response.status})`);
  }

  const json = await response.json().catch(() => null);
  if (!json || !json.success || !json.analysis) {
    throw new Error('Received malformed response from ScamSathi backend.');
  }

  return json.analysis;
}
