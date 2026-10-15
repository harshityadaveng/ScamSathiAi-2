import { scanImageUpload } from '../services/imageScanner.service.js';

/**
 * Controller for POST /api/scan-image
 * Inspects uploaded screenshots, images, and QR codes for fraud indicators.
 */
export async function scanImage(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No image file provided for scanning.',
      });
    }

    const language = req.body?.language || 'en';
    const report = await scanImageUpload(req.file, language);

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      analysis: report,
    });
  } catch (err) {
    if (
      err.code === 'LIMIT_FILE_SIZE' ||
      err.message?.includes('exceeds maximum allowed limit') ||
      err.message?.includes('File size exceeds')
    ) {
      return res.status(400).json({
        success: false,
        message: 'Image size exceeds maximum limit of 5MB.',
      });
    }

    if (
      err.message?.includes('Unsupported image format') ||
      err.message?.includes('INVALID_MIME_TYPE')
    ) {
      return res.status(400).json({
        success: false,
        message: err.message,
      });
    }

    next(err);
  }
}
