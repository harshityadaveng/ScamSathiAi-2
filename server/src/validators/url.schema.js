import { z } from 'zod';

export const checkUrlRequestSchema = z.object({
  url: z
    .string({
      required_error: 'URL is required',
      invalid_type_error: 'URL must be a string',
    })
    .trim()
    .min(1, { message: 'URL cannot be empty' })
    .max(2048, { message: 'URL length cannot exceed 2048 characters' })
    .transform((val) => {
      // If user provided a domain/URL without protocol, e.g. "google.com" or "amazon.in"
      if (!val.includes('://') && /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/.*)?$/i.test(val)) {
        return `https://${val}`;
      }
      return val;
    })
    .refine(
      (val) => {
        // Disallow dangerous or unsupported URI schemes
        const lower = val.toLowerCase();
        if (
          lower.startsWith('javascript:') ||
          lower.startsWith('data:') ||
          lower.startsWith('file:') ||
          lower.startsWith('ftp:') ||
          lower.startsWith('vbscript:')
        ) {
          return false;
        }

        try {
          const parsed = new URL(val);
          // Only permit http: and https: protocols
          return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch {
          return false;
        }
      },
      {
        message: 'Must be a valid, absolute HTTP or HTTPS URL (e.g. https://example.com)',
      }
    ),
  language: z.enum(['en', 'hi']).optional().default('en'),
});

