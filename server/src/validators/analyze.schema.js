import { z } from 'zod';

export const analyzeRequestSchema = z.object({
  content: z
    .string({
      required_error: 'Content is required',
      invalid_type_error: 'Content must be a string',
    })
    .trim()
    .min(1, { message: 'Content cannot be empty' })
    .max(10000, { message: 'Content cannot exceed 10,000 characters' }),
  language: z
    .enum(['en', 'hi'], {
      invalid_type_error: "Language must be either 'en' or 'hi'",
    })
    .default('en'),
  inputType: z
    .enum(['message', 'url', 'phone'], {
      invalid_type_error: "Input type must be 'message', 'url', or 'phone'",
    })
    .default('message'),
  sender: z
    .string({ invalid_type_error: 'Sender must be a string' })
    .trim()
    .max(100, { message: 'Sender cannot exceed 100 characters' })
    .optional()
    .nullable()
    .default(null),
});

/**
 * Middleware factory for validating request bodies against Zod schemas.
 */
export function validateBody(schema) {
  return (req, res, next) => {
    // Check if body exists
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request payload. Expected a JSON object.',
        timestamp: new Date().toISOString(),
      });
    }

    const result = schema.safeParse(req.body);

    if (!result.success) {
      const formattedErrors = result.error.errors.map((err) => ({
        field: err.path.join('.'),
        message: err.message,
      }));

      return res.status(400).json({
        success: false,
        message: 'Request validation failed',
        errors: formattedErrors,
        timestamp: new Date().toISOString(),
      });
    }

    // Assign sanitized & defaulted values back to req.body
    req.body = result.data;
    next();
  };
}
