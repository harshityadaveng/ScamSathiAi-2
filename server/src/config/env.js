import dotenv from 'dotenv';
import { z } from 'zod';

// Load variables from .env file
dotenv.config();

const envSchema = z.object({
  PORT: z
    .string()
    .default('5000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0 && val <= 65535, {
      message: 'PORT must be a valid port number between 1 and 65535',
    }),
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  CLIENT_URL: z
    .string()
    .url({ message: 'CLIENT_URL must be a valid URL (e.g. http://localhost:5173)' })
    .default('http://localhost:5173'),
  RATE_LIMIT_WINDOW_MS: z
    .string()
    .default('60000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'RATE_LIMIT_WINDOW_MS must be a positive number',
    }),
  RATE_LIMIT_MAX_REQUESTS: z
    .string()
    .default('30')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'RATE_LIMIT_MAX_REQUESTS must be a positive number',
    }),
  GEMINI_API_KEY: z.string().optional().default(''),
  GEMINI_MODEL: z.string().default('gemini-3.8-flash'),
  GEMINI_TIMEOUT_MS: z
    .string()
    .default('15000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'GEMINI_TIMEOUT_MS must be a positive number',
    }),
  AI_ENABLED: z
    .string()
    .default('true')
    .transform((val) => val.toLowerCase() === 'true' || val === '1'),
  URL_REPUTATION_PROVIDER: z
    .enum(['none', 'safebrowsing', 'virustotal', 'google_safe_browsing', 'webrisk', 'google_web_risk'])
    .default('none'),
  GOOGLE_WEB_RISK_API_KEY: z.string().optional().default(''),
  WEB_RISK_TIMEOUT_MS: z
    .string()
    .default('5000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'WEB_RISK_TIMEOUT_MS must be a positive number',
    }),
  GOOGLE_SAFE_BROWSING_API_KEY: z.string().optional().default(''),
  SAFE_BROWSING_TIMEOUT_MS: z
    .string()
    .default('5000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'SAFE_BROWSING_TIMEOUT_MS must be a positive number',
    }),
  VIRUSTOTAL_API_KEY: z.string().optional().default(''),
  VIRUSTOTAL_TIMEOUT_MS: z
    .string()
    .default('5000')
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val > 0, {
      message: 'VIRUSTOTAL_TIMEOUT_MS must be a positive number',
    }),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment variables configuration:');
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1);
}

export const env = parsed.data;
