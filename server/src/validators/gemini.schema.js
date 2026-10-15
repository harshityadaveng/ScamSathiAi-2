import { z } from 'zod';

export const SCAM_TYPES = [
  'utility_disconnection',
  'banking_kyc',
  'digital_arrest',
  'credential_harvesting',
  'malicious_software',
  'job_fraud',
  'lottery_reward',
  'loan_fraud',
  'impersonation',
  'urgency_coercion',
  'unknown',
  'none_detected',
];

export const RISK_LEVELS = ['low', 'caution', 'high', 'very_high'];
export const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export const geminiThreatIndicatorSchema = z.object({
  category: z.string().trim().min(1).max(100),
  severity: z.enum(SEVERITIES),
  evidence: z.string().trim().min(1).max(500),
});

export const geminiAnalysisSchema = z.object({
  scamType: z.enum(SCAM_TYPES),
  riskAssessment: z.enum(RISK_LEVELS),
  summary: z.string().trim().min(3).max(1000),
  threatIndicators: z.array(geminiThreatIndicatorSchema).default([]),
  safetyAdvice: z.array(z.string().trim().min(3).max(500)).default([]),
});

/**
 * Standard JSON schema object compatible with Google Gen AI SDK responseSchema
 */
export const geminiJsonSchema = {
  type: 'object',
  properties: {
    scamType: {
      type: 'string',
      enum: SCAM_TYPES,
      description: 'The classified scam pattern or none_detected / unknown if clean or unclear.',
    },
    riskAssessment: {
      type: 'string',
      enum: RISK_LEVELS,
      description: 'The qualitative risk assessment: low, caution, high, or very_high.',
    },
    summary: {
      type: 'string',
      description: 'Clear, concise explanation of findings in the requested language (English or Hindi).',
    },
    threatIndicators: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          category: { type: 'string' },
          severity: { type: 'string', enum: SEVERITIES },
          evidence: { type: 'string', description: 'Specific evidence found in the text.' },
        },
        required: ['category', 'severity', 'evidence'],
      },
    },
    safetyAdvice: {
      type: 'array',
      items: { type: 'string' },
      description: 'Practical, actionable safety tips in the requested language.',
    },
  },
  required: ['scamType', 'riskAssessment', 'summary', 'threatIndicators', 'safetyAdvice'],
};

export const URL_RISK_ASSESSMENTS = ['low', 'caution', 'suspicious', 'high', 'unknown'];

export const geminiUrlAnalysisSchema = z.object({
  summary: z.string().trim().min(3).max(1000),
  verdictExplanation: z.string().trim().min(3).max(1000),
  riskAssessment: z.enum(URL_RISK_ASSESSMENTS),
  threatExplanations: z
    .array(
      z.object({
        category: z.string().trim().min(1).max(100),
        explanation: z.string().trim().min(1).max(500),
      })
    )
    .default([]),
  safetyAdvice: z.array(z.string().trim().min(3).max(500)).default([]),
});

export const geminiUrlJsonSchema = {
  type: 'object',
  properties: {
    summary: {
      type: 'string',
      description: 'Concise summary of website safety findings in the requested language (English or Hindi).',
    },
    verdictExplanation: {
      type: 'string',
      description: 'Clear explanation of the safety assessment strictly tied to supplied indicators.',
    },
    riskAssessment: {
      type: 'string',
      enum: URL_RISK_ASSESSMENTS,
      description: 'Qualitative risk assessment: low, caution, suspicious, high, or unknown.',
    },
    threatExplanations: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          category: { type: 'string' },
          explanation: { type: 'string' },
        },
        required: ['category', 'explanation'],
      },
    },
    safetyAdvice: {
      type: 'array',
      items: { type: 'string' },
      description: 'Actionable guidance for the user in the requested language.',
    },
  },
  required: ['summary', 'verdictExplanation', 'riskAssessment', 'threatExplanations', 'safetyAdvice'],
};

