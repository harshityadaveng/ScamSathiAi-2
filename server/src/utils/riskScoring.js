/**
 * Risk Scoring Engine
 * Computes a transparent, heuristic risk score (0-100) based on triggered rule severities.
 *
 * Scoring Scale:
 *   0-24:   'low'
 *   25-49:  'caution'
 *   50-74:  'high'
 *   75-100: 'very_high'
 */

export const SEVERITY_WEIGHTS = {
  critical: 55,
  high: 35,
  medium: 20,
  low: 10,
};

/**
 * Maps a numeric score (0-100) to its standardized risk level.
 * @param {number} score
 * @returns {'low' | 'caution' | 'high' | 'very_high'}
 */
export function getRiskLevel(score) {
  if (score >= 75) return 'very_high';
  if (score >= 50) return 'high';
  if (score >= 25) return 'caution';
  return 'low';
}

/**
 * Calculates the overall risk score from triggered indicators and extracted entities.
 * Avoids duplicate indicator inflation and caps the score at 100.
 *
 * @param {Array<{ severity: string, ruleId: string }>} triggeredRules
 * @param {{ urls: string[], phoneNumbers: string[], upiIds: string[] }} entities
 * @returns {{ riskScore: number, riskLevel: 'low' | 'caution' | 'high' | 'very_high' }}
 */
export function calculateRiskScore(triggeredRules = [], entities = { urls: [], phoneNumbers: [], upiIds: [] }) {
  if (!triggeredRules || triggeredRules.length === 0) {
    return { riskScore: 0, riskLevel: 'low' };
  }

  // Deduplicate rules by ruleId to avoid duplicate counting
  const uniqueRules = new Map();
  for (const rule of triggeredRules) {
    if (!uniqueRules.has(rule.ruleId)) {
      uniqueRules.set(rule.ruleId, rule);
    }
  }

  let totalPoints = 0;
  let hasCriticalOrHigh = false;

  for (const rule of uniqueRules.values()) {
    const weight = SEVERITY_WEIGHTS[rule.severity] || SEVERITY_WEIGHTS.low;
    totalPoints += weight;
    if (rule.severity === 'critical' || rule.severity === 'high') {
      hasCriticalOrHigh = true;
    }
  }

  // Synergistic Boost: If high-severity coercion is combined with an action vehicle (URL, Phone, or UPI)
  if (hasCriticalOrHigh) {
    if (entities.urls && entities.urls.length > 0) {
      totalPoints += 8; // Contains actionable link
    }
    if (entities.phoneNumbers && entities.phoneNumbers.length > 0) {
      totalPoints += 5; // Contains callback number
    }
    if (entities.upiIds && entities.upiIds.length > 0) {
      totalPoints += 8; // Contains direct payment handle
    }
  }

  // Clamp score strictly between 0 and 100
  const finalScore = Math.min(100, Math.max(0, Math.round(totalPoints)));
  const riskLevel = getRiskLevel(finalScore);

  return {
    riskScore: finalScore,
    riskLevel,
  };
}
