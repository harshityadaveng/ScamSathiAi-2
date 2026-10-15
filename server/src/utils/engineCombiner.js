import { calculateRiskScore } from './riskScoring.js';

/**
 * Combines rule-based detection results with Gemini AI analysis.
 *
 * Combination Principles:
 * 1. Independent Evidence Pools: Rules and AI provide separate inputs.
 * 2. Non-Suppression: Gemini cannot erase or downgrade a rule-based high/critical threat.
 * 3. Deduplication: Overlapping indicators by category are unified to prevent score inflation.
 * 4. Deterministic Scoring: Recalculates risk score using unified deduplicated indicators.
 * 5. Transparent Engine Label: Distinguishes 'gemini+rules_v1' from 'rules_v1_fallback'.
 *
 * @param {object} ruleResults - Output from rule-based scamDetection.service
 * @param {object | null} aiResults - Output from gemini.service (if successful)
 * @param {string | null} aiErrorReason - Reason if Gemini failed
 * @param {object} entities - Extracted URLs, phones, UPIs
 * @param {'en' | 'hi'} language
 * @returns {object} Final unified analysis object
 */
export function combineEngineResults(ruleResults, aiResults, aiErrorReason, entities, language = 'en') {
  // If Gemini was unavailable, failed, timed out, or disabled: use pure rule-based fallback
  if (!aiResults) {
    const isExplicitlyDisabled = aiErrorReason === 'AI_DISABLED';
    return {
      riskScore: ruleResults.riskScore,
      riskLevel: ruleResults.riskLevel,
      scamType: ruleResults.scamType,
      summary: ruleResults.summary,
      threatIndicators: ruleResults.threatIndicators,
      entities,
      safetyAdvice: ruleResults.safetyAdvice,
      engine: isExplicitlyDisabled ? 'rules_v1' : 'rules_v1_fallback',
    };
  }

  // 1. Deduplicate & Combine Threat Indicators
  const combinedIndicators = [...ruleResults.threatIndicators];
  const existingCategories = new Set(ruleResults.threatIndicators.map((i) => i.category.toLowerCase()));

  for (const aiIndicator of aiResults.threatIndicators || []) {
    const catLower = aiIndicator.category.toLowerCase();
    if (!existingCategories.has(catLower)) {
      // Novel contextual indicator from AI
      combinedIndicators.push({
        ruleId: `AI_${aiIndicator.category.toUpperCase().replace(/\s+/g, '_')}`,
        category: aiIndicator.category,
        severity: aiIndicator.severity,
        evidence: aiIndicator.evidence,
      });
      existingCategories.add(catLower);
    }
  }

  // 2. Deterministic Scoring from unified evidence pool
  const { riskScore: combinedScore, riskLevel: combinedLevel } = calculateRiskScore(
    combinedIndicators,
    entities
  );

  // Guarantee that rules baseline is preserved: never drop below rule score
  const finalScore = Math.max(ruleResults.riskScore, combinedScore);
  const finalLevel = finalScore >= 75 ? 'very_high' : finalScore >= 50 ? 'high' : finalScore >= 25 ? 'caution' : 'low';

  // 3. Resolve Scam Type
  let finalScamType = ruleResults.scamType;
  if (ruleResults.scamType === 'none_detected' && aiResults.scamType && aiResults.scamType !== 'none_detected' && aiResults.scamType !== 'unknown') {
    finalScamType = aiResults.scamType;
  }

  // 4. Resolve Summary (prefer AI summary if contextual and valid, fallback to rules summary)
  const finalSummary = aiResults.summary || ruleResults.summary;

  // 5. Combine & Deduplicate Safety Advice
  const adviceSet = new Set(ruleResults.safetyAdvice || []);
  for (const item of aiResults.safetyAdvice || []) {
    if (item && item.trim().length > 5) {
      adviceSet.add(item.trim());
    }
  }

  return {
    riskScore: finalScore,
    riskLevel: finalLevel,
    scamType: finalScamType,
    summary: finalSummary,
    threatIndicators: combinedIndicators,
    entities,
    safetyAdvice: Array.from(adviceSet),
    engine: 'gemini+rules_v1',
  };
}
