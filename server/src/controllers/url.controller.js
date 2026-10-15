import { runWebsiteInvestigation } from '../services/websiteIntelPipeline.service.js';
import { analyzeUrlWithGemini } from '../services/gemini.service.js';
import { env } from '../config/env.js';

/**
 * Controller for POST /api/check-url
 * Executes the real evidence-based website intelligence pipeline:
 * - Domain registration intelligence (RDAP)
 * - DNS intelligence (A, AAAA, MX, NS records with SSRF guard)
 * - TLS certificate inspection (issuer, validity, expiration)
 * - Real URL reputation (Google Safe Browsing v4)
 * - Lookalike and brand impersonation heuristics
 * - Contextual evidence explanation via Gemini AI
 */
export async function checkUrl(req, res, next) {
  try {
    const { url, language = 'en' } = req.body;

    // 1. Run real multi-signal website investigation pipeline
    const pipelineResult = await runWebsiteInvestigation(url);

    // 2. Prepare evidence summary for Gemini (passing ONLY real collected data)
    const aiEvidenceContext = {
      normalizedUrl: pipelineResult.normalizedUrl.full,
      hostname: pipelineResult.hostname,
      registeredDomain: pipelineResult.normalizedUrl.registeredDomain,
      indicators: pipelineResult.indicators,
      riskScore: pipelineResult.riskScore,
      reputation: pipelineResult.checks.reputation,
      verificationStatus: pipelineResult.verificationStatus,
      checksSummary: {
        reputationStatus: pipelineResult.checks.reputation.reputationStatus,
        domainAgeDays: pipelineResult.checks.rdap.data?.ageDays ?? null,
        registrar: pipelineResult.checks.rdap.data?.registrar ?? null,
        dnsResolvedIps: pipelineResult.checks.dns.data?.resolvedIps?.length ?? 0,
        hasMx: pipelineResult.checks.dns.data?.hasMx ?? false,
        tlsIssuer: pipelineResult.checks.tls.data?.issuer ?? null,
        tlsValid: pipelineResult.checks.tls.data?.authorized ?? null,
      },
    };

    // 3. Run evidence-based Gemini analysis
    const aiResult = await analyzeUrlWithGemini(aiEvidenceContext, language);

    let summary = '';
    let verdictExplanation = '';
    let finalEngine = pipelineResult.engine;
    let aiAnalysis = null;
    let combinedSafetyAdvice = [...pipelineResult.safetyAdvice];

    if (aiResult.success && aiResult.data) {
      summary = aiResult.data.summary;
      verdictExplanation = aiResult.data.verdictExplanation;
      finalEngine = `gemini+${pipelineResult.engine}`;

      aiAnalysis = {
        status: 'completed',
        engine: env.GEMINI_MODEL,
        summary: aiResult.data.summary,
        verdictExplanation: aiResult.data.verdictExplanation,
        riskAssessment: aiResult.data.riskAssessment,
        threatExplanations: aiResult.data.threatExplanations || [],
      };

      // Strip unsupported marketing phrases from AI output
      summary = summary
        .replace(/100%\s*(real|safe)/gi, 'no known threat detected')
        .replace(/verified\s*safe/gi, 'low risk indicators')
        .replace(/guaranteed\s*legitimate/gi, 'unflagged')
        .replace(/authentic\s*website/gi, 'established domain');

      verdictExplanation = verdictExplanation
        .replace(/100%\s*(real|safe)/gi, 'no known threat detected')
        .replace(/verified\s*safe/gi, 'low risk indicators')
        .replace(/guaranteed\s*legitimate/gi, 'unflagged')
        .replace(/authentic\s*website/gi, 'established domain');

      // Guard: Confirmed threat cannot be overridden by Gemini
      if (
        pipelineResult.verificationStatus === 'threat_detected' ||
        pipelineResult.checks.reputation.reputationStatus === 'confirmed_threat'
      ) {
        if (
          aiResult.data.riskAssessment === 'low' ||
          aiResult.data.riskAssessment === 'caution' ||
          aiResult.data.riskAssessment === 'unknown'
        ) {
          aiResult.data.riskAssessment = 'high';
          aiAnalysis.riskAssessment = 'high';
        }
      }

      // If risk score is null due to insufficient evidence, ensure explanation reflects this
      if (pipelineResult.riskScore === null) {
        const notice =
          language === 'hi'
            ? 'जोखिम स्कोर अनुपलब्ध — अपर्याप्त साक्ष्य।'
            : 'Risk score unavailable — insufficient evidence.';
        if (!verdictExplanation.includes('Risk score unavailable')) {
          verdictExplanation = `${notice} ${verdictExplanation}`;
        }
      }

      // Prepend Gemini safety tips
      if (Array.isArray(aiResult.data.safetyAdvice) && aiResult.data.safetyAdvice.length > 0) {
        combinedSafetyAdvice = [...aiResult.data.safetyAdvice, ...combinedSafetyAdvice];
      }
    } else {
      // Deterministic rule fallback summary based on actual evidence
      finalEngine = pipelineResult.engine;
      aiAnalysis = {
        status: 'fallback',
        engine: pipelineResult.engine,
        errorReason: aiResult.errorReason,
      };

      if (pipelineResult.verificationStatus === 'threat_detected') {
        const topIndicator = pipelineResult.indicators[0];
        summary =
          language === 'hi'
            ? `वेबसाइट "${pipelineResult.hostname}" में गंभीर सुरक्षा खतरा पाया गया है (${topIndicator?.description || 'Threat detected'})।`
            : `Critical security threat detected for "${pipelineResult.hostname}": ${topIndicator?.description || 'Threat detected'}`;
        verdictExplanation =
          language === 'hi'
            ? `जोखिम स्कोर: ${pipelineResult.riskScore}/100 (${pipelineResult.verdictLabel})`
            : `Risk score: ${pipelineResult.riskScore}/100. Confirmed or critical threat indicators found.`;
      } else if (pipelineResult.verificationStatus === 'scan_unavailable') {
        summary =
          language === 'hi'
            ? `वेबसाइट "${pipelineResult.hostname}" का स्कैन अनुपलब्ध है। डोमेन रिज़ॉल्यूशन या नेटवर्क लुकअप विफल रहा।`
            : `Scan unavailable for "${pipelineResult.hostname}". Domain DNS resolution or network lookup failed.`;
        verdictExplanation =
          language === 'hi'
            ? 'जोखिम स्कोर अनुपलब्ध — डोमेन रिज़ॉल्यूशन पूरा नहीं हो सका।'
            : 'Risk score unavailable — domain resolution could not be completed.';
      } else if (pipelineResult.verificationStatus === 'insufficient_evidence') {
        if (pipelineResult.indicators.length > 0 && pipelineResult.riskScore !== null) {
          const topIndicator = pipelineResult.indicators[0];
          summary =
            language === 'hi'
              ? `वेबसाइट "${pipelineResult.hostname}" में ${pipelineResult.indicators.length} संदिग्ध तकनीकी संकेतक पाए गए हैं (${topIndicator.description})।`
              : `Website "${pipelineResult.hostname}" exhibited ${pipelineResult.indicators.length} risk indicator(s), including ${topIndicator.description}`;
          verdictExplanation =
            language === 'hi'
              ? `जोखिम स्कोर: ${pipelineResult.riskScore}/100 (${pipelineResult.verdictLabel})`
              : `Heuristic risk score: ${pipelineResult.riskScore}/100 based on detected technical indicators.`;
        } else {
          summary =
            language === 'hi'
              ? `वेबसाइट "${pipelineResult.hostname}" की सुरक्षा सत्यापित नहीं की जा सकी। स्थानीय नियमों में कोई ज्ञात चेतावनी संकेत नहीं मिले, लेकिन अपर्याप्त साक्ष्य के कारण सुरक्षा की गारंटी नहीं दी जा सकती।`
              : `Unable to verify website safety for "${pipelineResult.hostname}". No warning signs detected by local rules, but external verification is inconclusive or not catalogued.`;
          verdictExplanation =
            language === 'hi'
              ? 'जोखिम स्कोर अनुपलब्ध — अपर्याप्त साक्ष्य: यह वेबसाइट किसी सत्यापित आधिकारिक संस्था से संबंधित नहीं है और क्लीन ब्लॉकलिस्ट प्रामाणिकता साबित नहीं करती।'
              : 'Risk score unavailable — insufficient evidence: Domain is not a recognized authoritative platform and clean blocklist does not prove website authenticity.';
        }
      } else {
        // checks_completed_no_known_threat or limited_checks_completed on recognized domain
        summary =
          language === 'hi'
            ? `वेबसाइट "${pipelineResult.hostname}" के लिए तकनीकी जाँच पूरी हुई। कोई ज्ञात खतरे के संकेत नहीं मिले।`
            : `Completed standard structural, DNS, and threat intelligence checks for "${pipelineResult.hostname}". No known threats detected.`;
        verdictExplanation =
          language === 'hi'
            ? 'पहचाने गए आधिकारिक डोमेन पर स्थानीय नियमों व थ्रेट इंटेलिजेंस द्वारा कोई फ़िशिंग या मैलवेयर संकेतक नहीं मिले।'
            : 'Standard checks completed on recognized domain. No brand impersonation, high-abuse TLDs, or blocklist matches detected.';
      }
    }

    const uniqueAdvice = Array.from(new Set(combinedSafetyAdvice));

    // Logging
    console.log(
      `[WebsitePipeline] host=${pipelineResult.hostname} score=${pipelineResult.riskScore} band=${pipelineResult.displayBand} verif=${pipelineResult.verificationStatus} rep=${pipelineResult.checks.reputation.reputationStatus} engine=${finalEngine}`
    );

    return res.status(200).json({
      success: true,
      timestamp: new Date().toISOString(),
      analysis: {
        url: pipelineResult.url,
        safeDisplayUrl: pipelineResult.safeDisplayUrl || pipelineResult.url,
        hostname: pipelineResult.hostname,
        normalizedUrl: pipelineResult.normalizedUrl,
        riskScore: pipelineResult.riskScore,
        riskLevel: pipelineResult.riskLevel,
        verdict: pipelineResult.verdict,
        verdictCanonical: pipelineResult.verdictCanonical || 'UNKNOWN',
        verdictLabel: pipelineResult.verdictLabel,
        displayBand: pipelineResult.displayBand,
        verificationStatus: pipelineResult.verificationStatus,
        reputationStatus: pipelineResult.checks.reputation.reputationStatus,
        checks: pipelineResult.checks,
        indicators: pipelineResult.indicators,
        evidence: pipelineResult.evidence,
        structuredFindings: pipelineResult.structuredFindings || [],
        checksPerformed: pipelineResult.checksPerformed || [],
        checksNotPerformed: pipelineResult.checksNotPerformed || [],
        whyThisResult: pipelineResult.whyThisResult || verdictExplanation,
        limitations: pipelineResult.limitations || [],
        summary,
        verdictExplanation,
        reputation: pipelineResult.checks.reputation,
        aiAnalysis,
        safetyAdvice: uniqueAdvice,
        engine: finalEngine,
        engineVersion: pipelineResult.engineVersion || 'scamsathi_engine_v3',
        analyzedAt: pipelineResult.analyzedAt || new Date().toISOString(),
      },
    });
  } catch (err) {
    if (
      err.message?.includes('MALFORMED_URL') ||
      err.message?.includes('UNSUPPORTED_SCHEME') ||
      err.message?.includes('Invalid URL format')
    ) {
      const errorCode = err.message.includes('UNSUPPORTED_SCHEME')
        ? 'UNSUPPORTED_SCHEME'
        : 'MALFORMED_URL';
      return res.status(400).json({
        success: false,
        errorCode,
        message: err.message,
      });
    }
    next(err);
  }
}
