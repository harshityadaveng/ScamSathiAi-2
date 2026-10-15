import { scanUrl, isAuthoritativeDomain } from './urlScanner.service.js';
import { checkUrlReputation } from './reputation.service.js';
import { checkDnsIntel } from './dnsIntel.service.js';
import { checkRdapIntel } from './rdapIntel.service.js';
import { checkTlsIntel } from './tlsIntel.service.js';
import { traceRedirectChain } from './redirectChainIntel.service.js';

// In-memory cache for recent domain investigations (5-minute TTL)
const pipelineCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Clears the pipeline cache (useful for testing)
 */
export function clearPipelineCache() {
  pipelineCache.clear();
}

/**
 * Executes the complete multi-signal website investigation pipeline.
 * Runs independent checks concurrently:
 * - Structural and lookalike heuristics
 * - Threat intelligence reputation (Google Safe Browsing / VirusTotal)
 * - DNS resolution (A, AAAA, MX, NS) with SSRF enforcement
 * - RDAP registration intelligence (age, creation date, registrar)
 * - TLS certificate inspection (issuer, validity, expiration)
 * - Redirect chain analysis (hop-by-hop with SSRF guard)
 *
 * @param {string} rawUrl - Target website URL or domain
 * @returns {Promise<object>} Complete evidence report
 */
export async function runWebsiteInvestigation(rawUrl) {
  const cacheKey = rawUrl.trim().toLowerCase();
  const cached = pipelineCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  // 1. Initial heuristic scan & URL normalization
  const heuristics = scanUrl(rawUrl);
  const hostname = heuristics.normalizedUrl.hostname;
  const registeredDomain = heuristics.normalizedUrl.registeredDomain || hostname;
  const isHttps = heuristics.normalizedUrl.isHttps;

  // 2. Execute independent checks in parallel (settled promises so one failure never blocks others)
  const [repResult, dnsResult, rdapResult, tlsResult, redirectResult] = await Promise.all([
    checkUrlReputation(heuristics.normalizedUrl.full).catch((err) => ({
      name: 'threat_reputation',
      status: 'error',
      source: 'reputation_provider',
      reputationStatus: 'unavailable',
      verdict: null,
      threatCategory: null,
      details: `Reputation query error: ${err.message}`,
      timestamp: new Date().toISOString(),
    })),
    checkDnsIntel(hostname).catch((err) => ({
      name: 'dns_resolution',
      status: 'error',
      source: 'dns_resolver',
      timestamp: new Date().toISOString(),
      explanation: `DNS resolution failed: ${err.message}`,
      data: { aRecords: [], aaaaRecords: [], mxRecords: [], nsRecords: [], resolvedIps: [] },
    })),
    checkRdapIntel(registeredDomain).catch((err) => ({
      name: 'domain_registration',
      status: 'error',
      source: 'rdap',
      timestamp: new Date().toISOString(),
      explanation: `RDAP check failed: ${err.message}`,
      data: null,
    })),
    // Only attempt TLS if target is HTTPS or standard web hostname
    (isHttps || !hostname.includes(':')
      ? checkTlsIntel(hostname).catch((err) => ({
          name: 'tls_certificate',
          status: 'error',
          source: 'tls_handshake',
          timestamp: new Date().toISOString(),
          explanation: `TLS check error: ${err.message}`,
          data: null,
        }))
      : Promise.resolve({
          name: 'tls_certificate',
          status: 'no_data',
          source: 'tls_handshake',
          timestamp: new Date().toISOString(),
          explanation: 'Target URL explicitly uses insecure HTTP protocol without TLS.',
          data: null,
        })),
    traceRedirectChain(heuristics.normalizedUrl.full).catch((err) => ({
      name: 'redirect_chain',
      status: 'error',
      source: 'redirect_fetcher',
      timestamp: new Date().toISOString(),
      explanation: `Redirect evaluation failed: ${err.message}`,
      data: {
        initialUrl: heuristics.normalizedUrl.full,
        finalUrl: heuristics.normalizedUrl.full,
        hopCount: 1,
        hops: [],
        hasCrossDomainRedirect: false,
        hasSuspiciousHop: false,
      },
    })),
  ]);

  // Standardize reputation check structure with Feature 1 adapter interface
  const reputationCheck = {
    name: 'threat_reputation',
    provider: repResult.provider || 'google_web_risk',
    configured: repResult.configured ?? (repResult.reputationStatus !== 'not_configured'),
    requestSucceeded: repResult.requestSucceeded ?? false,
    lookupStatus:
      repResult.lookupStatus ||
      (repResult.reputationStatus === 'confirmed_threat'
        ? 'THREAT_FOUND'
        : repResult.reputationStatus === 'no_known_threat_detected'
        ? 'NO_MATCH_FOUND'
        : repResult.reputationStatus === 'not_configured'
        ? 'NOT_CONFIGURED'
        : 'UNAVAILABLE'),
    matchedThreatTypes:
      repResult.matchedThreatTypes || (repResult.threatCategory ? [repResult.threatCategory] : []),
    checkedAt: repResult.checkedAt || repResult.timestamp || new Date().toISOString(),
    errorCode: repResult.errorCode || null,
    checked: repResult.checked ?? false,
    status: repResult.status === 'error' ? 'error' : repResult.status === 'not_configured' ? 'not_configured' : repResult.status === 'unavailable' ? 'unavailable' : 'success',
    reputationStatus: repResult.reputationStatus || repResult.status || 'not_configured',
    source: repResult.provider || 'google_web_risk',
    verdict: repResult.verdict || null,
    threatCategory: repResult.threatCategory || null,
    details: repResult.details || 'No details provided.',
    timestamp: repResult.timestamp || new Date().toISOString(),
  };

  // 3. Multi-Signal Evidence Aggregation
  const combinedIndicators = [...heuristics.indicators];
  let calculatedScore = heuristics.riskScore;

  // Signal: Confirmed Threat Intelligence match
  if (reputationCheck.reputationStatus === 'confirmed_threat' || reputationCheck.verdict === 'malicious') {
    combinedIndicators.unshift({
      id: 'THREAT_INTELLIGENCE_MATCH',
      category: 'Confirmed Blocklist Match',
      severity: 'critical',
      source: 'threat_intelligence',
      description: reputationCheck.details,
    });
    calculatedScore = Math.max(90, calculatedScore + 50);
  }

  // Signal: SSRF Blocked / Internal target
  if (dnsResult.data?.ssrfBlocked) {
    combinedIndicators.unshift({
      id: 'SSRF_TARGET_BLOCKED',
      category: 'Network Security',
      severity: 'critical',
      source: 'dns_resolver',
      description: dnsResult.explanation,
    });
    calculatedScore = Math.max(95, calculatedScore + 50);
  }

  // Signal: Domain Age Risk (< 30 days or < 90 days)
  if (rdapResult.status === 'success' && rdapResult.data) {
    if (rdapResult.data.isVeryNewDomain) {
      combinedIndicators.push({
        id: 'VERY_NEW_DOMAIN',
        category: 'Domain Registration Age',
        severity: 'medium',
        source: 'rdap',
        description: `Domain was registered very recently (${rdapResult.data.ageDays} days ago). Newly created domains have elevated correlation with disposable phishing campaigns.`,
      });
      calculatedScore += 25;
    } else if (rdapResult.data.isYoungDomain) {
      combinedIndicators.push({
        id: 'YOUNG_DOMAIN',
        category: 'Domain Registration Age',
        severity: 'low',
        source: 'rdap',
        description: `Domain is relatively new (${rdapResult.data.ageDays} days old, under 3 months).`,
      });
      calculatedScore += 15;
    }
  }

  // Signal: Expired or Self-Signed TLS Certificate
  if (tlsResult.status === 'success' && tlsResult.data) {
    if (tlsResult.data.isExpired) {
      combinedIndicators.push({
        id: 'EXPIRED_TLS_CERTIFICATE',
        category: 'TLS Security',
        severity: 'medium',
        source: 'tls_handshake',
        description: `Website presents an expired TLS certificate (expired ${Math.abs(tlsResult.data.daysRemaining)} days ago).`,
      });
      calculatedScore += 20;
    }
    if (tlsResult.data.isSelfSigned) {
      combinedIndicators.push({
        id: 'SELF_SIGNED_TLS_CERTIFICATE',
        category: 'TLS Security',
        severity: 'medium',
        source: 'tls_handshake',
        description: 'Website uses a self-signed or untrusted SSL/TLS certificate.',
      });
      calculatedScore += 20;
    }
  }

  // Signal: Redirect chain vulnerabilities (SSRF / Loops / Cross-domain)
  if (redirectResult.status === 'ssrf_blocked') {
    combinedIndicators.unshift({
      id: 'SSRF_REDIRECT_HOP_BLOCKED',
      category: 'Network Security',
      severity: 'critical',
      source: 'redirect_fetcher',
      description: redirectResult.explanation,
    });
    calculatedScore = Math.max(95, calculatedScore + 50);
  } else if (redirectResult.status === 'redirect_loop' || redirectResult.status === 'max_hops_exceeded') {
    combinedIndicators.push({
      id: 'DECEPTIVE_REDIRECT_CHAIN',
      category: 'URL Redirection',
      severity: 'high',
      source: 'redirect_fetcher',
      description: redirectResult.explanation,
    });
    calculatedScore += 25;
  } else if (redirectResult.data?.hasCrossDomainRedirect && heuristics.riskScore >= 25) {
    combinedIndicators.push({
      id: 'CROSS_DOMAIN_REDIRECT',
      category: 'URL Redirection',
      severity: 'medium',
      source: 'redirect_fetcher',
      description: `Target redirects across different domains (${hostname} -> ${new URL(redirectResult.data.finalUrl).hostname}).`,
    });
    calculatedScore += 15;
  }

  // Deduplicate indicators by id
  const uniqueIndicators = Array.from(new Map(combinedIndicators.map((i) => [i.id, i])).values());

  const isAuthoritative = isAuthoritativeDomain(hostname, registeredDomain);

  // Centralized Documented Risk Engine
  // Canonical Verdicts:
  // - known_threat: confirmed blocklist match or SSRF attempt
  // - high_risk: heuristic score >= 75
  // - suspicious: score 50-74, or 25-49 with caution indicators
  // - no_known_threat_detected: authoritative domain with clean checks
  // - insufficient_evidence: arbitrary domain with insufficient evidence (riskScore: null)
  // - scan_unavailable: DNS/network resolution failure (riskScore: null)
  let finalRiskScore = null;
  let riskLevel = 'unknown';
  let verdict = 'insufficient_evidence';
  let verdictLabel = 'Unable to verify website safety';
  let displayBand = 'yellow';
  let verificationStatus = 'insufficient_evidence';

  // 1. Confirmed Threat match or SSRF attempt
  if (
    reputationCheck.reputationStatus === 'confirmed_threat' ||
    reputationCheck.verdict === 'malicious' ||
    dnsResult.data?.ssrfBlocked ||
    redirectResult.status === 'ssrf_blocked'
  ) {
    verificationStatus = 'threat_detected';
    verdict = 'known_threat';
    verdictLabel = 'Confirmed threat detected';
    riskLevel = 'high';
    displayBand = 'red';
    finalRiskScore = Math.min(100, Math.max(90, calculatedScore));
  }
  // 2. High Risk Heuristic Indicators (Score >= 75)
  else if (calculatedScore >= 75) {
    verificationStatus = 'threat_detected';
    verdict = 'high_risk';
    verdictLabel = 'High risk threat indicators';
    riskLevel = 'high';
    displayBand = 'red';
    finalRiskScore = Math.min(100, calculatedScore);
  }
  // 3. Suspicious Indicators (Score >= 50)
  else if (calculatedScore >= 50) {
    verificationStatus = 'suspicious';
    verdict = 'suspicious';
    verdictLabel = 'Suspicious indicators found';
    riskLevel = 'suspicious';
    displayBand = 'orange';
    finalRiskScore = calculatedScore;
  }
  // 4. DNS Resolution Failure (Domain cannot resolve or lookup failed)
  else if (dnsResult.status === 'error' || dnsResult.status === 'unavailable') {
    verificationStatus = 'scan_unavailable';
    verdict = 'scan_unavailable';
    verdictLabel = 'Scan unavailable — domain resolution failed';
    riskLevel = 'unknown';
    displayBand = 'yellow';
    finalRiskScore = null;
  }
  // 5. Authoritative Domain with clean checks
  else if (isAuthoritative && calculatedScore < 25) {
    if (dnsResult.status === 'success' && reputationCheck.reputationStatus === 'no_known_threat_detected') {
      verificationStatus = 'checks_completed_no_known_threat';
    } else {
      verificationStatus = 'limited_checks_completed';
    }
    verdict = 'no_known_threat_detected';
    verdictLabel = 'Low risk indicators';
    riskLevel = 'low';
    displayBand = 'green';
    finalRiskScore = 0;
  }
  // 6. Caution Indicators on non-authoritative domain (25 <= Score < 50)
  else if (calculatedScore >= 25) {
    verificationStatus = 'insufficient_evidence';
    verdict = 'suspicious';
    verdictLabel = 'Caution advised';
    riskLevel = 'caution';
    displayBand = 'yellow';
    finalRiskScore = calculatedScore;
  }
  // 7. Insufficient Evidence (Arbitrary/unknown domain, Score < 25, no authoritative proof)
  else {
    verificationStatus = 'insufficient_evidence';
    verdict = 'insufficient_evidence';
    verdictLabel = 'Unable to verify website safety';
    riskLevel = 'unknown';
    displayBand = 'yellow';
    finalRiskScore = null; // Strictly NULL! Never 0/100 on insufficient evidence
  }

  // Safety advice synthesis
  const safetyAdvice = [...heuristics.safetyAdvice];
  if (verificationStatus === 'threat_detected') {
    safetyAdvice.unshift('Do not visit this site, enter personal details, or download any software.');
  }
  if (rdapResult.data?.isVeryNewDomain) {
    safetyAdvice.push('This domain was registered less than 30 days ago. Exercise extreme caution before making payments.');
  }
  if (tlsResult.data?.isExpired || tlsResult.data?.isSelfSigned) {
    safetyAdvice.push('The website does not have a valid trusted SSL certificate. Any connection may be insecure.');
  }
  if (redirectResult.data?.hasCrossDomainRedirect) {
    safetyAdvice.push('This URL immediately redirects to a completely different domain. Verify the final destination carefully.');
  }

  // Canonical Uppercase Verdict (Feature 2.D & 4)
  let verdictCanonical = 'UNKNOWN';
  if (verdict === 'known_threat' || verdict === 'high_risk') {
    verdictCanonical = 'MALICIOUS';
  } else if (verdict === 'suspicious') {
    verdictCanonical = 'SUSPICIOUS';
  } else if (verdict === 'no_known_threat_detected') {
    verdictCanonical = 'SAFE_NO_THREAT_FOUND';
  } else {
    verdictCanonical = 'UNKNOWN';
  }

  // Execution tracking
  const checksPerformed = [];
  const checksNotPerformed = [];

  if (reputationCheck.reputationStatus !== 'not_configured' && reputationCheck.reputationStatus !== 'unavailable') {
    checksPerformed.push('Threat Intelligence');
  } else {
    checksNotPerformed.push(`Threat Intelligence (${reputationCheck.reputationStatus === 'not_configured' ? 'Not Configured' : 'Unavailable'})`);
  }

  if (dnsResult.status === 'success') {
    checksPerformed.push('DNS Resolution');
  } else {
    checksNotPerformed.push(`DNS Resolution (${dnsResult.status})`);
  }

  if (rdapResult.status === 'success') {
    checksPerformed.push('Domain Registration (RDAP)');
  } else {
    checksNotPerformed.push(`Domain Registration (${rdapResult.status})`);
  }

  if (tlsResult.status === 'success') {
    checksPerformed.push('TLS Certificate Inspection');
  } else if (tlsResult.status === 'no_data') {
    checksNotPerformed.push('TLS Certificate (Insecure HTTP)');
  } else {
    checksNotPerformed.push(`TLS Certificate (${tlsResult.status})`);
  }

  if (redirectResult.status === 'success' || redirectResult.status === 'ssrf_blocked') {
    checksPerformed.push('Safe Redirect Chain');
  } else {
    checksNotPerformed.push(`Redirect Chain (${redirectResult.status})`);
  }

  checksPerformed.push('Lexical & Lookalike Heuristics');

  // Structured Findings (Feature 4 requirement)
  const nowIso = new Date().toISOString();
  const structuredFindings = [];

  // Finding 1: Threat Intelligence
  structuredFindings.push({
    id: 'FINDING_THREAT_INTELLIGENCE',
    category: 'Threat Intelligence',
    status:
      reputationCheck.reputationStatus === 'confirmed_threat'
        ? 'THREAT_FOUND'
        : reputationCheck.reputationStatus === 'no_known_threat_detected'
        ? 'NO_MATCH_FOUND'
        : reputationCheck.reputationStatus === 'not_configured'
        ? 'NOT_CONFIGURED'
        : 'ERROR',
    severity:
      reputationCheck.reputationStatus === 'confirmed_threat'
        ? 'critical'
        : reputationCheck.reputationStatus === 'no_known_threat_detected'
        ? 'info'
        : 'low',
    title: 'External Threat Intelligence Database',
    explanation: reputationCheck.details,
    evidence: {
      provider: reputationCheck.source,
      reputationStatus: reputationCheck.reputationStatus,
      matchedThreatTypes: reputationCheck.threatCategory ? [reputationCheck.threatCategory] : [],
    },
    source: reputationCheck.source || 'reputation_provider',
    checkedAt: reputationCheck.timestamp || nowIso,
  });

  // Finding 2: DNS Resolution
  structuredFindings.push({
    id: 'FINDING_DNS_RESOLUTION',
    category: 'Network Security',
    status: dnsResult.status === 'success' ? 'PASS' : 'ERROR',
    severity: dnsResult.status === 'success' ? 'info' : 'medium',
    title: 'DNS Hostname Resolution',
    explanation: dnsResult.explanation,
    evidence: dnsResult.data,
    source: 'dns_resolver',
    checkedAt: dnsResult.timestamp || nowIso,
  });

  // Finding 3: Domain Registration (RDAP)
  structuredFindings.push({
    id: 'FINDING_DOMAIN_REGISTRATION',
    category: 'Domain Registration',
    status:
      rdapResult.status === 'success'
        ? rdapResult.data?.isVeryNewDomain
          ? 'WARNING'
          : 'PASS'
        : 'UNKNOWN',
    severity:
      rdapResult.status === 'success' && rdapResult.data?.isVeryNewDomain
        ? 'medium'
        : 'info',
    title: 'Domain Registration Age & WHOIS/RDAP',
    explanation: rdapResult.explanation,
    evidence: rdapResult.data,
    source: 'rdap',
    checkedAt: rdapResult.timestamp || nowIso,
  });

  // Finding 4: TLS/SSL Certificate
  structuredFindings.push({
    id: 'FINDING_TLS_CERTIFICATE',
    category: 'TLS Security',
    status:
      tlsResult.status === 'success'
        ? tlsResult.data?.isExpired || tlsResult.data?.isSelfSigned
          ? 'WARNING'
          : 'PASS'
        : tlsResult.status === 'no_data'
        ? 'NOT_CHECKED'
        : 'ERROR',
    severity:
      tlsResult.status === 'success' && (tlsResult.data?.isExpired || tlsResult.data?.isSelfSigned)
        ? 'medium'
        : 'info',
    title: 'TLS/SSL Certificate Inspection',
    explanation: tlsResult.explanation,
    evidence: tlsResult.data,
    source: 'tls_handshake',
    checkedAt: tlsResult.timestamp || nowIso,
  });

  // Finding 5: Redirect Chain
  structuredFindings.push({
    id: 'FINDING_REDIRECT_CHAIN',
    category: 'URL Redirection',
    status:
      redirectResult.status === 'ssrf_blocked'
        ? 'THREAT_FOUND'
        : redirectResult.status === 'redirect_loop' || redirectResult.status === 'max_hops_exceeded'
        ? 'WARNING'
        : redirectResult.status === 'success'
        ? 'PASS'
        : 'UNKNOWN',
    severity:
      redirectResult.status === 'ssrf_blocked'
        ? 'critical'
        : redirectResult.status === 'redirect_loop'
        ? 'high'
        : 'info',
    title: 'Safe Redirect Chain Analysis',
    explanation: redirectResult.explanation,
    evidence: redirectResult.data,
    source: 'redirect_fetcher',
    checkedAt: redirectResult.timestamp || nowIso,
  });

  // Finding 6+: Specific heuristic indicators
  for (const ind of uniqueIndicators) {
    structuredFindings.push({
      id: `FINDING_${ind.id}`,
      category: ind.category || 'Heuristics',
      status: ind.severity === 'critical' ? 'THREAT_FOUND' : 'WARNING',
      severity: ind.severity || 'medium',
      title: ind.id.replace(/_/g, ' '),
      explanation: ind.description,
      evidence: { indicatorId: ind.id, severity: ind.severity },
      source: ind.source || 'url_heuristics',
      checkedAt: nowIso,
    });
  }

  // Why this result synthesis
  let whyThisResult = '';
  if (verdictCanonical === 'MALICIOUS') {
    whyThisResult = `The website was assigned a MALICIOUS verdict because confirmed threat intelligence indicators or critical malicious signals were detected for "${hostname}".`;
  } else if (verdictCanonical === 'SUSPICIOUS') {
    whyThisResult = `The website was assigned a SUSPICIOUS verdict because ${uniqueIndicators.length} risk indicators were detected (e.g. brand impersonation or unusual domain attributes), requiring caution.`;
  } else if (verdictCanonical === 'SAFE_NO_THREAT_FOUND') {
    whyThisResult = `The website was assigned SAFE_NO_THREAT_FOUND because "${hostname}" is a recognized authoritative institution with clean security checks and no threat blocklist entries.`;
  } else {
    whyThisResult = `The website safety could not be verified (UNKNOWN / Unable to Verify Safety). There is insufficient evidence to confirm legitimacy. A clean threat intelligence lookup does not prove an unverified website is safe.`;
  }

  // Transparent limitations disclosure
  const limitations = [
    'External reputation lookups only verify if a URL is currently listed on known threat databases; a clean result does NOT prove authenticity or safety.',
    'DNS resolution and valid TLS certificates prove only network connectivity, NOT legitimacy or trustworthiness.',
    'The absence of RDAP or MX records is common across certain registries and does not independently prove malicious intent.',
    'Heuristic rules identify risk patterns and brand lookalikes, but independent verification through official channels is always recommended.',
  ];

  const structuredChecks = {
    reputation: reputationCheck,
    rdap: rdapResult,
    dns: dnsResult,
    tls: tlsResult,
    redirects: redirectResult,
    heuristics: {
      name: 'lookalike_heuristics',
      status: heuristics.indicators.length > 0 ? 'finding' : 'success',
      source: 'heuristic_rules',
      timestamp: new Date().toISOString(),
      indicatorsCount: heuristics.indicators.length,
      isAuthoritativeBrand: isAuthoritative,
    },
  };

  const evidence = [
    {
      check: 'Threat Intelligence',
      status: reputationCheck.reputationStatus,
      source: reputationCheck.source,
      summary: reputationCheck.details,
    },
    {
      check: 'DNS Resolution',
      status: dnsResult.status,
      source: 'dns_resolver',
      summary: dnsResult.explanation,
    },
    {
      check: 'Domain Registration (RDAP)',
      status: rdapResult.status,
      source: 'rdap',
      summary: rdapResult.explanation,
    },
    {
      check: 'TLS Certificate',
      status: tlsResult.status,
      source: 'tls_handshake',
      summary: tlsResult.explanation,
    },
    {
      check: 'Redirect Chain',
      status: redirectResult.status,
      source: 'redirect_fetcher',
      summary: redirectResult.explanation,
    },
    {
      check: 'Lexical & Lookalike Heuristics',
      status: heuristics.indicators.length > 0 ? 'finding' : 'passed',
      source: 'local_heuristics',
      summary:
        heuristics.indicators.length > 0
          ? `${heuristics.indicators.length} warning indicators detected.`
          : 'No lexical or lookalike warning signs found.',
    },
  ];

  const finalResult = {
    url: rawUrl,
    safeDisplayUrl: heuristics.safeDisplayUrl || rawUrl,
    hostname,
    normalizedUrl: heuristics.normalizedUrl,
    riskScore: finalRiskScore,
    riskLevel,
    verdict,
    verdictCanonical,
    verdictLabel,
    displayBand,
    verificationStatus,
    reputationStatus: reputationCheck.reputationStatus,
    isAuthoritativeDomain: isAuthoritative,
    checks: structuredChecks,
    indicators: uniqueIndicators,
    evidence,
    reputation: reputationCheck,
    structuredFindings,
    checksPerformed,
    checksNotPerformed,
    whyThisResult,
    limitations,
    safetyAdvice: Array.from(new Set(safetyAdvice)),
    engineVersion: 'scamsathi_engine_v3',
    engine: 'website_intelligence_pipeline_v3',
    analyzedAt: new Date().toISOString(),
  };

  pipelineCache.set(cacheKey, { timestamp: Date.now(), result: finalResult });
  return finalResult;
}
