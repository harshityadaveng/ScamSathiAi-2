import React, { useState, useEffect, useRef } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Phone,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  Globe,
  Radio,
  FileCode,
  Link as LinkIcon,
  CheckCircle2,
  AlertCircle,
  Lock,
  Unlock,
  Sparkles,
  Search,
  Shield,
  QrCode,
  Image as ImageIcon,
  ChevronDown,
  ChevronUp,
  Info
} from 'lucide-react';
import { analyzeMessage, checkUrlRisk, scanImageFile } from '../services/api';
import AnalysisLoadingScreen from './AnalysisLoadingScreen';

export default function AnalysisModal({ query, imageFile, onClose, onSelectSample, language }) {
  // Check if input looks like a URL or clean domain name
  const checkIfUrl = (text) => {
    if (!text) return false;
    const trimmed = text.trim();
    if (/^https?:\/\//i.test(trimmed)) return true;
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/.*)?$/i.test(trimmed) && !trimmed.includes(' ')) {
      return true;
    }
    return false;
  };

  const detectedAsUrl = !imageFile && checkIfUrl(query);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isUrlMode, setIsUrlMode] = useState(detectedAsUrl);
  const [isImageMode, setIsImageMode] = useState(Boolean(imageFile));
  const [imagePreviewUrl, setImagePreviewUrl] = useState(null);
  const [copied, setCopied] = useState(false);
  const [expandedWhy, setExpandedWhy] = useState(true);
  const [expandedFindings, setExpandedFindings] = useState(true);
  const [expandedChecks, setExpandedChecks] = useState(false);
  const isRequestPending = useRef(false);
  const isMountedRef = useRef(true);

  // Safeguard component lifecycle to prevent leaks on premature unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Keyboard accessibility: ESC key closes modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Handle image preview URL lifecycle
  useEffect(() => {
    if (imageFile) {
      const url = URL.createObjectURL(imageFile);
      setImagePreviewUrl(url);
      return () => URL.revokeObjectURL(url);
    } else {
      setImagePreviewUrl(null);
    }
  }, [imageFile]);

  // Main request executor
  const executeAnalysis = async () => {
    if (isRequestPending.current) return;
    isRequestPending.current = true;

    if (isMountedRef.current) {
      setLoading(true);
      setError(null);
    }

    // Branch A: Image / Screenshot Scan
    if (imageFile) {
      if (isMountedRef.current) {
        setIsImageMode(true);
        setIsUrlMode(false);
      }
      try {
        const result = await scanImageFile(imageFile, language);
        if (isMountedRef.current) {
          setAnalysisResult(result);
        }
      } catch (err) {
        console.error('[AnalysisModal] Image Scan Error:', err);
        if (isMountedRef.current) {
          setError(
            err.message ||
              (language === 'hi'
                ? 'इमेज विश्लेषण विफल रहा। कृपया वैध पीएनजी, जेपीईजी या वेबपी इमेज पुनः अपलोड करें।'
                : 'Failed to analyze image. Please ensure valid PNG, JPEG, or WebP format.')
          );
        }
      } finally {
        if (isMountedRef.current) {
          setLoading(false);
        }
        isRequestPending.current = false;
      }
      return;
    }

    // Branch B: Text / URL Scan
    if (isMountedRef.current) {
      setIsImageMode(false);
    }
    const trimmed = (query || '').trim();
    if (!trimmed) {
      if (isMountedRef.current) {
        setError(language === 'hi' ? 'कोई सामग्री प्रदान नहीं की गई।' : 'No content provided for analysis.');
        setLoading(false);
      }
      isRequestPending.current = false;
      return;
    }

    const isUrl = checkIfUrl(trimmed);
    if (isMountedRef.current) {
      setIsUrlMode(isUrl);
    }

    try {
      let result;
      if (isUrl) {
        result = await checkUrlRisk(trimmed);
      } else {
        result = await analyzeMessage(trimmed, language);
      }
      if (isMountedRef.current) {
        setAnalysisResult(result);
      }
    } catch (err) {
      console.error('[AnalysisModal] Analysis Error:', err);
      if (isMountedRef.current) {
        setError(
          err.message ||
            (language === 'hi'
              ? 'सर्वर से कनेक्ट करने में विफल। कृपया पुनः प्रयास करें।'
              : 'Failed to connect to ScamSathi backend. Please ensure the server is running and try again.')
        );
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
      isRequestPending.current = false;
    }
  };

  useEffect(() => {
    executeAnalysis();
  }, [query, imageFile, language]);

  // Copy report summary
  const copyReportSummary = () => {
    if (!analysisResult) return;

    let textToCopy = '';
    if (isImageMode) {
      textToCopy = `ScamSathi AI Image & QR Inspection Report:
File: ${analysisResult.imageInfo?.fileName || 'Image'} (${Math.round((analysisResult.imageInfo?.sizeBytes || 0) / 1024)} KB)
Verdict: ${analysisResult.overallVerdict} (Score: ${analysisResult.overallRiskScore !== null ? `${analysisResult.overallRiskScore}/100` : 'N/A'})
QR Detected: ${analysisResult.qrCode?.detected ? `Yes (${analysisResult.qrCode.type})` : 'No'}
${analysisResult.qrCode?.isPayment ? `UPI Advisory: Payment Request (${analysisResult.qrCode.upiDetails?.payeeAddress || ''})` : ''}
OCR Text: ${analysisResult.ocr?.extractedText ? analysisResult.ocr.extractedText.slice(0, 160) : 'None'}
Summary: ${analysisResult.summary || 'N/A'}`;
    } else if (isUrlMode) {
      const hostname = analysisResult.normalizedUrl?.hostname || query;
      const scoreStr =
        analysisResult.riskScore !== null && analysisResult.riskScore !== undefined
          ? `${analysisResult.riskScore}/100`
          : 'Unavailable (Insufficient Evidence)';
      textToCopy = `ScamSathi AI Website Inspection Report:
Target: ${hostname}
Verdict: ${analysisResult.verdictCanonical || analysisResult.verdict}
Risk Score: ${scoreStr}
Google Web Risk / Threat Intel: ${analysisResult.reputation?.lookupStatus || analysisResult.reputation?.reputationStatus || 'NOT_CONFIGURED'}
Indicators: ${analysisResult.indicators?.map((i) => i.description).join('; ') || 'None detected'}
Summary: ${analysisResult.whyThisResult?.summary || analysisResult.summary || 'N/A'}
Recommendation: ${analysisResult.safetyAdvice?.[0] || 'Exercise caution.'}`;
    } else {
      textToCopy = `ScamSathi AI Message Analysis Report:
Input: "${query}"
Risk Level: ${analysisResult.riskLevel} (${analysisResult.riskScore}/100)
Pattern: ${analysisResult.scamType}
Summary: ${analysisResult.summary || 'N/A'}
Recommendation: ${analysisResult.safetyAdvice?.[0] || 'Stay cautious.'}`;
    }

    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2200);
  };

  // Safe finding evidence renderer
  const formatFindingEvidence = (ev) => {
    if (!ev) return 'Telemetry observation';
    if (typeof ev === 'string') return ev;
    if (typeof ev === 'object') {
      if (ev.reputationStatus) {
        return `Status: ${ev.reputationStatus}${ev.matchedThreatTypes?.length ? ` (${ev.matchedThreatTypes.join(', ')})` : ''}`;
      }
      if (ev.ageDays !== undefined) {
        return `Domain age: ${ev.ageDays} days${ev.registrationDate ? ` (Reg: ${ev.registrationDate.split('T')[0]})` : ''}`;
      }
      if (ev.issuer !== undefined || ev.authorized !== undefined) {
        return `Issuer: ${ev.issuer || 'Unknown'}, Valid: ${ev.authorized ? 'Yes' : 'No'}`;
      }
      if (ev.resolvedIps !== undefined) {
        return `Resolved IPs: ${(ev.resolvedIps || []).join(', ') || 'None'}`;
      }
      if (ev.hopCount !== undefined) {
        return `Hops: ${ev.hopCount}, Cross-domain: ${ev.hasCrossDomainRedirect ? 'Yes' : 'No'}`;
      }
      try {
        const keys = Object.keys(ev).filter((k) => typeof ev[k] !== 'object');
        if (keys.length > 0) {
          return keys.slice(0, 3).map((k) => `${k}: ${ev[k]}`).join(', ');
        }
        return 'Telemetry data';
      } catch {
        return 'Telemetry observation';
      }
    }
    return String(ev);
  };

  // Canonical verdict styling helper
  const getScoreTheme = (score, verificationStatus, verdict, verdictCanonical) => {
    const vCanon = (verdictCanonical || '').toUpperCase();

    // 1. Confirmed Threat / Malicious
    if (
      vCanon === 'MALICIOUS' ||
      verdict === 'known_threat' ||
      verdict === 'high_risk' ||
      verificationStatus === 'threat_detected' ||
      (score !== null && score !== undefined && score >= 75)
    ) {
      return {
        color: '#DC2626',
        bg: '#FDE1DE',
        border: 'rgba(220, 38, 38, 0.4)',
        label: language === 'hi' ? 'दुर्भावनापूर्ण खतरा (MALICIOUS)' : 'MALICIOUS (High Threat)',
        band: 'red',
        icon: <ShieldAlert size={20} color="#DC2626" />,
      };
    }

    // 2. Suspicious Indicators
    if (vCanon === 'SUSPICIOUS' || (score !== null && score !== undefined && score >= 40)) {
      return {
        color: '#EA580C',
        bg: '#FFF7EC',
        border: 'rgba(234, 88, 12, 0.4)',
        label: language === 'hi' ? 'संदिग्ध संकेतक (SUSPICIOUS)' : 'SUSPICIOUS (Indicators Found)',
        band: 'orange',
        icon: <AlertTriangle size={20} color="#EA580C" />,
      };
    }

    // 3. Clean Authoritative Domain (No Threat Found)
    if (vCanon === 'SAFE_NO_THREAT_FOUND' || (score !== null && score !== undefined && score === 0)) {
      return {
        color: '#16A34A',
        bg: '#EDFBF2',
        border: 'rgba(22, 163, 74, 0.3)',
        label: language === 'hi' ? 'कोई खतरा नहीं मिला (SAFE)' : 'SAFE (No Threat Found)',
        band: 'green',
        icon: <CheckCircle2 size={20} color="#16A34A" />,
      };
    }

    // 4. Insufficient Evidence / Unknown (Default honest state)
    return {
      color: '#D97706',
      bg: '#FFFBEB',
      border: 'rgba(217, 119, 6, 0.4)',
      label: language === 'hi' ? 'सुरक्षा असत्यापित (UNKNOWN)' : 'UNKNOWN (Insufficient Evidence)',
      band: 'yellow',
      icon: <AlertCircle size={20} color="#D97706" />,
    };
  };

  const scoreTheme = analysisResult
    ? isImageMode
      ? getScoreTheme(analysisResult.overallRiskScore, null, null, analysisResult.overallVerdict)
      : getScoreTheme(
          analysisResult.riskScore,
          analysisResult.verificationStatus,
          analysisResult.verdict,
          analysisResult.verdictCanonical
        )
    : null;

  const isHighRisk =
    analysisResult &&
    ((analysisResult.riskScore !== null && analysisResult.riskScore >= 50) ||
      analysisResult.overallRiskScore >= 50 ||
      analysisResult.overallVerdict === 'MALICIOUS' ||
      analysisResult.verdictCanonical === 'MALICIOUS' ||
      analysisResult.riskLevel === 'high' ||
      analysisResult.riskLevel === 'very_high');

  // Gauge calculation constants (SVG circle circumference)
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const currentRiskScore = isImageMode
    ? analysisResult?.overallRiskScore
    : analysisResult?.riskScore;

  const strokeDashoffset =
    currentRiskScore !== null && currentRiskScore !== undefined
      ? circumference - (Math.min(currentRiskScore, 100) / 100) * circumference
      : circumference;

  if (loading) {
    return (
      <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
        <AnalysisLoadingScreen
          mode={isImageMode ? 'image' : (isUrlMode || detectedAsUrl) ? 'url' : 'message'}
          language={language}
          onClose={onClose}
        />
      </div>
    );
  }

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '760px' }}>
        {/* Modal Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '50%',
                background: scoreTheme ? scoreTheme.bg : 'rgba(184, 59, 0, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: scoreTheme ? scoreTheme.color : '#B83B00',
              }}
            >
              {isImageMode ? <QrCode size={20} /> : isUrlMode ? <Globe size={20} /> : <Shield size={20} />}
            </div>
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#171717', margin: 0 }}>
                {isImageMode
                  ? language === 'hi'
                    ? 'स्क्रीनशॉट एवं क्यूआर कोड सुरक्षा विश्लेषण'
                    : 'Screenshot & QR-Code Scam Inspection'
                  : isUrlMode
                  ? language === 'hi'
                    ? 'वेबसाइट सुरक्षा एवं प्रमाण-आधारित जाँच'
                    : 'Evidence-Based Website Threat Inspection'
                  : language === 'hi'
                  ? 'संदेश धोखाधड़ी विश्लेषण रिपोर्ट'
                  : 'Message Scam Analysis Report'}
              </h3>
              <span style={{ fontSize: '12px', color: '#655E54' }}>
                {isImageMode
                  ? 'In-Memory Local QR Decoding + Gemini Vision OCR'
                  : isUrlMode
                  ? 'Google Web Risk Telemetry + Multi-Layered Heuristic Engine'
                  : 'ScamSathi AI Multi-Engine Screening'}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#655E54',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            aria-label="Close modal"
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Error State with Retry Button */}
          {error && (
            <div style={{ textAlign: 'center', padding: '36px 20px' }}>
              <div
                style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '50%',
                  background: '#FDE1DE',
                  color: '#CC191D',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 16px auto',
                }}
              >
                <AlertTriangle size={24} />
              </div>
              <h4 style={{ fontSize: '17px', fontWeight: 800, color: '#171717', marginBottom: '8px' }}>
                {language === 'hi' ? 'जाँच विफल' : 'Inspection Could Not Complete'}
              </h4>
              <p style={{ fontSize: '14px', color: '#655E54', maxWidth: '440px', margin: '0 auto 20px auto', lineHeight: 1.5 }}>
                {error}
              </p>
              <button
                type="button"
                className="nav-cta-btn"
                onClick={executeAnalysis}
                style={{ fontSize: '14px', padding: '10px 24px' }}
              >
                <RefreshCw size={15} />
                <span>{language === 'hi' ? 'पुनः प्रयास करें' : 'Retry Inspection'}</span>
              </button>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════════
              FEATURE 5: SUCCESSFUL SCREENSHOT & QR-CODE INSPECTION VIEW
          ══════════════════════════════════════════════════════════════════════ */}
          {!loading && !error && analysisResult && isImageMode && (
            <div className="modal-result-panel">
              {/* Image Preview & Metadata Header */}
              <div className="image-preview-container">
                {imagePreviewUrl && (
                  <img
                    src={imagePreviewUrl}
                    alt="Uploaded screenshot"
                    className="image-preview-thumb"
                  />
                )}
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: '#B83B00', textTransform: 'uppercase' }}>
                      IN-MEMORY IMAGE ANALYSIS
                    </span>
                    <button
                      type="button"
                      onClick={copyReportSummary}
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #E7DED0',
                        color: '#171717',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontSize: '11.5px',
                        fontWeight: 600,
                      }}
                    >
                      {copied ? <Check size={12} color="#16A34A" /> : <Copy size={12} />}
                      {copied ? 'Copied' : 'Copy Report'}
                    </button>
                  </div>
                  <h4 style={{ fontSize: '15px', fontWeight: 800, color: '#171717', margin: '4px 0 2px 0' }}>
                    {analysisResult.imageInfo?.fileName || 'Uploaded Image'}
                  </h4>
                  <div style={{ fontSize: '11.5px', color: '#655E54' }}>
                    Size: {Math.round((analysisResult.imageInfo?.sizeBytes || 0) / 1024)} KB &bull; Type:{' '}
                    {analysisResult.imageInfo?.mimeType || 'image/png'}
                  </div>
                </div>
              </div>

              {/* Main Image Verdict Card */}
              <div className="website-gauge-card" style={{ borderColor: scoreTheme.border }}>
                <div className="gauge-svg-container">
                  <svg className="gauge-svg" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r={radius} fill="transparent" stroke="#E7DED0" strokeWidth="9" />
                    <circle
                      cx="50"
                      cy="50"
                      r={radius}
                      fill="transparent"
                      stroke={scoreTheme.color}
                      strokeWidth="9"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      strokeLinecap="round"
                      style={{ transition: 'stroke-dashoffset 0.8s ease' }}
                    />
                  </svg>
                  <div className="gauge-center-text">
                    <span style={{ fontSize: '26px', fontWeight: 900, color: scoreTheme.color, lineHeight: 1 }}>
                      {analysisResult.overallRiskScore !== null && analysisResult.overallRiskScore !== undefined
                        ? analysisResult.overallRiskScore
                        : '—'}
                    </span>
                    <span style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: '#655E54' }}>
                      /100
                    </span>
                  </div>
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '4px 12px',
                        borderRadius: '20px',
                        fontSize: '12px',
                        fontWeight: 800,
                        background: scoreTheme.bg,
                        color: scoreTheme.color,
                        border: `1px solid ${scoreTheme.border}`,
                      }}
                    >
                      {scoreTheme.icon}
                      <span>{scoreTheme.label.toUpperCase()}</span>
                    </span>
                  </div>
                  <h4 style={{ fontSize: '16px', fontWeight: 800, color: '#171717', margin: '4px 0' }}>
                    {analysisResult.summary}
                  </h4>
                  <div style={{ fontSize: '12px', color: '#655E54' }}>
                    {analysisResult.privacyNotice}
                  </div>
                </div>
              </div>

              {/* 1. Decoded QR-Code Findings */}
              <div style={{ marginBottom: '18px' }}>
                <h5 style={{ fontSize: '13px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <QrCode size={15} color="#B83B00" />
                  <span>Decoded QR Code Findings:</span>
                </h5>

                {analysisResult.qrCode?.detected ? (
                  <div style={{ background: '#FFFFFF', border: '1px solid #E7DED0', borderRadius: '12px', padding: '14px 16px' }}>
                    {/* UPI DEBIT FRAUD ADVISORY (CRITICAL REQUIREMENT) */}
                    {analysisResult.qrCode?.type === 'upi' && (
                      <div className="upi-warning-banner">
                        <AlertTriangle size={20} color="#DC2626" style={{ flexShrink: 0, marginTop: '2px' }} />
                        <div style={{ fontSize: '12.5px', color: '#991B1B', lineHeight: 1.45 }}>
                          <strong style={{ display: 'block', fontSize: '13px', marginBottom: '3px' }}>
                            🚨 CRITICAL UPI SECURITY ADVISORY (भारतीय यूपीआई चेतावनी):
                          </strong>
                          <span>
                            {language === 'hi'
                              ? 'सावधान: यूपीआई में क्यूआर कोड केवल पैसे भेजने (DEBIT) के लिए होता है। पैसे प्राप्त करने या लॉटरी/रिफंड के लिए कभी भी क्यूआर कोड स्कैन करने या यूपीआई पिन डालने की आवश्यकता नहीं होती। इस क्यूआर को स्कैन करने से आपके बैंक खाते से पैसे कट जाएंगे!'
                              : 'Warning: In Indian banking (UPI), scanning a QR code or entering your PIN is strictly used to SEND / DEBIT money. Receiving money, refunds, or lottery prizes NEVER requires scanning a QR code or entering a PIN. Scanning this will immediately transfer money out of your account!'}
                          </span>
                        </div>
                      </div>
                    )}

                    <div style={{ fontSize: '13px', color: '#171717', marginBottom: '8px' }}>
                      <strong>Payload Content: </strong>
                      <code style={{ background: '#F4EFE6', padding: '2px 6px', borderRadius: '4px', wordBreak: 'break-all', fontSize: '12px' }}>
                        {analysisResult.qrCode.payload}
                      </code>
                    </div>

                    {analysisResult.qrCode.upiDetails && (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', background: '#FEFBF4', padding: '10px', borderRadius: '8px', border: '1px solid #E7DED0', fontSize: '12px' }}>
                        {analysisResult.qrCode.upiDetails.payeeAddress && (
                          <div>
                            <span style={{ color: '#655E54', fontWeight: 600 }}>Payee UPI ID: </span>
                            <strong>{analysisResult.qrCode.upiDetails.payeeAddress}</strong>
                          </div>
                        )}
                        {analysisResult.qrCode.upiDetails.payeeName && (
                          <div>
                            <span style={{ color: '#655E54', fontWeight: 600 }}>Payee Name: </span>
                            <strong>{analysisResult.qrCode.upiDetails.payeeName}</strong>
                          </div>
                        )}
                        {analysisResult.qrCode.upiDetails.amount && (
                          <div>
                            <span style={{ color: '#655E54', fontWeight: 600 }}>Requested Amount: </span>
                            <strong style={{ color: '#DC2626' }}>₹{analysisResult.qrCode.upiDetails.amount}</strong>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ background: '#FEFBF4', border: '1px solid #E7DED0', borderRadius: '12px', padding: '12px 14px', fontSize: '12.5px', color: '#655E54' }}>
                    {analysisResult.qrCode?.message || 'No QR code pattern detected in this image.'}
                  </div>
                )}
              </div>

              {/* 2. Extracted OCR Text & Message Signals */}
              <div style={{ marginBottom: '18px' }}>
                <h5 style={{ fontSize: '13px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ImageIcon size={15} color="#B83B00" />
                  <span>Extracted OCR Text & Indicators:</span>
                </h5>

                {analysisResult.ocr?.extractedText ? (
                  <div style={{ background: '#FFFFFF', border: '1px solid #E7DED0', borderRadius: '12px', padding: '14px 16px' }}>
                    <div style={{ fontSize: '11px', color: '#88898D', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                      OCR Transcribed Text ({analysisResult.ocr.method}):
                    </div>
                    <p style={{ fontSize: '13px', color: '#171717', fontStyle: 'italic', background: '#F9F8F6', padding: '10px 12px', borderRadius: '8px', margin: '0 0 10px 0', lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>
                      "{analysisResult.ocr.extractedText}"
                    </p>

                    {/* Entities */}
                    {(analysisResult.ocr.extractedUrls?.length > 0 ||
                      analysisResult.ocr.extractedPhoneNumbers?.length > 0 ||
                      analysisResult.ocr.extractedUpiIds?.length > 0) && (
                      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' }}>
                        {analysisResult.ocr.extractedUrls?.map((u, i) => (
                          <span key={i} style={{ fontSize: '11.5px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                            🔗 {u}
                          </span>
                        ))}
                        {analysisResult.ocr.extractedPhoneNumbers?.map((p, i) => (
                          <span key={i} style={{ fontSize: '11.5px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                            📞 {p}
                          </span>
                        ))}
                        {analysisResult.ocr.extractedUpiIds?.map((up, i) => (
                          <span key={i} style={{ fontSize: '11.5px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                            💳 {up}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Threat indicators from message rules */}
                    {analysisResult.messageAnalysis?.threatIndicators?.length > 0 && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {analysisResult.messageAnalysis.threatIndicators.map((ti, i) => (
                          <div key={i} className="evidence-row-animated" style={{ background: '#FFF7ED', border: '1px solid rgba(234, 88, 12, 0.3)', padding: '6px 10px', borderRadius: '6px', fontSize: '12px', color: '#171717' }}>
                            <strong style={{ color: '#EA580C' }}>{ti.category?.replace(/_/g, ' ')}: </strong>
                            <span>{ti.evidence}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ background: '#FEFBF4', border: '1px solid #E7DED0', borderRadius: '12px', padding: '12px 14px', fontSize: '12.5px', color: '#655E54' }}>
                    No readable text detected by OCR in this image.
                  </div>
                )}
              </div>

              {/* 3. Extracted URLs Deep Pipeline Results */}
              {analysisResult.urlScans && analysisResult.urlScans.length > 0 && (
                <div style={{ marginBottom: '18px' }}>
                  <h5 style={{ fontSize: '13px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Globe size={15} color="#B83B00" />
                    <span>Extracted URL Threat Scans ({analysisResult.urlScans.length}):</span>
                  </h5>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {analysisResult.urlScans.map((us, idx) => (
                      <div key={idx} className="evidence-row-animated" style={{ background: '#FFFFFF', border: '1px solid #E7DED0', borderRadius: '10px', padding: '12px 14px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: 800, fontSize: '13px', color: '#171717' }}>
                            {us.url}
                          </span>
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 800,
                              padding: '2px 8px',
                              borderRadius: '6px',
                              background:
                                us.verdictCanonical === 'MALICIOUS'
                                  ? '#FDE1DE'
                                  : us.verdictCanonical === 'SUSPICIOUS'
                                  ? '#FFF7EC'
                                  : us.verdictCanonical === 'SAFE_NO_THREAT_FOUND'
                                  ? '#EDFBF2'
                                  : '#F4EFE6',
                              color:
                                us.verdictCanonical === 'MALICIOUS'
                                  ? '#DC2626'
                                  : us.verdictCanonical === 'SUSPICIOUS'
                                  ? '#EA580C'
                                  : us.verdictCanonical === 'SAFE_NO_THREAT_FOUND'
                                  ? '#16A34A'
                                  : '#655E54',
                            }}
                          >
                            {us.verdictCanonical || us.verdict}
                          </span>
                        </div>
                        {us.indicators && us.indicators.length > 0 && (
                          <div style={{ fontSize: '12px', color: '#655E54' }}>
                            {us.indicators.map((ind) => ind.description).join('; ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Bottom Actions Row */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '8px' }}>
                <button type="button" className="nav-cta-btn" onClick={onClose} style={{ fontSize: '13.5px', padding: '9px 20px' }}>
                  <span>{language === 'hi' ? 'दूसरा स्कैन करें' : 'Done / New Scan'}</span>
                </button>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════════
              FEATURE 4: SUCCESSFUL EVIDENCE-BASED WEBSITE INSPECTION VIEW
          ══════════════════════════════════════════════════════════════════════ */}
          {!loading && !error && analysisResult && isUrlMode && (
            <div className="modal-result-panel">
              {/* Top Target Domain Bar */}
              <div
                style={{
                  background: '#FFF7EC',
                  border: '1px solid #E7DED0',
                  borderRadius: '14px',
                  padding: '12px 16px',
                  marginBottom: '16px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '10px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {analysisResult.normalizedUrl?.isHttps ? (
                    <span title="Uses HTTPS Transport" style={{ color: '#16A34A', display: 'flex' }}>
                      <Lock size={16} />
                    </span>
                  ) : (
                    <span title="Insecure HTTP Transport" style={{ color: '#EA580C', display: 'flex' }}>
                      <Unlock size={16} />
                    </span>
                  )}
                  <span style={{ fontWeight: 800, fontSize: '15px', color: '#171717' }}>
                    {analysisResult.safeDisplayUrl || analysisResult.normalizedUrl?.hostname || query}
                  </span>
                  <span
                    style={{
                      fontSize: '11px',
                      background: '#FFFFFF',
                      border: '1px solid #E7DED0',
                      padding: '2px 8px',
                      borderRadius: '12px',
                      color: '#655E54',
                    }}
                  >
                    {analysisResult.normalizedUrl?.protocol?.replace(':', '').toUpperCase() || 'HTTP'}
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <button
                    type="button"
                    onClick={copyReportSummary}
                    style={{
                      background: '#FFFFFF',
                      border: '1px solid #E7DED0',
                      color: '#171717',
                      padding: '4px 10px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '12px',
                      fontWeight: 600,
                    }}
                  >
                    {copied ? <Check size={13} color="#16A34A" /> : <Copy size={13} />}
                    {copied ? 'Copied Report' : 'Copy Report'}
                  </button>
                </div>
              </div>

              {/* Main Score & Canonical Verdict Hero Card */}
              <div className="website-gauge-card" style={{ borderColor: scoreTheme.border }}>
                {/* Circular Gauge SVG */}
                <div className="gauge-svg-container">
                  <svg className="gauge-svg" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r={radius} fill="transparent" stroke="#E7DED0" strokeWidth="9" />
                    <circle
                      cx="50"
                      cy="50"
                      r={radius}
                      fill="transparent"
                      stroke={scoreTheme.color}
                      strokeWidth="9"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      strokeLinecap="round"
                      style={{ transition: 'stroke-dashoffset 0.8s ease' }}
                    />
                  </svg>
                  <div className="gauge-center-text">
                    <span style={{ fontSize: '26px', fontWeight: 900, color: scoreTheme.color, lineHeight: 1 }}>
                      {analysisResult.riskScore !== null && analysisResult.riskScore !== undefined
                        ? analysisResult.riskScore
                        : '—'}
                    </span>
                    <span style={{ display: 'block', fontSize: '11px', fontWeight: 700, color: '#655E54' }}>
                      /100
                    </span>
                  </div>
                </div>

                {/* Score Verdict Info */}
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '4px 12px',
                        borderRadius: '20px',
                        fontSize: '12px',
                        fontWeight: 800,
                        letterSpacing: '0.03em',
                        background: scoreTheme.bg,
                        color: scoreTheme.color,
                        border: `1px solid ${scoreTheme.border}`,
                      }}
                    >
                      {scoreTheme.icon}
                      <span>{scoreTheme.label.toUpperCase()}</span>
                    </span>

                    <span
                      style={{
                        fontSize: '11px',
                        color: analysisResult.riskScore === null ? '#D97706' : '#655E54',
                        fontWeight: analysisResult.riskScore === null ? 700 : 600,
                      }}
                    >
                      {analysisResult.riskScore === null
                        ? language === 'hi'
                          ? 'जोखिम स्कोर अनुपलब्ध — अपर्याप्त साक्ष्य'
                          : 'Risk score unavailable — insufficient evidence'
                        : language === 'hi'
                        ? 'प्रमाण-आधारित जोखिम स्कोर'
                        : 'Evidence-Based Risk Score'}
                    </span>
                  </div>

                  <h4 style={{ fontSize: '18px', fontWeight: 800, color: '#171717', margin: '4px 0' }}>
                    {analysisResult.normalizedUrl?.registeredDomain || analysisResult.normalizedUrl?.hostname}
                  </h4>

                  <p style={{ fontSize: '13px', color: '#655E54', lineHeight: 1.45, margin: 0 }}>
                    {analysisResult.verdictExplanation || analysisResult.whyThisResult?.summary || analysisResult.summary}
                  </p>
                </div>
              </div>

              {/* SECTION: WHY THIS RESULT? (FEATURE 4 TRANSPARENCY REQUIREMENT) */}
              {analysisResult.whyThisResult && (
                <div className="why-result-box">
                  <div className="why-result-header" onClick={() => setExpandedWhy(!expandedWhy)}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Info size={16} color="#B83B00" />
                      <strong style={{ fontSize: '13.5px', color: '#171717' }}>
                        {language === 'hi' ? 'यह परिणाम क्यों आया? (Why this result?):' : 'Why this result? (Transparent Rationale):'}
                      </strong>
                    </div>
                    {expandedWhy ? <ChevronUp size={16} color="#655E54" /> : <ChevronDown size={16} />}
                  </div>

                  {expandedWhy && (
                    <div style={{ marginTop: '10px', fontSize: '13px', color: '#171717', lineHeight: 1.45 }}>
                      <p style={{ margin: '0 0 8px 0' }}>{analysisResult.whyThisResult.summary}</p>
                      {analysisResult.whyThisResult.factors && analysisResult.whyThisResult.factors.length > 0 && (
                        <ul style={{ paddingLeft: '18px', margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {analysisResult.whyThisResult.factors.map((factor, idx) => (
                            <li key={idx} style={{ color: '#4B453E' }}>
                              {factor}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* SECTION: CHECKS PERFORMED VS NOT PERFORMED (FEATURE 4 REQUIREMENT) */}
              {(analysisResult.checksPerformed?.length > 0 || analysisResult.checksNotPerformed?.length > 0) && (
                <div style={{ marginBottom: '18px' }}>
                  <div
                    style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', marginBottom: '8px' }}
                    onClick={() => setExpandedChecks(!expandedChecks)}
                  >
                    <span style={{ fontSize: '12px', fontWeight: 800, color: '#655E54', textTransform: 'uppercase' }}>
                      Scope of Verification ({analysisResult.checksPerformed?.length || 0} Performed, {analysisResult.checksNotPerformed?.length || 0} Skipped)
                    </span>
                    {expandedChecks ? <ChevronUp size={14} color="#655E54" /> : <ChevronDown size={14} />}
                  </div>

                  {expandedChecks && (
                    <div className="checks-scope-grid">
                      {/* Performed Checks */}
                      <div>
                        <span style={{ fontSize: '11px', color: '#16A34A', fontWeight: 700, textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
                          Active Checks Completed:
                        </span>
                        <div className="checks-pill-group">
                          {analysisResult.checksPerformed?.map((c, i) => (
                            <span key={i} className="check-pill performed">
                              <CheckCircle2 size={12} color="#16A34A" />
                              <span>{typeof c === 'string' ? c : `${c.name || c.check || 'Check'}: ${c.status || 'PASS'}`}</span>
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Not Performed Checks */}
                      {analysisResult.checksNotPerformed?.length > 0 && (
                        <div>
                          <span style={{ fontSize: '11px', color: '#88898D', fontWeight: 700, textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
                            Checks Not Performed / Limitations:
                          </span>
                          <div className="checks-pill-group">
                            {analysisResult.checksNotPerformed?.map((c, i) => (
                              <span key={i} className="check-pill not-performed" title={typeof c === 'string' ? c : c.reason || ''}>
                                <AlertCircle size={12} color="#88898D" />
                                <span>{typeof c === 'string' ? c : `${c.name || c.check || 'Check'}${c.reason ? ` (${c.reason})` : ''}`}</span>
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Multi-Signal Investigation Evidence Cards (Grid) */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px', marginBottom: '22px' }}>
                {/* 1. Threat Intelligence Card (Google Web Risk) */}
                <div className="check-status-card evidence-row-animated">
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#655E54', textTransform: 'uppercase' }}>
                    Google Web Risk Intel
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {analysisResult.reputation?.lookupStatus === 'THREAT_FOUND' || analysisResult.reputation?.reputationStatus === 'confirmed_threat' ? (
                      <ShieldAlert size={16} color="#DC2626" />
                    ) : analysisResult.reputation?.lookupStatus === 'NO_MATCH_FOUND' || analysisResult.reputation?.reputationStatus === 'no_known_threat_detected' ? (
                      <ShieldCheck size={16} color="#16A34A" />
                    ) : (
                      <AlertCircle size={16} color="#88898D" />
                    )}
                    <span
                      style={{
                        fontWeight: 700,
                        fontSize: '12.5px',
                        color:
                          analysisResult.reputation?.lookupStatus === 'THREAT_FOUND' || analysisResult.reputation?.reputationStatus === 'confirmed_threat'
                            ? '#DC2626'
                            : analysisResult.reputation?.lookupStatus === 'NO_MATCH_FOUND' || analysisResult.reputation?.reputationStatus === 'no_known_threat_detected'
                            ? '#16A34A'
                            : '#655E54',
                      }}
                    >
                      {analysisResult.reputation?.lookupStatus === 'THREAT_FOUND'
                        ? 'Threat Found'
                        : analysisResult.reputation?.lookupStatus === 'NO_MATCH_FOUND'
                        ? 'No Match Found'
                        : analysisResult.reputation?.lookupStatus === 'NOT_CONFIGURED' || analysisResult.reputation?.reputationStatus === 'not_configured'
                        ? 'Not Configured'
                        : 'Unavailable'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#88898D', lineHeight: 1.3 }}>
                    {analysisResult.reputation?.lookupStatus === 'NOT_CONFIGURED' || analysisResult.reputation?.reputationStatus === 'not_configured'
                      ? 'Google Web Risk API key not set. External threat lookup skipped.'
                      : analysisResult.reputation?.lookupStatus === 'NO_MATCH_FOUND'
                      ? 'Clean on Google Web Risk blocklist. (Note: Clean blocklist does not prove website legitimacy).'
                      : analysisResult.reputation?.lookupStatus === 'THREAT_FOUND'
                      ? `Threat matched: ${(analysisResult.reputation.matchedThreatTypes || []).join(', ')}`
                      : 'Threat intelligence telemetry status.'}
                  </span>
                </div>

                {/* 2. Domain Registration (RDAP) Card */}
                <div className="check-status-card evidence-row-animated">
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#655E54', textTransform: 'uppercase' }}>
                    Domain Age (RDAP)
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Globe size={16} color={analysisResult.checks?.rdap?.data?.isVeryNewDomain ? '#EA580C' : '#B83B00'} />
                    <span style={{ fontWeight: 700, fontSize: '12.5px', color: analysisResult.checks?.rdap?.data?.isVeryNewDomain ? '#EA580C' : '#171717' }}>
                      {analysisResult.checks?.rdap?.data?.ageDays !== null && analysisResult.checks?.rdap?.data?.ageDays !== undefined
                        ? `${analysisResult.checks?.rdap?.data?.ageDays} days old`
                        : analysisResult.checks?.rdap?.status === 'no_data'
                        ? 'Record Not Found'
                        : 'Unavailable'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#88898D', lineHeight: 1.3 }}>
                    {analysisResult.checks?.rdap?.data?.registrationDate
                      ? `Reg: ${analysisResult.checks.rdap.data.registrationDate.split('T')[0]}`
                      : analysisResult.checks?.rdap?.explanation || 'Public registry data.'}
                  </span>
                </div>

                {/* 3. DNS Resolution Card */}
                <div className="check-status-card evidence-row-animated">
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#655E54', textTransform: 'uppercase' }}>
                    DNS Resolution
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Search size={16} color={analysisResult.checks?.dns?.data?.ssrfBlocked ? '#DC2626' : '#B83B00'} />
                    <span style={{ fontWeight: 700, fontSize: '12.5px', color: analysisResult.checks?.dns?.data?.ssrfBlocked ? '#DC2626' : '#171717' }}>
                      {analysisResult.checks?.dns?.data?.ssrfBlocked
                        ? 'Private IP Blocked'
                        : analysisResult.checks?.dns?.data?.hasA
                        ? `${analysisResult.checks.dns.data.resolvedIps?.length || 1} IP(s) Active`
                        : 'No A Records'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#88898D', lineHeight: 1.3 }}>
                    {analysisResult.checks?.dns?.data?.hasMx ? 'MX mail exchange configured.' : 'No MX records found.'}
                  </span>
                </div>

                {/* 4. TLS/HTTPS Certificate Card */}
                <div className="check-status-card evidence-row-animated">
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#655E54', textTransform: 'uppercase' }}>
                    TLS/SSL Security
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {analysisResult.checks?.tls?.data?.authorized ? (
                      <Lock size={16} color="#16A34A" />
                    ) : (
                      <Unlock size={16} color="#EA580C" />
                    )}
                    <span
                      style={{
                        fontWeight: 700,
                        fontSize: '12.5px',
                        color: analysisResult.checks?.tls?.data?.authorized ? '#16A34A' : '#EA580C',
                      }}
                    >
                      {analysisResult.checks?.tls?.data?.authorized
                        ? 'Valid Certificate'
                        : analysisResult.checks?.tls?.status === 'no_data'
                        ? 'No HTTPS'
                        : 'Unverified / Expired'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#88898D', lineHeight: 1.3 }}>
                    {analysisResult.checks?.tls?.data?.issuer
                      ? `Issuer: ${analysisResult.checks.tls.data.issuer}`
                      : 'Certificate metadata inspection.'}
                  </span>
                </div>

                {/* 5. Safe Redirect Chain Security Card */}
                <div className="check-status-card evidence-row-animated">
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#655E54', textTransform: 'uppercase' }}>
                    Safe Redirect Chain
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Radio
                      size={16}
                      color={
                        analysisResult.checks?.redirects?.status === 'ssrf_blocked' ||
                        analysisResult.checks?.redirects?.status === 'redirect_loop'
                          ? '#DC2626'
                          : analysisResult.checks?.redirects?.data?.hasCrossDomainRedirect
                          ? '#EA580C'
                          : '#16A34A'
                      }
                    />
                    <span
                      style={{
                        fontWeight: 700,
                        fontSize: '12.5px',
                        color:
                          analysisResult.checks?.redirects?.status === 'ssrf_blocked' ||
                          analysisResult.checks?.redirects?.status === 'redirect_loop'
                            ? '#DC2626'
                            : analysisResult.checks?.redirects?.data?.hasCrossDomainRedirect
                            ? '#EA580C'
                            : '#16A34A',
                      }}
                    >
                      {analysisResult.checks?.redirects?.status === 'ssrf_blocked'
                        ? 'SSRF Hop Blocked'
                        : analysisResult.checks?.redirects?.status === 'redirect_loop'
                        ? 'Redirect Loop'
                        : analysisResult.checks?.redirects?.data?.hasCrossDomainRedirect
                        ? 'Cross-Domain Redirect'
                        : (analysisResult.checks?.redirects?.data?.hopCount || 1) > 1
                        ? `${analysisResult.checks.redirects.data.hopCount} Hops Verified`
                        : 'Direct Destination'}
                    </span>
                  </div>
                  <span style={{ fontSize: '11px', color: '#88898D', lineHeight: 1.3 }}>
                    {analysisResult.checks?.redirects?.explanation || 'Hop-by-hop SSRF validation.'}
                  </span>
                </div>
              </div>

              {/* SECTION: STRUCTURED TECHNICAL FINDINGS (FEATURE 4 REQUIREMENT) */}
              <div style={{ marginBottom: '20px' }}>
                <div
                  style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', marginBottom: '10px' }}
                  onClick={() => setExpandedFindings(!expandedFindings)}
                >
                  <h5 style={{ fontSize: '13.5px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', margin: 0 }}>
                    {language === 'hi' ? 'जाँचे गए तकनीकी साक्ष्य एवं निष्कर्ष:' : 'Structured Technical Findings:'}
                  </h5>
                  {expandedFindings ? <ChevronUp size={16} color="#655E54" /> : <ChevronDown size={16} />}
                </div>

                {expandedFindings && (
                  <div>
                    {analysisResult.structuredFindings && analysisResult.structuredFindings.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {analysisResult.structuredFindings.map((finding, idx) => (
                          <div key={idx} className="structured-finding-card evidence-row-animated">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span className={`finding-status-tag ${finding.status}`}>
                                  {finding.status}
                                </span>
                                <span style={{ fontSize: '12.5px', fontWeight: 800, color: '#171717' }}>
                                  {finding.title}
                                </span>
                              </div>
                              <span
                                style={{
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  textTransform: 'uppercase',
                                  color: finding.severity === 'critical' ? '#DC2626' : finding.severity === 'high' ? '#EA580C' : '#655E54',
                                }}
                              >
                                {finding.severity}
                              </span>
                            </div>

                            <p style={{ fontSize: '12.5px', color: '#4B453E', margin: '4px 0 2px 0', lineHeight: 1.4 }}>
                              {finding.explanation}
                            </p>

                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: '#88898D', marginTop: '2px' }}>
                              <span>Evidence: {formatFindingEvidence(finding.evidence)}</span>
                              <span className="source-badge">{finding.source}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : analysisResult.indicators && analysisResult.indicators.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {analysisResult.indicators.map((ind, idx) => (
                          <div key={idx} className="indicator-item-card evidence-row-animated">
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span className="source-badge">{ind.source}</span>
                              <span style={{ fontSize: '11px', fontWeight: 700, color: '#EA580C' }}>{ind.severity}</span>
                            </div>
                            <div style={{ fontSize: '13px', color: '#171717', marginTop: '2px' }}>
                              <strong>{ind.category}: </strong>
                              <span>{ind.description}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div
                        style={{
                          background: analysisResult.verdictCanonical === 'UNKNOWN' ? '#FFFBEB' : '#EDFBF2',
                          border: `1px solid ${analysisResult.verdictCanonical === 'UNKNOWN' ? 'rgba(217, 119, 6, 0.3)' : '#BCE9C8'}`,
                          borderRadius: '12px',
                          padding: '14px 16px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '12px',
                        }}
                      >
                        {analysisResult.verdictCanonical === 'UNKNOWN' ? (
                          <AlertCircle size={20} color="#D97706" />
                        ) : (
                          <CheckCircle2 size={20} color="#16A34A" />
                        )}
                        <div>
                          <strong style={{ fontSize: '13.5px', color: analysisResult.verdictCanonical === 'UNKNOWN' ? '#B45309' : '#0E7A36', display: 'block' }}>
                            {analysisResult.verdictCanonical === 'UNKNOWN'
                              ? 'No Known Technical Threat Matches (Unverified Domain)'
                              : 'No Known Technical Threat Matches (Recognized Domain)'}
                          </strong>
                          <span style={{ fontSize: '12.5px', color: '#171717' }}>
                            {analysisResult.verdictCanonical === 'UNKNOWN'
                              ? 'Google Web Risk and heuristic checks found no listed threats. However, absence of evidence is not proof of safety.'
                              : 'Standard structural, DNS, and threat intelligence checks completed clean for recognized domain.'}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Honest Scan Limitations Notice */}
              <div
                style={{
                  background: '#F9F8F6',
                  border: '1px solid #E7DED0',
                  borderRadius: '12px',
                  padding: '12px 14px',
                  marginBottom: '18px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                }}
              >
                <Shield size={16} color="#655E54" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ fontSize: '12px', color: '#655E54', lineHeight: 1.45 }}>
                  <strong style={{ color: '#171717', display: 'block', marginBottom: '2px' }}>
                    {language === 'hi' ? 'जाँच की सीमाएँ (Scan Limitations):' : 'Important Scan Limitations:'}
                  </strong>
                  <span>
                    {analysisResult.limitations && analysisResult.limitations.length > 0
                      ? analysisResult.limitations.join(' • ')
                      : 'This investigation evaluates DNS records, TLS certificates, safe redirect paths, and Google Web Risk telemetry. Clean blocklist results do NOT guarantee that a website is genuine.'}
                  </span>
                </div>
              </div>

              {/* Actionable Safety Recommendations */}
              {analysisResult.safetyAdvice && analysisResult.safetyAdvice.length > 0 && (
                <div
                  style={{
                    background: isHighRisk ? '#FDE1DE' : '#FFF7EC',
                    border: `1px solid ${isHighRisk ? 'rgba(220, 38, 38, 0.4)' : '#E7DED0'}`,
                    borderRadius: '16px',
                    padding: '16px 18px',
                    marginBottom: '22px',
                  }}
                >
                  <h5
                    style={{
                      fontSize: '13.5px',
                      fontWeight: 800,
                      color: isHighRisk ? '#DC2626' : '#B83B00',
                      marginBottom: '10px',
                    }}
                  >
                    {language === 'hi' ? 'सुरक्षा अनुशंसाएँ (Safety Recommendations):' : 'Safety Recommendations & Advice:'}
                  </h5>
                  <ul
                    style={{
                      paddingLeft: '20px',
                      fontSize: '13px',
                      color: '#171717',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                      lineHeight: 1.45,
                      margin: 0,
                    }}
                  >
                    {analysisResult.safetyAdvice.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Bottom Actions Row */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', paddingTop: '8px' }}>
                <button
                  type="button"
                  className="nav-cta-btn"
                  onClick={onClose}
                  style={{ fontSize: '13.5px', padding: '9px 20px' }}
                >
                  <span>{language === 'hi' ? 'दूसरी वेबसाइट जाँचें' : 'Check Another Website'}</span>
                </button>

                <button
                  type="button"
                  onClick={executeAnalysis}
                  style={{
                    background: '#FFFFFF',
                    border: '1px solid #E7DED0',
                    color: '#655E54',
                    padding: '8px 16px',
                    borderRadius: '20px',
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                  }}
                >
                  <RefreshCw size={14} />
                  <span>Re-scan</span>
                </button>
              </div>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════════
              ORIGINAL MESSAGE SCAM ANALYSIS VIEW (PRESERVED)
          ══════════════════════════════════════════════════════════════════════ */}
          {!loading && !error && analysisResult && !isUrlMode && !isImageMode && (
            <div className="modal-result-panel">
              {/* Analyzed Snippet Box */}
              <div
                style={{
                  background: '#FFF7EC',
                  border: '1px solid #E7DED0',
                  borderRadius: '14px',
                  padding: '14px 16px',
                  marginBottom: '18px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '11.5px', fontWeight: 800, textTransform: 'uppercase', color: '#B83B00', letterSpacing: '0.04em' }}>
                    {language === 'hi' ? 'विश्लेषित इनपुट' : 'Analyzed Message'}
                  </span>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        background: '#FFFFFF',
                        border: '1px solid #E7DED0',
                        color: '#655E54',
                        padding: '2px 8px',
                        borderRadius: '9999px',
                        fontWeight: 600,
                      }}
                    >
                      Engine: {analysisResult.engine || 'gemini+rules_v1'}
                    </span>
                    <button
                      onClick={copyReportSummary}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#655E54',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        fontSize: '12px',
                      }}
                    >
                      {copied ? <Check size={14} color="#171717" /> : <Copy size={14} />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                </div>
                <p style={{ fontSize: '13.5px', color: '#171717', wordBreak: 'break-all', fontStyle: 'italic', lineHeight: 1.45, margin: 0 }}>
                  "{query}"
                </p>
              </div>

              {/* Risk Level & Score Hero Card */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 20px',
                  borderRadius: '16px',
                  background: isHighRisk ? '#FDE1DE' : '#FFF7EC',
                  border: `1px solid ${isHighRisk ? 'rgba(204, 25, 29, 0.4)' : '#E7DED0'}`,
                  marginBottom: '20px',
                }}
              >
                <div>
                  <span
                    style={{
                      display: 'inline-block',
                      fontSize: '11.5px',
                      fontWeight: 800,
                      color: isHighRisk ? '#CC191D' : '#B83B00',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                    }}
                  >
                    {isHighRisk ? 'HIGH RISK SCAM PATTERN' : 'LOW RISK / CAUTION'}
                  </span>
                  <h4 style={{ fontSize: '17px', fontWeight: 800, color: '#171717', marginTop: '2px' }}>
                    {analysisResult.scamType?.replace(/_/g, ' ').toUpperCase()}
                  </h4>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ fontSize: '28px', fontWeight: 900, color: isHighRisk ? '#CC191D' : '#B83B00' }}>
                    {analysisResult.riskScore}/100
                  </span>
                  <div style={{ fontSize: '11px', color: '#655E54', fontWeight: 700 }}>
                    HEURISTIC RISK SCORE
                  </div>
                </div>
              </div>

              {/* Summary Statement */}
              {analysisResult.summary && (
                <p style={{ fontSize: '14px', lineHeight: 1.55, color: '#171717', marginBottom: '20px' }}>
                  {analysisResult.summary}
                </p>
              )}

              {/* Message Threat Indicators */}
              {analysisResult.threatIndicators && analysisResult.threatIndicators.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                  <h5 style={{ fontSize: '13px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', marginBottom: '10px' }}>
                    {language === 'hi' ? 'पहचाने गए खतरे के संकेत:' : 'Key Threat Indicators:'}
                  </h5>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {analysisResult.threatIndicators.map((flag, idx) => (
                      <div
                        key={idx}
                        className="evidence-row-animated"
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '10px',
                          fontSize: '13px',
                          color: '#171717',
                          background: '#FEFBF4',
                          padding: '10px 14px',
                          borderRadius: '10px',
                          border: '1px solid #E7DED0',
                        }}
                      >
                        <AlertTriangle size={16} color="#B83B00" style={{ flexShrink: 0, marginTop: '2px' }} />
                        <div>
                          <strong>{flag.category?.replace(/_/g, ' ')}: </strong>
                          <span>{flag.evidence}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sender & Channel Intelligence Card */}
              {analysisResult.senderIntel && analysisResult.senderIntel.checked && (
                <div
                  className="evidence-row-animated"
                  style={{
                    marginBottom: '18px',
                    background: analysisResult.senderIntel.isSuspicious ? '#FDE1DE' : '#FEFBF4',
                    border: `1px solid ${analysisResult.senderIntel.isSuspicious ? 'rgba(220, 38, 38, 0.4)' : '#E7DED0'}`,
                    borderRadius: '12px',
                    padding: '12px 14px',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                  }}
                >
                  <Phone
                    size={16}
                    color={analysisResult.senderIntel.isSuspicious ? '#DC2626' : '#B83B00'}
                    style={{ flexShrink: 0, marginTop: '2px' }}
                  />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                      <strong style={{ fontSize: '12.5px', color: '#171717' }}>
                        {analysisResult.senderIntel.senderType === 'trai_dlt_header'
                          ? 'TRAI DLT Verified Enterprise Header'
                          : analysisResult.senderIntel.senderType === 'indian_mobile'
                          ? 'Indian Mobile Number (+91)'
                          : 'Sender Intelligence'}
                      </strong>
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '1px 7px',
                          borderRadius: '10px',
                          background: analysisResult.senderIntel.isSuspicious ? '#FEE2E2' : '#DCFCE7',
                          color: analysisResult.senderIntel.isSuspicious ? '#DC2626' : '#16A34A',
                        }}
                      >
                        {analysisResult.senderIntel.reputationStatus?.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <p style={{ fontSize: '12.5px', color: '#655E54', margin: 0, lineHeight: 1.4 }}>
                      {analysisResult.senderIntel.explanation}
                    </p>
                  </div>
                </div>
              )}

              {/* Verbatim Evidence Excerpts from Submitted Text */}
              {analysisResult.evidenceExcerpts && analysisResult.evidenceExcerpts.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                  <h5 style={{ fontSize: '13px', fontWeight: 800, color: '#171717', textTransform: 'uppercase', marginBottom: '10px' }}>
                    {language === 'hi' ? 'संदेश से निकाले गए साक्ष्य (Evidence Excerpts):' : 'Evidence Excerpts from Submitted Text:'}
                  </h5>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {analysisResult.evidenceExcerpts.map((item, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: '#FFF7EC',
                          border: '1px solid #E7DED0',
                          borderRadius: '10px',
                          padding: '10px 14px',
                          fontSize: '12.5px',
                        }}
                      >
                        <span style={{ fontSize: '10.5px', fontWeight: 800, color: '#B83B00', textTransform: 'uppercase', display: 'block', marginBottom: '2px' }}>
                          Matched: {item.category?.replace(/_/g, ' ')}
                        </span>
                        <code style={{ fontSize: '13px', color: '#171717', fontWeight: 600 }}>
                          {item.excerpt}
                        </code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted Entities */}
              {analysisResult.entities &&
                (analysisResult.entities.urls?.length > 0 ||
                  analysisResult.entities.phoneNumbers?.length > 0 ||
                  analysisResult.entities.upiIds?.length > 0) && (
                  <div style={{ marginBottom: '20px', background: '#FEFBF4', padding: '12px 14px', borderRadius: '12px', border: '1px solid #E7DED0' }}>
                    <span style={{ fontSize: '11.5px', fontWeight: 800, textTransform: 'uppercase', color: '#655E54', display: 'block', marginBottom: '8px' }}>
                      Extracted Unverified Entities:
                    </span>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {analysisResult.entities.urls?.map((u, i) => (
                        <span key={i} style={{ fontSize: '12px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                          🔗 {u}
                        </span>
                      ))}
                      {analysisResult.entities.phoneNumbers?.map((p, i) => (
                        <span key={i} style={{ fontSize: '12px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                          📞 {p}
                        </span>
                      ))}
                      {analysisResult.entities.upiIds?.map((up, i) => (
                        <span key={i} style={{ fontSize: '12px', background: '#FFF7EC', border: '1px solid #E7DED0', padding: '2px 8px', borderRadius: '6px' }}>
                          💳 {up}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

              {/* Practical Safety Advice */}
              {analysisResult.safetyAdvice && analysisResult.safetyAdvice.length > 0 && (
                <div
                  style={{
                    background: '#FFF7EC',
                    border: '1px solid #E7DED0',
                    borderRadius: '16px',
                    padding: '16px 18px',
                    marginBottom: '22px',
                  }}
                >
                  <h5 style={{ fontSize: '13.5px', fontWeight: 800, color: '#B83B00', marginBottom: '10px' }}>
                    {language === 'hi' ? 'सुरक्षा दिशानिर्देश (Actionable Safety Steps):' : 'Actionable Safety Advice:'}
                  </h5>
                  <ul style={{ paddingLeft: '20px', fontSize: '13px', color: '#171717', display: 'flex', flexDirection: 'column', gap: '6px', lineHeight: 1.45 }}>
                    {analysisResult.safetyAdvice.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
