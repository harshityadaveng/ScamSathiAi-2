import React, { useState, useEffect } from 'react';
import {
  Search,
  Shield,
  AlertTriangle,
  Globe,
  Link as LinkIcon,
  QrCode,
  Image as ImageIcon,
  FileText,
  Sparkles,
  Lock,
  X,
} from 'lucide-react';

/**
 * Stage definitions for each analysis mode.
 * Completely removed any customer satisfaction or irrelevant text.
 * Strictly focused on real scam and cybersecurity telemetry stages.
 */
const STAGES_BY_MODE = {
  message: [
    {
      id: 'input',
      icon: Search,
      titleEn: 'Validating input context',
      titleHi: 'संदेश सामग्री व संदर्भ की पुष्टि',
      descEn: 'Sanitizing text and identifying sender identifiers...',
      descHi: 'संदेश की भाषा, प्रेषक व प्रारूप का सत्यापन...',
    },
    {
      id: 'patterns',
      icon: AlertTriangle,
      titleEn: 'Scanning for scam patterns',
      titleHi: 'धोखाधड़ी पैटर्न का विश्लेषण',
      descEn: 'Detecting urgency triggers, impersonation & financial traps...',
      descHi: 'तात्कालिकता, बैंक प्रतिरूपण व लॉटरी जाल की पहचान...',
    },
    {
      id: 'links',
      icon: LinkIcon,
      titleEn: 'Checking links & contact signals',
      titleHi: 'लिंक एवं संपर्क नंबर की जाँच',
      descEn: 'Inspecting embedded URLs, TRAI headers & UPI IDs...',
      descHi: 'अज्ञात यूआरएल, टीआरएआई हेडर व यूपीआई आईडी का सत्यापन...',
    },
    {
      id: 'intel',
      icon: Shield,
      titleEn: 'Reviewing threat intelligence',
      titleHi: 'खतरे की खुफिया जानकारी की समीक्षा',
      descEn: 'Cross-referencing known fraud registries & threat databases...',
      descHi: 'साइबर सुरक्षा डेटाबेस व ज्ञात फ़िशिंग रिकॉर्ड से मिलान...',
    },
    {
      id: 'report',
      icon: Sparkles,
      titleEn: 'Preparing the analysis report',
      titleHi: 'सुरक्षा रिपोर्ट तैयार की जा रही है',
      descEn: 'Synthesizing risk assessment & protective recommendations...',
      descHi: 'जोखिम स्कोर एवं सुरक्षात्मक कदमों का संकलन...',
    },
  ],
  url: [
    {
      id: 'input',
      icon: Search,
      titleEn: 'Validating URL structure',
      titleHi: 'यूआरएल संरचना का सत्यापन',
      descEn: 'Resolving protocol, hostname & path elements...',
      descHi: 'प्रोटोकॉल, होस्टनेम और पथ की वैधता जाँच...',
    },
    {
      id: 'domain',
      icon: Globe,
      titleEn: 'Checking URL and domain signals',
      titleHi: 'डोमेन एवं सुरक्षा संकेतकों की जाँच',
      descEn: 'Inspecting domain age, SSL certificate & DNS telemetry...',
      descHi: 'डोमेन आयु, एसएसएल प्रमाणपत्र एवं डीएनएस रिकॉर्ड...',
    },
    {
      id: 'patterns',
      icon: AlertTriangle,
      titleEn: 'Analyzing suspicious patterns',
      titleHi: 'संदिग्ध प्रतिरूपण पैटर्न की जाँच',
      descEn: 'Screening brand spoofing, typosquatting & redirect chains...',
      descHi: 'नकली ब्रांड, टाइपो व गुप्त रीडायरेक्ट की खोज...',
    },
    {
      id: 'intel',
      icon: Shield,
      titleEn: 'Reviewing threat intelligence',
      titleHi: 'धमकी खुफिया डेटाबेस से मिलान',
      descEn: 'Querying Google Web Risk, VirusTotal & domain blocklists...',
      descHi: 'वेब रिस्क व ब्लॉकलिस्ट में दुर्भावनापूर्ण स्थिति की जाँच...',
    },
    {
      id: 'report',
      icon: Sparkles,
      titleEn: 'Preparing the analysis report',
      titleHi: 'विस्तृत रिपोर्ट तैयार की जा रही है',
      descEn: 'Evaluating heuristic evidence & authoritative safety verdict...',
      descHi: 'प्रमाण-आधारित निष्कर्ष व सुरक्षा स्कोर का संश्लेषण...',
    },
  ],
  image: [
    {
      id: 'input',
      icon: ImageIcon,
      titleEn: 'Validating image buffer & MIME safety',
      titleHi: 'इमेज बफ़र व प्रारूप का सत्यापन',
      descEn: 'Processing in volatile memory without disk persistence...',
      descHi: 'सुरक्षित मेमोरी बफ़र में फ़ाइल प्रारूप की पुष्टि...',
    },
    {
      id: 'qr',
      icon: QrCode,
      titleEn: 'Scanning for QR & payment traps',
      titleHi: 'क्यूआर कोड व यूपीआई ट्रैप की खोज',
      descEn: 'Decoding QR matrices and inspecting UPI collect parameters...',
      descHi: 'क्यूआर मैट्रिक्स डिकोडिंग व अनधिकृत भुगतान जाँच...',
    },
    {
      id: 'patterns',
      icon: FileText,
      titleEn: 'Analyzing suspicious patterns via OCR',
      titleHi: 'ओसीआर टेक्स्ट एवं पैटर्न का विश्लेषण',
      descEn: 'Extracting visual text, urgency cues & unverified links...',
      descHi: 'स्क्रीनशॉट से टेक्स्ट निष्कर्षण व जालसाजी के संकेत...',
    },
    {
      id: 'intel',
      icon: Shield,
      titleEn: 'Reviewing threat intelligence',
      titleHi: 'निकाले गए लिंक की सुरक्षा समीक्षा',
      descEn: 'Checking extracted domains against threat databases...',
      descHi: 'निकाले गए वेब पतों की प्रतिष्ठा डेटाबेस में जाँच...',
    },
    {
      id: 'report',
      icon: Sparkles,
      titleEn: 'Preparing the analysis report',
      titleHi: 'मल्टी-सिग्नल रिपोर्ट का निर्माण',
      descEn: 'Synthesizing visual, QR & heuristic risk scores...',
      descHi: 'क्यूआर, टेक्स्ट व लिंक जोखिम स्कोर का एकीकरण...',
    },
  ],
};

export default function AnalysisLoadingScreen({
  mode = 'message',
  language = 'en',
  onClose,
}) {
  const stages = STAGES_BY_MODE[mode] || STAGES_BY_MODE.message;

  // Active focus cycles sequentially to honestly represent the indeterminate multi-layered pipeline
  const [activeStageIndex, setActiveStageIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveStageIndex((prev) => (prev + 1) % stages.length);
    }, 1400);
    return () => clearInterval(interval);
  }, [stages.length]);

  // Support ESC key to cancel/close
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Dynamic badge and text by mode
  const getBadgeDetails = () => {
    if (mode === 'url') {
      return {
        icon: Globe,
        text: language === 'hi' ? 'वेबसाइट सुरक्षा जाँच' : 'Analyzing Website',
        subtitle:
          language === 'hi'
            ? 'हमारा एआई फ़िशिंग, ब्रांड प्रतिरूपण और डोमेन सुरक्षा संकेतकों का मूल्यांकन कर रहा है।'
            : 'Our AI is evaluating the website for phishing traps, brand impersonation, and domain threat signals.',
        scannerLabel: language === 'hi' ? 'वेबसाइट स्कैनिंग जारी...' : 'SCANNING WEBSITE...',
      };
    }
    if (mode === 'image') {
      return {
        icon: QrCode,
        text: language === 'hi' ? 'स्क्रीनशॉट व क्यूआर जाँच' : 'Analyzing Image & QR',
        subtitle:
          language === 'hi'
            ? 'हमारा एआई क्यूआर पेमेंट जाल, ओसीआर टेक्स्ट और संदिग्ध लिंक की सुरक्षा जाँच कर रहा है।'
            : 'Our AI is inspecting the image for embedded QR payment traps, OCR text signals, and suspicious links.',
        scannerLabel: language === 'hi' ? 'इमेज व क्यूआर स्कैनिंग...' : 'SCANNING IMAGE & QR...',
      };
    }
    return {
      icon: Search,
      text: language === 'hi' ? 'संदेश विश्लेषण जारी' : 'Analyzing Message',
      subtitle:
        language === 'hi'
          ? 'हमारा एआई संभावित धोखाधड़ी पैटर्न, संदिग्ध लिंक और जोखिम संकेतकों का विश्लेषण कर रहा है।'
          : 'Our AI is analyzing the message for possible scam patterns, suspicious links and risk indicators.',
      scannerLabel: language === 'hi' ? 'संदेश स्कैनिंग जारी...' : 'SCANNING MESSAGE...',
    };
  };

  const badgeInfo = getBadgeDetails();
  const BadgeIcon = badgeInfo.icon;
  const CenterIcon = mode === 'url' ? Globe : mode === 'image' ? QrCode : Shield;

  return (
    <div
      className="analysis-loading-wrapper"
      role="status"
      aria-live="polite"
      onClick={(e) => e.stopPropagation()}
    >
      {/* Close / Cancel Button */}
      {onClose && (
        <button
          type="button"
          onClick={onClose}
          className="analysis-loading-close-btn"
          aria-label={language === 'hi' ? 'जाँच रद्द करें' : 'Cancel analysis'}
          title={language === 'hi' ? 'जाँच रद्द करें' : 'Cancel analysis'}
        >
          <X size={20} />
        </button>
      )}

      {/* Top Header Section */}
      <div className="analysis-loading-header">
        {/* Pill Tag */}
        <div className="analysis-loading-pill">
          <BadgeIcon size={14} className="analysis-pill-icon" />
          <span>{badgeInfo.text}</span>
        </div>

        {/* Mandatory Heading */}
        <h2 className="analysis-loading-heading">
          <span>
            {language === 'hi' ? 'संभावित धोखाधड़ी का विश्लेषण' : 'Analyzing for Potential Scams'}
          </span>
          <span className="analysis-loading-dots" aria-hidden="true">
            <span>.</span>
            <span>.</span>
            <span>.</span>
          </span>
        </h2>

        {/* Reassuring Subtitle */}
        <p className="analysis-loading-subtext">{badgeInfo.subtitle}</p>
      </div>

      {/* Main Dual-Column Scanning Card */}
      <div className="analysis-loading-card">
        {/* Left Column: Cybersecurity Scanner Visualization */}
        <div className="analysis-scanner-col">
          <div className="analysis-scanner-stage">
            {/* Concentric Pulsing Radar Waves */}
            <div className="analysis-pulse-wave wave-1" aria-hidden="true" />
            <div className="analysis-pulse-wave wave-2" aria-hidden="true" />

            {/* Radar Conic Sweep Beam */}
            <div className="analysis-radar-sweep" aria-hidden="true" />

            {/* Precision SVG Rings & Rotating Security Arcs */}
            <svg
              className="analysis-scanner-svg"
              viewBox="0 0 240 240"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              {/* Outer Calibration Track */}
              <circle
                cx="120"
                cy="120"
                r="110"
                stroke="#E7DED0"
                strokeWidth="1.5"
                strokeDasharray="4 6"
              />

              {/* Mid Track */}
              <circle
                cx="120"
                cy="120"
                r="86"
                stroke="rgba(245, 169, 0, 0.28)"
                strokeWidth="1.2"
              />

              {/* Inner Track */}
              <circle
                cx="120"
                cy="120"
                r="64"
                stroke="rgba(184, 59, 0, 0.2)"
                strokeWidth="1"
                strokeDasharray="3 5"
              />

              {/* Primary Rotating Burnt-Orange Security Arc */}
              <circle
                className="analysis-rotating-arc-outer"
                cx="120"
                cy="120"
                r="110"
                stroke="#B83B00"
                strokeWidth="3.6"
                strokeLinecap="round"
                strokeDasharray="140 551"
              />

              {/* Secondary Counter-Rotating Gold Arc */}
              <circle
                className="analysis-rotating-arc-mid"
                cx="120"
                cy="120"
                r="86"
                stroke="#F5A900"
                strokeWidth="2.8"
                strokeLinecap="round"
                strokeDasharray="80 460"
              />

              {/* Primary Orbiting Security Node */}
              <g className="analysis-rotating-arc-outer">
                <circle cx="120" cy="10" r="4.5" fill="#B83B00" />
                <circle cx="120" cy="10" r="7" stroke="rgba(184, 59, 0, 0.4)" strokeWidth="1" />
              </g>

              {/* Secondary Orbiting Satellite */}
              <g className="analysis-rotating-arc-mid">
                <circle cx="120" cy="34" r="3.5" fill="#F5A900" />
              </g>

              {/* Radar Crosshair / Tick Marks */}
              <line x1="120" y1="4" x2="120" y2="12" stroke="rgba(184, 59, 0, 0.4)" strokeWidth="1.5" />
              <line x1="120" y1="228" x2="120" y2="236" stroke="rgba(184, 59, 0, 0.4)" strokeWidth="1.5" />
              <line x1="4" y1="120" x2="12" y2="120" stroke="rgba(184, 59, 0, 0.4)" strokeWidth="1.5" />
              <line x1="228" y1="120" x2="236" y2="120" stroke="rgba(184, 59, 0, 0.4)" strokeWidth="1.5" />
            </svg>

            {/* Glowing Center Core */}
            <div className="analysis-scanner-core">
              <div className="analysis-core-inner">
                <CenterIcon size={28} color="#FFFFFF" strokeWidth={2.3} />
                {/* Subtle Laser Scan Line */}
                <div className="analysis-core-laser" aria-hidden="true" />
              </div>
            </div>
          </div>

          {/* Bottom Tracking Status Label */}
          <div className="analysis-scanner-label" aria-hidden="true">
            {badgeInfo.scannerLabel}
          </div>
        </div>

        {/* Right Column: Analysis Stages List */}
        <div className="analysis-stages-col">
          <div className="analysis-stages-list">
            {stages.map((stage, idx) => {
              const StageIcon = stage.icon;
              const isActive = idx === activeStageIndex;

              return (
                <div
                  key={stage.id}
                  className={`analysis-stage-row ${isActive ? 'is-active-focus' : ''}`}
                >
                  {/* Stage Icon Badge */}
                  <div className={`analysis-stage-icon-wrap ${isActive ? 'is-active' : ''}`}>
                    <StageIcon size={18} strokeWidth={2.2} />
                  </div>

                  {/* Stage Details */}
                  <div className="analysis-stage-content">
                    <div className="analysis-stage-title">
                      {language === 'hi' ? stage.titleHi : stage.titleEn}
                    </div>
                    <div className="analysis-stage-desc">
                      {language === 'hi' ? stage.descHi : stage.descEn}
                    </div>
                  </div>

                  {/* Honest Indeterminate Status Indicator */}
                  <div className="analysis-stage-indicator" aria-hidden="true">
                    {isActive ? (
                      <div className="analysis-stage-spinner" />
                    ) : (
                      <div className="analysis-stage-bullet" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Genuine Backend Telemetry Footnote */}
          <div className="analysis-stages-footer">
            <Lock size={12} className="analysis-footer-icon" />
            <span>
              {language === 'hi'
                ? 'रीयल-टाइम एआई सुरक्षा पाइपलाइन • बहु-संकेतक विश्लेषण प्रगति पर'
                : 'Live multi-signal security pipeline • Real-time backend analysis in progress'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
