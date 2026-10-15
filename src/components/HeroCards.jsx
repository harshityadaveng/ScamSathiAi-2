import React from 'react';
import { Search } from 'lucide-react';

export default function HeroCards({ onCardClick, language }) {
  return (
    <div className="hero-cards-grid" role="region" aria-label="Core features">
      {/* Card 1: AI-powered message analysis */}
      <div
        className="hero-card scroll-reveal stagger-1"
        onClick={() => onCardClick('message-analysis')}
        tabIndex={0}
        role="button"
        aria-label="AI-powered message analysis"
      >
        <div className="hero-card-icon-wrap" aria-hidden="true">
          <svg
            width="26"
            height="26"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </div>

        <h3 className="hero-card-title">
          {language === 'hi' ? (
            <>एआई-संचालित<br />संदेश विश्लेषण</>
          ) : (
            <>AI-powered<br />message analysis</>
          )}
        </h3>

        <p className="hero-card-desc">
          {language === 'hi'
            ? 'उन्नत एआई और नियम-आधारित जांच के साथ संदिग्ध पैटर्न का पता लगाएँ।'
            : 'Detect suspicious patterns with advanced AI and rule-based checks.'}
        </p>
      </div>

      {/* Card 2: Clear risk indicators */}
      <div
        className="hero-card scroll-reveal stagger-2"
        onClick={() => onCardClick('risk-indicators')}
        tabIndex={0}
        role="button"
        aria-label="Clear risk indicators"
      >
        <div className="hero-card-icon-wrap" aria-hidden="true">
          <Search size={25} strokeWidth={2.3} />
        </div>

        <h3 className="hero-card-title">
          {language === 'hi' ? 'स्पष्ट जोखिम संकेतक' : 'Clear risk indicators'}
        </h3>

        <p className="hero-card-desc">
          {language === 'hi'
            ? 'सटीक रूप से समझें कि कोई संदेश संदिग्ध क्यों है, सरल सबूतों के साथ।'
            : 'See exactly why a message looks suspicious, with evidence you can understand.'}
        </p>
      </div>

      {/* Card 3: Safety steps in Hindi & English */}
      <div
        className="hero-card scroll-reveal stagger-3"
        onClick={() => onCardClick('multilingual-safety')}
        tabIndex={0}
        role="button"
        aria-label="Safety steps in Hindi & English"
      >
        <div className="hero-card-icon-wrap" aria-hidden="true">
          {/* Custom Stylized 'अA' Badge matching reference image */}
          <span
            style={{
              fontWeight: 800,
              fontSize: '20px',
              letterSpacing: '-0.02em',
              lineHeight: 1,
              fontFamily: 'system-ui, sans-serif'
            }}
          >
            अA
          </span>
        </div>

        <h3 className="hero-card-title">
          {language === 'hi' ? (
            <>सुरक्षा कदम<br />हिन्दी और अंग्रेज़ी में</>
          ) : (
            <>Safety steps in<br />Hindi & English</>
          )}
        </h3>

        <p className="hero-card-desc">
          {language === 'hi'
            ? 'ऑनलाइन सुरक्षित रहने के लिए सरल, व्यावहारिक और त्वरित सुझाव प्राप्त करें।'
            : 'Get simple, actionable advice to stay safe online.'}
        </p>
      </div>
    </div>
  );
}
