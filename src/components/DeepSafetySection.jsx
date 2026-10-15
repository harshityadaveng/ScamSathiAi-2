import React from 'react';
import { MessageSquareWarning, Link2, ShieldCheck, ArrowRight, AlertCircle, Lock, Smartphone } from 'lucide-react';

export default function DeepSafetySection({ onAnalyzeClick, language }) {
  return (
    <section id="safety-section" className="section-light">
      <div className="section-container">
        {/* Header Section */}
        <div className="section-header-center scroll-reveal">
          <div className="section-badge">
            <ShieldCheck size={14} />
            <span>{language === 'hi' ? 'साइबर जागरूकता एवं रोकथाम' : 'Cyber Awareness & Prevention'}</span>
          </div>

          <h2 className="section-title">
            {language === 'hi'
              ? 'क्लिक करने से पहले सोचें। एक कदम आगे रहें।'
              : 'Think Before You Click. Stay One Step Ahead.'}
          </h2>

          <p className="section-subtitle">
            {language === 'hi'
              ? 'संदिग्ध संदेशों को समझें, सामान्य चेतावनी संकेतों को पहचानें और लिंक, ऑफ़र और भुगतान अनुरोधों को सत्यापित करने के सुरक्षित तरीके जानें।'
              : 'Understand suspicious messages, spot common warning signs, and learn safer ways to verify links, offers, and payment requests.'}
          </p>
        </div>

        {/* 3 Core Feature Blocks */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
            gap: '24px',
            marginBottom: '64px'
          }}
        >
          {/* Block 1: Message Analysis */}
          <div
            className="deep-safety-card scroll-reveal stagger-1"
            style={{
              background: '#FFFFFF',
              border: '1px solid #E7DED0',
              borderRadius: '22px',
              padding: '32px 28px',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)'
            }}
          >
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '14px',
                background: 'rgba(245, 169, 0, 0.15)',
                color: '#B83B00',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '20px'
              }}
            >
              <MessageSquareWarning size={24} />
            </div>

            <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#171717', marginBottom: '12px' }}>
              {language === 'hi' ? 'संदेश विश्लेषण' : 'Message Analysis'}
            </h3>

            <p style={{ fontSize: '14.5px', color: '#655E54', lineHeight: 1.5, marginBottom: '20px' }}>
              {language === 'hi'
                ? 'संदिग्ध संदेशों में चेतावनी संकेतों को समझें। कृत्रिम तात्कालिकता, लॉटरी के झूठे दावों और अनधिकृत फोन नंबरों की तुरंत पहचान करें।'
                : 'Understand warning signs in suspicious messages. Identify artificial urgency, fake lottery claims, and unauthorized phone numbers.'}
            </p>

            <div
              style={{
                background: '#FFF7EC',
                padding: '12px 14px',
                borderRadius: '12px',
                border: '1px solid #E7DED0',
                fontSize: '13px',
                color: '#171717'
              }}
            >
              <strong>Red Flag:</strong> "Action required within 2 hours or penalty will apply."
            </div>
          </div>

          {/* Block 2: Link Awareness */}
          <div
            className="deep-safety-card scroll-reveal stagger-2"
            style={{
              background: '#FFFFFF',
              border: '1px solid #E7DED0',
              borderRadius: '22px',
              padding: '32px 28px',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)'
            }}
          >
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '14px',
                background: 'rgba(245, 169, 0, 0.15)',
                color: '#B83B00',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '20px'
              }}
            >
              <Link2 size={24} />
            </div>

            <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#171717', marginBottom: '12px' }}>
              {language === 'hi' ? 'लिंक जागरूकता' : 'Link Awareness'}
            </h3>

            <p style={{ fontSize: '14.5px', color: '#655E54', lineHeight: 1.5, marginBottom: '20px' }}>
              {language === 'hi'
                ? 'संदिग्ध यूआरएल और भ्रामक लिंक को पहचानना सीखें। नकली डोमेन, शॉर्टनर्स और खतरनाक .APK फ़ाइलों से बचें।'
                : 'Learn to recognize suspicious URLs and misleading links. Detect lookalike domains, spoofed banking pages, and risky .APK downloads.'}
            </p>

            <div
              style={{
                background: '#FFF7EC',
                padding: '12px 14px',
                borderRadius: '12px',
                border: '1px solid #E7DED0',
                fontSize: '13px',
                color: '#171717'
              }}
            >
              <strong>Lookalike check:</strong> `sbi-netbanking.top` vs official `onlinesbi.sbi`
            </div>
          </div>

          {/* Block 3: Cyber Safety Guidance */}
          <div
            className="deep-safety-card scroll-reveal stagger-3"
            style={{
              background: '#FFFFFF',
              border: '1px solid #E7DED0',
              borderRadius: '22px',
              padding: '32px 28px',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)'
            }}
          >
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '14px',
                background: 'rgba(245, 169, 0, 0.15)',
                color: '#B83B00',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '20px'
              }}
            >
              <Lock size={24} />
            </div>

            <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#171717', marginBottom: '12px' }}>
              {language === 'hi' ? 'साइबर सुरक्षा मार्गदर्शन' : 'Cyber Safety Guidance'}
            </h3>

            <p style={{ fontSize: '14.5px', color: '#655E54', lineHeight: 1.5, marginBottom: '20px' }}>
              {language === 'hi'
                ? 'अपने बैंक खातों और व्यक्तिगत डेटा की सुरक्षा के लिए व्यावहारिक कदम खोजें। कभी भी यूपीआई पिन दर्ज न करें पैसे प्राप्त करने के लिए।'
                : 'Discover practical steps to protect your accounts and money. Remember: You never need to enter a UPI PIN to receive money.'}
            </p>

            <div
              style={{
                background: '#FFF7EC',
                padding: '12px 14px',
                borderRadius: '12px',
                border: '1px solid #E7DED0',
                fontSize: '13px',
                color: '#171717'
              }}
            >
              <strong>Golden Rule:</strong> UPI PIN is ONLY entered to deduct money, NEVER to receive.
            </div>
          </div>
        </div>

        {/* Call-to-action Section */}
        <div
          className="scroll-reveal"
          style={{
            background: '#FFF7EC',
            border: '1px solid #E7DED0',
            borderRadius: '28px',
            padding: '52px 36px',
            textAlign: 'center',
            maxWidth: '860px',
            margin: '0 auto',
            position: 'relative',
            overflow: 'hidden'
          }}
        >
          <h3 style={{ fontSize: 'clamp(1.8rem, 3vw, 2.4rem)', fontWeight: 850, color: '#171717', marginBottom: '14px' }}>
            {language === 'hi' ? 'संदेह होने पर, पहले जाँचें।' : 'When in Doubt, Check First.'}
          </h3>

          <p style={{ fontSize: '16px', color: '#655E54', maxWidth: '580px', margin: '0 auto 28px auto', lineHeight: 1.5 }}>
            {language === 'hi'
              ? 'एक सेकंड की सावधानी आपको और आपके परिवार को हजारों रुपये के साइबर नुकसान से बचा सकती है।'
              : 'A one-second check with ScamSathi AI can save you from devastating financial fraud.'}
          </p>

          <button
            type="button"
            className="nav-cta-btn"
            style={{ fontSize: '16px', padding: '14px 32px' }}
            onClick={onAnalyzeClick}
          >
            <span>{language === 'hi' ? 'संदेश का विश्लेषण करें' : 'Analyze a Message'}</span>
            <ArrowRight size={18} />
          </button>
        </div>
      </div>
    </section>
  );
}
