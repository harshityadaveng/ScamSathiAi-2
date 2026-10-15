import React, { useState } from 'react';
import { Phone, ShieldAlert, ExternalLink, Clock, Copy, Check } from 'lucide-react';

export default function HelplineSection({ language }) {
  const [copiedHelpline, setCopiedHelpline] = useState(false);

  const handleCopyHelpline = () => {
    navigator.clipboard.writeText('1930');
    setCopiedHelpline(true);
    setTimeout(() => setCopiedHelpline(false), 2000);
  };

  return (
    <section id="helpline-section" className="section-light" style={{ background: '#FFF7EC' }}>
      <div className="section-container">
        <div className="section-header-center scroll-reveal">
          <div className="section-badge" style={{ background: '#FDE1DE', color: '#CC191D', borderColor: 'rgba(204,25,29,0.3)' }}>
            <ShieldAlert size={14} />
            <span>{language === 'hi' ? 'आपातकालीन सहायता' : 'Emergency Assistance'}</span>
          </div>

          <h2 className="section-title">
            {language === 'hi' ? 'साइबर धोखाधड़ी की रिपोर्ट करें' : 'Report Scams & Official Helplines'}
          </h2>

          <p className="section-subtitle">
            {language === 'hi'
              ? 'यदि आपके साथ या किसी परिचित के साथ वित्तीय धोखाधड़ी हुई है, तो तुरंत भारत सरकार के राष्ट्रीय साइबर अपराध पोर्टल पर रिपोर्ट करें।'
              : 'If you or someone you know has been targeted by financial fraud, take immediate action during the Golden Hour.'}
          </p>
        </div>

        <div className="helpline-grid">
          {/* Card 1: 1930 National Helpline */}
          <div className="helpline-card alert scroll-reveal stagger-1">
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <span style={{ fontSize: '12px', fontWeight: 800, color: '#CC191D', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  National Cyber Crime Helpline
                </span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', color: '#655E54' }}>
                  <Clock size={13} /> 24x7 Available
                </span>
              </div>

              <h3 style={{ fontSize: '36px', fontWeight: 900, color: '#CC191D', letterSpacing: '-0.02em', marginBottom: '8px' }}>
                1930
              </h3>

              <p style={{ fontSize: '14px', color: '#655E54', lineHeight: 1.5 }}>
                Toll-free national emergency number operated by the Ministry of Home Affairs (MHA), Government of India, to freeze fraudulent fund transfers.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '24px' }}>
              <a
                href="tel:1930"
                className="helpline-btn helpline-btn-primary"
                style={{ flex: 1 }}
              >
                <Phone size={16} />
                <span>Call 1930</span>
              </a>

              <button
                type="button"
                className="helpline-btn helpline-btn-secondary"
                onClick={handleCopyHelpline}
                style={{ padding: '12px 16px' }}
                title="Copy helpline number"
              >
                {copiedHelpline ? <Check size={16} color="#171717" /> : <Copy size={16} />}
              </button>
            </div>
          </div>

          {/* Card 2: CyberCrime Portal */}
          <div className="helpline-card scroll-reveal stagger-2">
            <div>
              <span style={{ fontSize: '12px', fontWeight: 800, color: '#B83B00', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '16px' }}>
                Official Government Portal
              </span>

              <h3 style={{ fontSize: '24px', fontWeight: 800, color: '#171717', marginBottom: '8px' }}>
                cybercrime.gov.in
              </h3>

              <p style={{ fontSize: '14px', color: '#655E54', lineHeight: 1.5 }}>
                File an official online FIR for financial frauds, online harassment, social media identity theft, and cyber bullying directly to law enforcement.
              </p>
            </div>

            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="helpline-btn helpline-btn-secondary"
            >
              <span>Visit Portal</span>
              <ExternalLink size={16} />
            </a>
          </div>

          {/* Card 3: Golden Hour Action */}
          <div className="helpline-card scroll-reveal stagger-3">
            <div>
              <span style={{ fontSize: '12px', fontWeight: 800, color: '#B05D27', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '16px' }}>
                Golden Hour Checklist
              </span>

              <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#171717', marginBottom: '12px' }}>
                Act Within 2 Hours
              </h3>

              <ul style={{ paddingLeft: '18px', fontSize: '13.5px', color: '#655E54', display: 'flex', flexDirection: 'column', gap: '8px', lineHeight: 1.4 }}>
                <li>Call 1930 immediately with transaction UTR numbers.</li>
                <li>Block your ATM card and net banking via official bank app.</li>
                <li>Take screenshots of the chat, SMS, and transaction slips.</li>
              </ul>
            </div>

            <div style={{ marginTop: '20px', fontSize: '12.5px', color: '#88898D', fontStyle: 'italic' }}>
              Prompt reporting increases money recovery chances up to 85%.
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
