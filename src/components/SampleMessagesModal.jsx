import React from 'react';
import { X, ArrowRight, Zap, Building, Briefcase, ShieldAlert, Award } from 'lucide-react';

const SAMPLES = [
  {
    id: 'electricity',
    category: 'Electricity Bill Scam',
    icon: Zap,
    text: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please contact electricity officer at 9876543210 immediately.',
    risk: 'High Risk (94%)'
  },
  {
    id: 'kyc',
    category: 'Banking / PAN KYC Phishing',
    icon: Building,
    text: 'Dear Customer, your bank account ending in 4102 has been temporarily BLOCKED due to expired PAN KYC. Visit http://sbi-pan-kyc.xyz/verify now to update or your account will be closed.',
    risk: 'High Risk (96%)'
  },
  {
    id: 'job',
    category: 'Part-Time Telegram Job Fraud',
    icon: Briefcase,
    text: 'Congratulations! You are shortlisted for Part-Time Work From Home job. Just like YouTube videos and earn ₹2,500 to ₹8,000 daily. WhatsApp / Telegram HR directly on +91-9812345678.',
    risk: 'High Risk (92%)'
  },
  {
    id: 'digital_arrest',
    category: 'Digital Arrest / Police Impersonation',
    icon: ShieldAlert,
    text: 'Mumbai Crime Branch Alert: A parcel containing illegal narcotics and fake passports was intercepted in your name. Connect immediately on Skype / WhatsApp video call for judicial verification.',
    risk: 'Extreme Risk (98%)'
  },
  {
    id: 'lottery',
    category: 'Lottery & Prize Advance-Fee Scam',
    icon: Award,
    text: 'Dear winner, your SIM number has won ₹25,00,000 in KBC All India WhatsApp Lucky Draw. Contact KBC manager Rajiv Sharma on WhatsApp at 9988776655 to claim your prize.',
    risk: 'High Risk (90%)'
  }
];

export default function SampleMessagesModal({ onClose, onSelectSample, language }) {
  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#171717' }}>
              {language === 'hi' ? 'वास्तविक नमूना संदेश चुनें' : 'Choose a Sample Scam Message'}
            </h3>
            <p style={{ fontSize: '13px', color: '#655E54' }}>
              {language === 'hi' ? 'देखें कि स्कैमसाथी एआई वास्तविक घोटालों का विश्लेषण कैसे करता है' : 'Test ScamSathi AI detection on real-world Indian cyber threats'}
            </p>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#88898D', padding: '6px' }}
            aria-label="Close modal"
          >
            <X size={20} />
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {SAMPLES.map((sample) => {
            const IconComponent = sample.icon;
            return (
              <div
                key={sample.id}
                onClick={() => onSelectSample(sample.text)}
                style={{
                  background: '#FFF7EC',
                  border: '1px solid #E7DED0',
                  borderRadius: '16px',
                  padding: '16px 18px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '14px'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = '#B83B00';
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = '0 6px 16px rgba(184, 59, 0, 0.08)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = '#E7DED0';
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '50%',
                    background: '#FFFFFF',
                    border: '1px solid #E7DED0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#B83B00',
                    flexShrink: 0
                  }}
                >
                  <IconComponent size={20} />
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 800, color: '#171717' }}>
                      {sample.category}
                    </span>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: '#CC191D', background: '#FDE1DE', padding: '2px 8px', borderRadius: '9999px' }}>
                      {sample.risk}
                    </span>
                  </div>
                  <p style={{ fontSize: '13.5px', color: '#655E54', lineHeight: 1.45 }}>
                    "{sample.text}"
                  </p>
                </div>

                <div style={{ alignSelf: 'center', color: '#B83B00' }}>
                  <ArrowRight size={18} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
