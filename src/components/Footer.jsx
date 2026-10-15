import React from 'react';
import BrandLogo from './BrandLogo';

export default function Footer({ language }) {
  const scrollTo = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <footer id="about-section" className="footer-wrapper">
      <div className="footer-content">
        <div className="footer-top-row">
          {/* Brand Info */}
          <div className="footer-brand">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
              <div style={{ width: '32px', height: '32px' }}>
                <svg viewBox="0 0 36 36" width="32" height="32" fill="none">
                  <path
                    d="M18 3.5L5.5 8.2V16.8C5.5 24.3 10.8 31.2 18 33C25.2 31.2 30.5 24.3 30.5 16.8V8.2L18 3.5Z"
                    fill="#171717"
                    stroke="#B83B00"
                    strokeWidth="3.2"
                  />
                  <path
                    d="M12.5 17.5L16.2 21.2L23.8 13.5"
                    stroke="#F5A900"
                    strokeWidth="3.2"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <span style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF' }}>
                ScamSathi<span style={{ color: '#B83B00' }}>AI</span>
              </span>
            </div>

            <p style={{ fontSize: '14px', lineHeight: 1.6, color: '#88898D', maxWidth: '340px' }}>
              {language === 'hi'
                ? 'भारतीय नागरिकों को डिजिटल घोटालों, फर्जी एसएमएस और ऑनलाइन धोखाधड़ी से सुरक्षित रखने के लिए बनाया गया एआई-संचालित मंच।'
                : 'Empowering citizens with rapid AI-driven scam detection and cybersecurity awareness in Hindi and English.'}
            </p>
          </div>

          {/* Links Columns */}
          <div className="footer-links-group">
            <div className="footer-col">
              <h4>Platform</h4>
              <ul>
                <li><a href="#" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>Home</a></li>
                <li><a href="#safety-section" onClick={(e) => { e.preventDefault(); scrollTo('safety-section'); }}>Safety Tips</a></li>
                <li><a href="#helpline-section" onClick={(e) => { e.preventDefault(); scrollTo('helpline-section'); }}>Report Scam</a></li>
              </ul>
            </div>

            <div className="footer-col">
              <h4>Helplines</h4>
              <ul>
                <li><a href="tel:1930">National Helpline 1930</a></li>
                <li><a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">CyberCrime Portal</a></li>
                <li><a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener noreferrer">Sanchar Saathi</a></li>
              </ul>
            </div>

            <div className="footer-col">
              <h4>Legal & Policy</h4>
              <ul>
                <li><a href="#" onClick={(e) => e.preventDefault()}>Privacy Policy</a></li>
                <li><a href="#" onClick={(e) => e.preventDefault()}>Terms of Service</a></li>
                <li><a href="#" onClick={(e) => e.preventDefault()}>Disclaimer</a></li>
              </ul>
            </div>
          </div>
        </div>

        {/* Disclaimer & Bottom Bar */}
        <div className="footer-bottom-bar">
          <p>
            © {new Date().getFullYear()} ScamSathi AI. All rights reserved.
          </p>
          <p style={{ maxWidth: '640px', fontSize: '12px', lineHeight: 1.5 }}>
            Disclaimer: ScamSathi AI provides educational analysis and risk indicators based on known scam patterns. It does not replace official police investigations or banking authentication.
          </p>
        </div>
      </div>
    </footer>
  );
}
