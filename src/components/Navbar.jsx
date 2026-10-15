import React, { useState } from 'react';
import { Globe, ChevronDown, Menu, X } from 'lucide-react';
import BrandLogo from './BrandLogo';

export default function Navbar({ onOpenAnalyze, language, setLanguage }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [langDropdownOpen, setLangDropdownOpen] = useState(false);

  const scrollToSection = (id) => {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="nav-container-wrapper">
      <nav className="nav-bar" aria-label="Main Navigation">
        {/* Left Column: Brand Logo */}
        <div className="nav-left-col">
          <BrandLogo size={26} />
        </div>

        {/* Center Column: Navigation Links */}
        <div className="nav-links-row">
          <button
            type="button"
            className="nav-link-item active"
            onClick={() => onOpenAnalyze()}
          >
            {language === 'hi' ? 'संदेश जाँचें' : 'Analyze Message'}
          </button>

          <button
            type="button"
            className="nav-link-item"
            onClick={() => scrollToSection('safety-section')}
          >
            {language === 'hi' ? 'साइबर सुरक्षा' : 'Cyber Safety'}
          </button>

          <button
            type="button"
            className="nav-link-item"
            onClick={() => scrollToSection('helpline-section')}
          >
            {language === 'hi' ? 'रिपोर्ट व हेल्पलाइन' : 'Report & Helplines'}
          </button>

          <button
            type="button"
            className="nav-link-item"
            onClick={() => scrollToSection('about-section')}
          >
            {language === 'hi' ? 'हमारे बारे में' : 'About'}
          </button>
        </div>

        {/* Right Column: Language Switcher & Mobile Menu Toggle */}
        <div className="nav-right-col">
          {/* Language Switcher Dropdown */}
          <div style={{ position: 'relative' }}>
            <button
              type="button"
              className="nav-lang-btn"
              onClick={() => setLangDropdownOpen(!langDropdownOpen)}
              aria-label="Change language"
            >
              <Globe size={15} />
              <span>{language === 'hi' ? 'HI' : 'EN'}</span>
              <ChevronDown size={13} />
            </button>

            {langDropdownOpen && (
              <div
                style={{
                  position: 'absolute',
                  top: '100%',
                  right: 0,
                  marginTop: '6px',
                  background: '#FFFFFF',
                  border: '1px solid #E7DED0',
                  borderRadius: '10px',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.1)',
                  padding: '5px',
                  zIndex: 60,
                  minWidth: '115px'
                }}
              >
                <button
                  type="button"
                  style={{
                    display: 'block',
                    width: '100%',
                    padding: '6px 10px',
                    textAlign: 'left',
                    background: language === 'en' ? '#FFF7EC' : 'transparent',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: language === 'en' ? 700 : 500,
                    color: '#171717',
                    cursor: 'pointer',
                    fontSize: '13px'
                  }}
                  onClick={() => {
                    setLanguage('en');
                    setLangDropdownOpen(false);
                  }}
                >
                  English (EN)
                </button>
                <button
                  type="button"
                  style={{
                    display: 'block',
                    width: '100%',
                    padding: '6px 10px',
                    textAlign: 'left',
                    background: language === 'hi' ? '#FFF7EC' : 'transparent',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: language === 'hi' ? 700 : 500,
                    color: '#171717',
                    cursor: 'pointer',
                    fontSize: '13px'
                  }}
                  onClick={() => {
                    setLanguage('hi');
                    setLangDropdownOpen(false);
                  }}
                >
                  हिन्दी (HI)
                </button>
              </div>
            )}
          </div>

          {/* Mobile Menu Toggle Button */}
          <button
            type="button"
            className="mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div
          style={{
            position: 'absolute',
            top: '62px',
            left: '16px',
            right: '16px',
            background: '#FFFFFF',
            borderRadius: '16px',
            boxShadow: '0 16px 40px rgba(0,0,0,0.12)',
            border: '1px solid #E7DED0',
            padding: '16px',
            zIndex: 60,
            display: 'flex',
            flexDirection: 'column',
            gap: '12px'
          }}
        >
          <button
            type="button"
            className="nav-link-item active"
            style={{ textAlign: 'left', fontSize: '16px' }}
            onClick={() => { setMobileMenuOpen(false); onOpenAnalyze(); }}
          >
            {language === 'hi' ? 'संदेश जाँचें' : 'Analyze Message'}
          </button>
          <button
            type="button"
            className="nav-link-item"
            style={{ textAlign: 'left', fontSize: '16px' }}
            onClick={() => scrollToSection('safety-section')}
          >
            {language === 'hi' ? 'साइबर सुरक्षा' : 'Cyber Safety'}
          </button>
          <button
            type="button"
            className="nav-link-item"
            style={{ textAlign: 'left', fontSize: '16px' }}
            onClick={() => scrollToSection('helpline-section')}
          >
            {language === 'hi' ? 'रिपोर्ट व हेल्पलाइन' : 'Report & Helplines'}
          </button>
          <button
            type="button"
            className="nav-link-item"
            style={{ textAlign: 'left', fontSize: '16px' }}
            onClick={() => scrollToSection('about-section')}
          >
            {language === 'hi' ? 'हमारे बारे में' : 'About'}
          </button>

          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', paddingTop: '10px', borderTop: '1px solid #E7DED0' }}>
            <button
              type="button"
              style={{
                background: 'none',
                border: '1px solid #E7DED0',
                padding: '8px 16px',
                borderRadius: '8px',
                fontWeight: 600,
                fontSize: '14px',
                cursor: 'pointer'
              }}
              onClick={() => {
                setLanguage(language === 'en' ? 'hi' : 'en');
                setMobileMenuOpen(false);
              }}
            >
              🌐 {language === 'en' ? 'Switch to हिन्दी' : 'Switch to English'}
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
