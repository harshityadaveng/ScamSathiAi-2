import React, { useState, useRef } from 'react';
import { Search, X, ArrowRight, QrCode } from 'lucide-react';

export default function HeroSearch({ onAnalyze, onAnalyzeImage, onOpenSampleModal, language, isAnalyzing }) {
  const [query, setQuery] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isAnalyzing) return;
    if (!query.trim()) {
      setErrorMessage(
        language === 'hi'
          ? 'कृपया जाँच करने के लिए कोई संदिग्ध संदेश या लिंक दर्ज करें।'
          : 'Please enter a suspicious message or link to analyze.'
      );
      setTimeout(() => setErrorMessage(''), 3500);
      return;
    }
    setErrorMessage('');
    onAnalyze(query.trim());
  };

  const handleClear = () => {
    setQuery('');
    setErrorMessage('');
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      setErrorMessage(
        language === 'hi'
          ? 'फ़ाइल का आकार 5MB की सीमा से अधिक है।'
          : 'Image size exceeds maximum limit of 5MB.'
      );
      setTimeout(() => setErrorMessage(''), 3500);
      e.target.value = '';
      return;
    }

    if (onAnalyzeImage) {
      onAnalyzeImage(file);
    }
    e.target.value = '';
  };

  return (
    <div className="hero-search-container">
      {/* Hidden file input for screenshot and QR scanning */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/png,image/jpeg,image/webp"
        style={{ display: 'none' }}
        onChange={handleFileChange}
        aria-label="Upload Screenshot or QR code image"
      />

      <form onSubmit={handleSubmit} className="hero-search-pill" role="search">
        {/* Search Icon */}
        <Search size={22} className="hero-search-icon" aria-hidden="true" />

        {/* Text Input */}
        <input
          type="text"
          className="hero-search-input"
          placeholder={
            language === 'hi'
              ? 'वेबसाइट यूआरएल, संदेश या क्यूआर कोड स्कैन करें...'
              : 'Paste website URL, message, or scan QR/screenshot...'
          }
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            if (errorMessage) setErrorMessage('');
          }}
          aria-label="Paste website URL or suspicious message"
        />

        {/* Clear Button (Visible when text present) */}
        {query.length > 0 && (
          <button
            type="button"
            className="hero-clear-btn"
            onClick={handleClear}
            title="Clear text"
            aria-label="Clear input"
          >
            <X size={18} />
          </button>
        )}

        {/* QR Code / Screenshot Upload Button */}
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          title={language === 'hi' ? 'स्क्रीनशॉट या क्यूआर कोड अपलोड करें' : 'Scan Screenshot or QR Code'}
          aria-label="Scan Screenshot or QR Code"
          style={{
            background: 'none',
            border: 'none',
            color: '#B83B00',
            cursor: 'pointer',
            padding: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '50%',
            marginRight: '2px',
            transition: 'opacity 0.2s',
          }}
        >
          <QrCode size={20} strokeWidth={2.2} />
        </button>

        {/* Circular Submit Button with Arrow */}
        <button
          type="submit"
          className="hero-search-submit-btn"
          aria-label="Check Website or Message"
          title={isAnalyzing ? (language === 'hi' ? 'जाँच जारी है...' : 'Scanning...') : query.includes('.') ? 'Check Website' : 'Analyze'}
          disabled={isAnalyzing}
          aria-busy={isAnalyzing}
        >
          <ArrowRight size={22} strokeWidth={2.4} />
        </button>
      </form>

      {/* Validation / Helper message */}
      {errorMessage && (
        <div
          style={{
            position: 'absolute',
            top: '82px',
            left: '50%',
            transform: 'translateX(-50%)',
            background: '#FDE1DE',
            color: '#CC191D',
            padding: '6px 16px',
            borderRadius: '9999px',
            fontSize: '13px',
            fontWeight: 600,
            boxShadow: '0 4px 12px rgba(204, 25, 29, 0.12)',
            zIndex: 10,
            whiteSpace: 'nowrap',
          }}
        >
          {errorMessage}
        </div>
      )}

      {/* Secondary CTA underneath search with Quick Sample Links */}
      <div className="hero-subcta-row" style={{ flexWrap: 'wrap', gap: '8px 12px' }}>
        <span className="hero-subcta-text">
          {language === 'hi' ? 'त्वरित विकल्प:' : 'Quick tests:'}
        </span>
        <button
          type="button"
          onClick={() => onAnalyze('google.com')}
          style={{
            background: 'none',
            border: 'none',
            color: '#B83B00',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 700,
            padding: 0,
            textDecoration: 'underline',
            textUnderlineOffset: '3px',
          }}
        >
          google.com
        </button>
        <span style={{ color: '#E7DED0' }}>•</span>
        <button
          type="button"
          onClick={() => onAnalyze('amazon.in')}
          style={{
            background: 'none',
            border: 'none',
            color: '#B83B00',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 700,
            padding: 0,
            textDecoration: 'underline',
            textUnderlineOffset: '3px',
          }}
        >
          amazon.in
        </button>
        <span style={{ color: '#E7DED0' }}>•</span>
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          style={{
            background: 'none',
            border: 'none',
            color: '#B83B00',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: 700,
            padding: 0,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            textDecoration: 'underline',
            textUnderlineOffset: '3px',
          }}
        >
          <QrCode size={13} />
          {language === 'hi' ? 'स्क्रीनशॉट / क्यूआर स्कैन' : 'Scan QR / Screenshot'}
        </button>
        <span style={{ color: '#E7DED0' }}>•</span>
        <button
          type="button"
          className="hero-subcta-link"
          onClick={onOpenSampleModal}
        >
          <span>
            {language === 'hi' ? 'नमूना संदेश आज़माएँ' : 'Sample messages'}
          </span>
          <ArrowRight size={14} />
        </button>
      </div>
    </div>
  );
}
