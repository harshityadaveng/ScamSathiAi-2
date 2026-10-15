import React from 'react';

export default function BrandLogo({ size = 36, showText = true }) {
  return (
    <div className="nav-logo-group" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
      <div className="nav-logo-icon" style={{ width: size, height: size }}>
        <svg
          viewBox="0 0 36 36"
          width={size}
          height={size}
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Shield Base Outline */}
          <path
            d="M18 3.5L5.5 8.2V16.8C5.5 24.3 10.8 31.2 18 33C25.2 31.2 30.5 24.3 30.5 16.8V8.2L18 3.5Z"
            fill="#FEFBF4"
            stroke="#B83B00"
            strokeWidth="3.2"
            strokeLinejoin="round"
          />
          {/* Internal Checkmark */}
          <path
            d="M12.5 17.5L16.2 21.2L23.8 13.5"
            stroke="#B83B00"
            strokeWidth="3.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      {showText && (
        <span className="nav-logo-text">
          ScamSathi<span className="nav-logo-accent">AI</span>
        </span>
      )}
    </div>
  );
}
