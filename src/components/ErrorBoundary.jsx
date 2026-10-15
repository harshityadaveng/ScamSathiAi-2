import React from 'react';
import { AlertTriangle, RefreshCw, X } from 'lucide-react';

/**
 * Robust Error Boundary to prevent React runtime render crashes
 * from taking down the entire application into a blank cream screen.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ScamSathi ErrorBoundary] Uncaught render exception:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      // If a custom fallback is provided, use it
      if (this.props.fallback) {
        return this.props.fallback({
          error: this.state.error,
          reset: this.handleReset,
        });
      }

      const isModal = this.props.isModal;
      const isHindi = this.props.language === 'hi';

      const content = (
        <div
          role="alert"
          style={{
            background: '#FFFFFF',
            border: '1px solid #E7DED0',
            borderRadius: '16px',
            padding: '28px 24px',
            maxWidth: '560px',
            margin: isModal ? '20px auto' : '40px auto',
            textAlign: 'center',
            boxShadow: '0 12px 32px rgba(0, 0, 0, 0.08)',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              background: '#FDE1DE',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 14px auto',
              color: '#DC2626',
            }}
          >
            <AlertTriangle size={24} />
          </div>

          <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#171717', marginBottom: '8px' }}>
            {isHindi ? 'विश्लेषण पूर्ण नहीं हो सका' : 'Analysis Could Not Be Completed'}
          </h3>

          <p style={{ fontSize: '13.5px', color: '#655E54', lineHeight: 1.5, margin: '0 0 20px 0' }}>
            {isHindi
              ? 'विश्लेषण के दौरान एक तकनीकी समस्या आई। पृष्ठ को रिफ्रेश किए बिना पुनः प्रयास करें।'
              : 'Analysis could not be completed. Please try again or check your input.'}
          </p>

          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', alignItems: 'center' }}>
            <button
              type="button"
              className="nav-cta-btn"
              onClick={this.handleReset}
              style={{ fontSize: '13.5px', padding: '9px 20px' }}
            >
              <RefreshCw size={14} />
              <span>{isHindi ? 'पुनः प्रयास करें' : 'Try Again'}</span>
            </button>

            {this.props.onClose && (
              <button
                type="button"
                onClick={this.props.onClose}
                style={{
                  background: '#FFFFFF',
                  border: '1px solid #E7DED0',
                  color: '#171717',
                  padding: '9px 18px',
                  borderRadius: '9999px',
                  cursor: 'pointer',
                  fontSize: '13.5px',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <X size={14} />
                <span>{isHindi ? 'बंद करें' : 'Close'}</span>
              </button>
            )}
          </div>
        </div>
      );

      if (isModal) {
        return (
          <div className="modal-overlay" onClick={this.props.onClose} role="dialog" aria-modal="true">
            <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
              {content}
            </div>
          </div>
        );
      }

      return content;
    }

    return this.props.children;
  }
}
