import React, { useState, useEffect } from 'react';
import BackgroundDecorations from './components/BackgroundDecorations';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import DeepSafetySection from './components/DeepSafetySection';
import HelplineSection from './components/HelplineSection';
import Footer from './components/Footer';
import AnalysisModal from './components/AnalysisModal';
import SampleMessagesModal from './components/SampleMessagesModal';
import ErrorBoundary from './components/ErrorBoundary';

export default function App() {
  const [language, setLanguage] = useState('en');
  const [analysisQuery, setAnalysisQuery] = useState(null);
  const [analysisImage, setAnalysisImage] = useState(null);
  const [isSampleModalOpen, setIsSampleModalOpen] = useState(false);

  const isAnalyzing = Boolean(analysisQuery !== null || analysisImage !== null);

  // IntersectionObserver for scroll reveals (Progressive Enhancement)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const prefersReducedMotion =
      window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Enable scroll reveal styling on body only if IntersectionObserver is supported and reduced motion is off
    if ('IntersectionObserver' in window && !prefersReducedMotion) {
      document.body.classList.add('js-scroll-reveal');

      const observer = new IntersectionObserver(
        (entries, obs) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              entry.target.classList.add('is-revealed');
              obs.unobserve(entry.target); // Reveal each element once by default
            }
          });
        },
        {
          root: null,
          rootMargin: '0px 0px -36px 0px',
          threshold: 0.1,
        }
      );

      const elements = document.querySelectorAll('.scroll-reveal');
      elements.forEach((el) => observer.observe(el));

      return () => {
        observer.disconnect();
        document.body.classList.remove('js-scroll-reveal');
      };
    }
  }, []);

  const handleStartAnalysis = (query) => {
    // If empty query is submitted from button click, give a default prompt or open sample selector
    if (!query) {
      setIsSampleModalOpen(true);
      return;
    }
    setAnalysisImage(null);
    setAnalysisQuery(query);
  };

  const handleStartImageAnalysis = (file) => {
    setAnalysisQuery(null);
    setAnalysisImage(file);
  };

  const handleCardClick = (cardType) => {
    if (cardType === 'message-analysis') {
      setIsSampleModalOpen(true);
    } else if (cardType === 'risk-indicators') {
      const el = document.getElementById('safety-section');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    } else if (cardType === 'multilingual-safety') {
      // Toggle language between en and hi!
      setLanguage((prev) => (prev === 'en' ? 'hi' : 'en'));
    }
  };

  const handleSelectSample = (sampleText) => {
    setIsSampleModalOpen(false);
    setAnalysisImage(null);
    setAnalysisQuery(sampleText);
  };

  return (
    <div className="page-wrapper">
      {/* Decorative Geometric Background */}
      <BackgroundDecorations />

      {/* Floating Navigation Bar */}
      <Navbar
        onOpenAnalyze={(q) => handleStartAnalysis(q || '')}
        language={language}
        setLanguage={setLanguage}
      />

      {/* Hero Section matching exact reference */}
      <Hero
        onAnalyze={handleStartAnalysis}
        onAnalyzeImage={handleStartImageAnalysis}
        onOpenSampleModal={() => setIsSampleModalOpen(true)}
        onCardClick={handleCardClick}
        language={language}
        isAnalyzing={isAnalyzing}
      />

      {/* Below-the-Hero Light Sections */}
      <DeepSafetySection
        onAnalyzeClick={() => setIsSampleModalOpen(true)}
        language={language}
      />

      {/* Helplines and Reporting Guidance */}
      <HelplineSection language={language} />

      {/* Minimal Footer */}
      <Footer language={language} />

      {/* Interactive Analysis Results Modal */}
      {isAnalyzing && (
        <ErrorBoundary
          isModal
          language={language}
          onClose={() => {
            setAnalysisQuery(null);
            setAnalysisImage(null);
          }}
          onReset={() => {
            // Reset modal by clearing and re-setting query on next tick
            const q = analysisQuery;
            const img = analysisImage;
            setAnalysisQuery(null);
            setAnalysisImage(null);
            setTimeout(() => {
              if (q) setAnalysisQuery(q);
              if (img) setAnalysisImage(img);
            }, 50);
          }}
        >
          <AnalysisModal
            query={analysisQuery}
            imageFile={analysisImage}
            onClose={() => {
              setAnalysisQuery(null);
              setAnalysisImage(null);
            }}
            onSelectSample={handleSelectSample}
            language={language}
          />
        </ErrorBoundary>
      )}

      {/* Sample Messages Quick Picker Modal */}
      {isSampleModalOpen && (
        <SampleMessagesModal
          onClose={() => setIsSampleModalOpen(false)}
          onSelectSample={handleSelectSample}
          language={language}
        />
      )}
    </div>
  );
}
