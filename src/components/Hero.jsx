import React from 'react';
import HeroSearch from './HeroSearch';
import HeroCards from './HeroCards';
import TypewriterHeadline from './TypewriterHeadline';

export default function Hero({ onAnalyze, onAnalyzeImage, onOpenSampleModal, onCardClick, language, isAnalyzing }) {
  return (
    <main className="hero-section">
      {/* Centered Main Headline with Smooth Typewriter Entrance */}
      <TypewriterHeadline language={language} />

      {/* Main Pill Search Bar & Sample Message CTA */}
      <HeroSearch
        onAnalyze={onAnalyze}
        onAnalyzeImage={onAnalyzeImage}
        onOpenSampleModal={onOpenSampleModal}
        language={language}
        isAnalyzing={isAnalyzing}
      />

      {/* Three Feature Cards */}
      <HeroCards onCardClick={onCardClick} language={language} />
    </main>
  );
}
