import React from 'react';

export default function BackgroundDecorations() {
  return (
    <div className="bg-decorations" aria-hidden="true">
      {/* Top Left Soft Glow */}
      <div className="decor-top-left-glow" />

      {/* Top Left Diagonal Pill 1 (Subtle cream/gold) */}
      <div className="decor-pill-top-left-1" />

      {/* Top Left Diagonal Pill 2 (Vibrant gold accent) */}
      <div className="decor-pill-top-left-2" />

      {/* Top Right Subtle Disc */}
      <div className="decor-top-right-disc" />

      {/* Right Edge Solid Gold Dot/Circle */}
      <div className="decor-right-small-circle" />

      {/* Bottom Left Floating Pill */}
      <div className="decor-pill-bottom-left" />

      {/* Bottom Right Organic Burnt-Orange Mound & Ring */}
      <div className="decor-bottom-right-ring" />
      <div className="decor-bottom-right-mound" />
    </div>
  );
}
