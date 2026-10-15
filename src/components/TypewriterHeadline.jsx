import React, { useState, useEffect } from 'react';

// Module-level guard: ensures animation only plays once per page load
let hasAnimatedHeadline = false;

export default function TypewriterHeadline({ language }) {
  const line1Full = language === 'hi' ? 'संदेशों में छिपा होता है धोखा' : 'Fraud Hides in Messages';
  const line2Full = language === 'hi' ? 'सच्चाई यहीं से शुरू होती है।' : 'Truth Starts Here';

  // Check user preference for reduced motion
  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const shouldSkipAnimation = prefersReducedMotion || hasAnimatedHeadline;

  const [line1, setLine1] = useState(shouldSkipAnimation ? line1Full : '');
  const [line2, setLine2] = useState(shouldSkipAnimation ? line2Full : '');
  const [showSlash, setShowSlash] = useState(shouldSkipAnimation);
  const [cursorLine, setCursorLine] = useState(shouldSkipAnimation ? 0 : 1);
  const [isDone, setIsDone] = useState(shouldSkipAnimation);

  // If language changes after completion or if reduced motion is active, update text immediately
  useEffect(() => {
    if (isDone || shouldSkipAnimation) {
      setLine1(line1Full);
      setLine2(line2Full);
      setShowSlash(true);
      setCursorLine(0);
      setIsDone(true);
    }
  }, [language, line1Full, line2Full, isDone, shouldSkipAnimation]);

  useEffect(() => {
    if (shouldSkipAnimation) {
      hasAnimatedHeadline = true;
      return;
    }

    let isCancelled = false;
    let timerId = null;

    // Smooth typing speed: ~50-55ms per character (within 45–65ms spec)
    const TYPING_SPEED = 52;
    const LINE_PAUSE = 340; // Short pause between line 1 and line 2
    const END_PAUSE = 480;  // Pause at the end before removing cursor

    let idx1 = 0;
    let idx2 = 0;

    const typeLine1 = () => {
      if (isCancelled) return;
      if (idx1 < line1Full.length) {
        idx1++;
        setLine1(line1Full.slice(0, idx1));
        timerId = setTimeout(typeLine1, TYPING_SPEED);
      } else {
        // Line 1 finished. Pause briefly, then show slash and move cursor to Line 2
        timerId = setTimeout(() => {
          if (isCancelled) return;
          setShowSlash(true);
          setCursorLine(2);
          timerId = setTimeout(typeLine2, TYPING_SPEED);
        }, LINE_PAUSE);
      }
    };

    const typeLine2 = () => {
      if (isCancelled) return;
      if (idx2 < line2Full.length) {
        idx2++;
        setLine2(line2Full.slice(0, idx2));
        timerId = setTimeout(typeLine2, TYPING_SPEED);
      } else {
        // Line 2 finished. Wait briefly, then remove cursor and finalize
        timerId = setTimeout(() => {
          if (isCancelled) return;
          setCursorLine(0);
          setIsDone(true);
          hasAnimatedHeadline = true;
        }, END_PAUSE);
      }
    };

    // Begin typing on initial load
    timerId = setTimeout(typeLine1, 120);

    return () => {
      isCancelled = true;
      if (timerId) clearTimeout(timerId);
    };
  }, [shouldSkipAnimation, line1Full, line2Full]);

  const accessibleTitle = `${line1Full} / ${line2Full}`;

  return (
    <h1 className="hero-headline" aria-label={accessibleTitle}>
      <span className="hero-headline-line" aria-hidden="true">
        {line1}
        {cursorLine === 1 && <span className="typewriter-cursor" />}
      </span>
      <span className="hero-headline-line" aria-hidden="true">
        {showSlash && <span className="hero-slash">/</span>}
        {showSlash && ' '}
        {line2}
        {cursorLine === 2 && <span className="typewriter-cursor" />}
      </span>
    </h1>
  );
}
