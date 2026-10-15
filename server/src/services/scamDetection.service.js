/**
 * Scam Detection Engine
 * Modular rule-based detection for common Indian cyber fraud patterns.
 */

export const RULES = [
  // 1. Urgent Electricity or Utility Disconnection Threat
  {
    ruleId: 'URGENT_UTILITY_DISCONNECTION',
    category: 'utility_disconnection',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasUtility = /\b(?:electricity|bijli|power|power-cut|discom|bses|dhbvn|uppcl|tneb|wbsedcl|bescom|mseb|adani\s*electricity|bill\s*payment)\b/i.test(lower);
      const hasDisconnection = /\b(?:disconnect|disconnection|cut|cut\s*off|will\s*be\s*disconnected|tonight|night|9:30|8:30|contact\s*officer|call\s*officer)\b/i.test(lower);
      return hasUtility && hasDisconnection;
    },
    evidence: {
      en: 'Threat of imminent utility or electricity disconnection demanding immediate payment or callback to an unverified number.',
      hi: 'बिजली या उपयोगिता सेवा को तत्काल काटने की धमकी और व्यक्तिगत नंबर पर कॉल करने का दबाव।'
    }
  },

  // 2. Banking KYC & Account Suspension Threat
  {
    ruleId: 'BANKING_KYC_THREAT',
    category: 'banking_kyc',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasBanking = /\b(?:bank|sbi|hdfc|icici|pnb|axis|bob|kotak|canara|account|a\/c|netbanking|yono|pan|aadhaar)\b/i.test(lower);
      const hasSuspension = /\b(?:block|blocked|deactivate|deactivated|suspend|suspended|closed|expire|expired|update\s*kyc|kyc\s*pending|link\s*pan)\b/i.test(lower);
      const hasAction = /\b(?:click|link|verify|update|avoid|login|submit)\b/i.test(lower);
      return (hasBanking && hasSuspension && hasAction) || (lower.includes('kyc') && hasSuspension);
    },
    evidence: {
      en: 'False notification claiming your bank account or PAN is blocked/expired, prompting credential submission.',
      hi: 'बैंक खाता या पैन कार्ड ब्लॉक/निष्क्रिय होने का दावा करते हुए विवरण अपडेट करने का दबाव।'
    }
  },

  // 3. Digital Arrest & Law Enforcement Impersonation
  {
    ruleId: 'DIGITAL_ARREST_COERCION',
    category: 'digital_arrest',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasLaw = /\b(?:cbi|police|customs|crime\s*branch|narcotics|ncb|court|judge|arrest|warrant|fedex|dhl|parcel)\b/i.test(lower);
      const hasCoercion = /\b(?:digital\s*arrest|video\s*call|skype|illegal|drugs|contraband|money\s*laundering|compromised|penal\s*code|fir)\b/i.test(lower);
      return hasLaw && hasCoercion;
    },
    evidence: {
      en: 'Digital Arrest coercion: Impersonating police, customs, or CBI alleging illegal parcels and demanding remote interrogation.',
      hi: 'डिजिटल अरेस्ट धमकी: फर्जी पुलिस, कस्टम्स या सीबीआई अधिकारी बनकर पार्सल में अवैध सामान मिलने का दावा।'
    }
  },

  // 4. Credential & OTP/PIN Harvesting Request
  {
    ruleId: 'CREDENTIAL_HARVESTING_OTP',
    category: 'credential_harvesting',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasSecret = /\b(?:otp|one\s*time\s*password|upi\s*pin|atm\s*pin|cvv|password|passcode)\b/i.test(lower);
      const hasRequest = /\b(?:share|tell|send|enter|verify|provide|disclose|give|bhejo|batao)\b/i.test(lower);
      return hasSecret && hasRequest;
    },
    evidence: {
      en: 'Direct request to disclose sensitive credentials (OTP, UPI PIN, ATM PIN, or passwords).',
      hi: 'ओटीपी, यूपीआई पिन या गोपनीय पासवर्ड साझा करने का सीधा अनुरोध।'
    }
  },

  // 5. Suspicious APK / Malicious App Download
  {
    ruleId: 'SUSPICIOUS_APK_DOWNLOAD',
    category: 'malicious_software',
    severity: 'critical',
    check: (text, entities) => {
      const lower = text.toLowerCase();
      const hasApkFile = /\.apk\b/i.test(lower) || entities.urls.some((u) => u.toLowerCase().endsWith('.apk'));
      const hasRemoteApp = /\b(?:anydesk|quicksupport|teamviewer|rustdesk|screen\s*share|install\s*app|download\s*app)\b/i.test(lower);
      return hasApkFile || hasRemoteApp;
    },
    evidence: {
      en: 'Requests downloading an external .APK file or installing remote screen-sharing software (e.g. AnyDesk/QuickSupport).',
      hi: 'अज्ञात .APK फाइल या स्क्रीन-शेयरिंग रिमोट एक्सेस ऐप (जैसे AnyDesk) डाउनलोड करने का संकेत।'
    }
  },

  // 6. Fake Job Offers & Telegram Task Scams
  {
    ruleId: 'TASK_JOB_ADVANCE_FEE',
    category: 'job_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasJob = /\b(?:part[\s\-]?time|work\s*from\s*home|wfh|job\s*offer|daily\s*income|earn\s*daily|daily\s*earning)\b/i.test(lower);
      const hasTaskOrPrepaid = /\b(?:youtube\s*like|google\s*review|hotel\s*review|telegram|prepaid|task|commission|earn\s*₹|₹\s*\d{3,5})\b/i.test(lower);
      return hasJob && hasTaskOrPrepaid;
    },
    evidence: {
      en: 'Unrealistic income promise for minimal tasks (liking videos, writing reviews) directing to Telegram or WhatsApp.',
      hi: 'यूट्यूब लाइक या रिव्यू जैसे साधारण कार्यों के लिए अवास्तविक दैनिक कमाई का वादा।'
    }
  },

  // 7. Lottery, Prize, and Reward Advance-Fee Scam
  {
    ruleId: 'LOTTERY_PRIZE_ADVANCE_FEE',
    category: 'lottery_reward',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasReward = /\b(?:lottery|lucky\s*draw|kbc|won|winner|cash\s*prize|gift\s*card|reward|congratulations)\b/i.test(lower);
      const hasFeeOrScale = /\b(?:lakh|crore|deposit|processing\s*fee|registration\s*fee|tax|claim\s*prize|claim\s*amount)\b/i.test(lower);
      return hasReward && hasFeeOrScale;
    },
    evidence: {
      en: 'Claims you won a lottery or lucky draw requiring an advance registration fee or tax deposit.',
      hi: 'लॉटरी या केबीसी लकी ड्रा जीतने का झूठा दावा और इनाम पाने के लिए अग्रिम शुल्क की मांग।'
    }
  },

  // 8. Suspicious Instant Loan Offer & Processing Advance
  {
    ruleId: 'SUSPICIOUS_LOAN_OFFER',
    category: 'loan_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasLoan = /\b(?:instant\s*loan|pre[\s\-]?approved\s*loan|personal\s*loan|fast\s*loan)\b/i.test(lower);
      const hasNoCheck = /\b(?:without\s*cibil|no\s*documents|0%\s*interest|instant\s*disbursal|processing\s*charges?|advance\s*fee)\b/i.test(lower);
      return hasLoan && hasNoCheck;
    },
    evidence: {
      en: 'Unregulated instant loan offer claiming zero credit checks while demanding upfront processing fees.',
      hi: 'बिना सिबिल स्कोर या बिना दस्तावेज के तत्काल लोन का वादा और अग्रिम प्रोसेसिंग फीस की मांग।'
    }
  },

  // 9. Institutional Impersonation
  {
    ruleId: 'GOVT_BANK_IMPERSONATION',
    category: 'impersonation',
    severity: 'medium',
    check: (text, entities) => {
      const lower = text.toLowerCase();
      const claimsOrg = /\b(?:reserve\s*bank\s*of\s*india|rbi|income\s*tax|trai|dot|customs|sbi|mha|police)\b/i.test(lower);
      const hasUnverifiedContact = entities.phoneNumbers.length > 0 || entities.upiIds.length > 0 || entities.urls.length > 0;
      return claimsOrg && hasUnverifiedContact;
    },
    evidence: {
      en: 'References government authorities or financial institutions alongside unofficial contact or payment channels.',
      hi: 'सरकारी विभाग या बैंक का नाम लेते हुए अनधिकृत संपर्क या भुगतान चैनलों का उपयोग।'
    }
  },

  // 10. Artificial Urgency & Coercive Pressure
  {
    ruleId: 'EXTREME_URGENCY_PRESSURE',
    category: 'urgency_coercion',
    severity: 'medium',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const urgencyMatch = /\b(?:immediately|urgent|within\s*\d+\s*(?:hours?|minutes?|mins?)|today\s*itself|last\s*chance|before\s*(?:midnight|tonight)|action\s*required)\b/i.test(lower);
      const pressureMatch = /\b(?:legal\s*action|penalty|court|fine|lawsuit|permanent\s*loss|confiscate)\b/i.test(lower);
      return urgencyMatch && pressureMatch;
    },
    evidence: {
      en: 'Psychological urgency tactic creating fear of immediate financial penalty or legal action.',
      hi: 'त्वरित जुर्माने या कानूनी कार्रवाई का भय दिखाकर जल्दबाजी में कदम उठाने का मानसिक दबाव।'
    }
  },

  // 11. Fake Courier Delivery & Customs Fee Scam
  {
    ruleId: 'COURIER_CUSTOMS_FEE_SCAM',
    category: 'courier_customs_fraud',
    severity: 'high',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasCourier = /\b(?:fedex|dhl|indiapost|india\s*post|speedpost|blue\s*dart|delhivery|parcel|package|shipment|delivery|order)\b/i.test(lower);
      const hasFeeOrAddress = /\b(?:customs|duty|tax|redelivery|reschedule|delivery\s*fee|update\s*address|wrong\s*address|pending\s*charges?|₹\s*\d{1,4}|rs\.?\s*\d{1,4})\b/i.test(lower);
      const hasAction = /\b(?:click|link|pay|visit|update|track)\b/i.test(lower);
      return (hasCourier && hasFeeOrAddress) || (hasCourier && hasAction && /\b(?:failed|incomplete|undelivered|held)\b/i.test(lower));
    },
    evidence: {
      en: 'Fake parcel delivery or customs charges notification demanding immediate payment or address updates to release shipment.',
      hi: 'पार्सल या डाक डिलीवरी रोकने का दावा करते हुए सीमा शुल्क या पुनः डिलीवरी शुल्क मांगने का झांसा।'
    }
  },

  // 12. Fraudulent UPI Collect Request ("Enter PIN to receive money")
  {
    ruleId: 'UPI_COLLECT_PIN_SCAM',
    category: 'payment_collect_fraud',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasUpi = /\b(?:upi|gpay|phonepe|paytm|bhim|qr\s*code|collect\s*request|request\s*money)\b/i.test(lower);
      const hasPinTrap = /\b(?:enter\s*pin|enter\s*upi\s*pin|pin\s*daale|paise\s*(?:aayenge|milenge)|receive\s*money|credit\s*amount|refund|cashback)\b/i.test(lower);
      return hasUpi && hasPinTrap;
    },
    evidence: {
      en: 'Deceptive claim that entering a UPI PIN will receive money or credit a refund (UPI PIN is ONLY required for debiting money).',
      hi: 'पैसे प्राप्त करने के लिए यूपीआई पिन डालने का झूठा दावा (यूपीआई पिन केवल पैसे कटने पर ही डाला जाता है)।'
    }
  },

  // 13. High-Yield Investment, Crypto & Guaranteed Returns Scam
  {
    ruleId: 'HIGH_YIELD_INVESTMENT_SCAM',
    category: 'investment_fraud',
    severity: 'critical',
    check: (text, _entities) => {
      const lower = text.toLowerCase();
      const hasInvestment = /\b(?:invest|investment|crypto|bitcoin|trading|forex|stock|ipo|fund|deposit)\b/i.test(lower);
      const hasUnrealisticReturn = /\b(?:guaranteed\s*returns?|daily\s*returns?|double\s*money|100%\s*profit|vip\s*signals?|assured\s*income|zero\s*risk|10x|20x|passive\s*income)\b/i.test(lower);
      return hasInvestment && hasUnrealisticReturn;
    },
    evidence: {
      en: 'Fraudulent high-yield investment scheme promising guaranteed, zero-risk returns or trading profits.',
      hi: 'बिना जोखिम के गारंटीकृत भारी मुनाफे या दोगुने रिटर्न का वादा करने वाला फर्जी निवेश प्रलोभन।'
    }
  }
];

/**
 * Executes all rules against the input text and extracted entities.
 * @param {string} text - Raw input text
 * @param {{ urls: string[], phoneNumbers: string[], upiIds: string[] }} entities
 * @param {'en' | 'hi'} language
 * @returns {Array<{ ruleId: string, category: string, severity: string, evidence: string }>}
 */
export function evaluateScamRules(text, entities, language = 'en') {
  if (!text || typeof text !== 'string') return [];

  const matchedRules = [];

  for (const rule of RULES) {
    try {
      if (rule.check(text, entities)) {
        matchedRules.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          evidence: rule.evidence[language] || rule.evidence.en,
        });
      }
    } catch (err) {
      console.error(`Rule evaluation error [${rule.ruleId}]:`, err.message);
    }
  }

  return matchedRules;
}

/**
 * Determines primary scam type from triggered rules.
 */
export function determineScamType(matchedRules) {
  if (!matchedRules || matchedRules.length === 0) {
    return 'none_detected';
  }

  // Prioritize critical rules first, then high
  const priorityOrder = ['critical', 'high', 'medium', 'low'];
  for (const severity of priorityOrder) {
    const found = matchedRules.find((r) => r.severity === severity);
    if (found) return found.category;
  }

  return matchedRules[0].category;
}

/**
 * Generates actionable safety advice based on matched threat rules and entities.
 * @param {Array<{ ruleId: string, category: string }>} matchedRules
 * @param {{ urls: string[], phoneNumbers: string[], upiIds: string[] }} entities
 * @param {'en' | 'hi'} language
 * @returns {string[]}
 */
export function generateSafetyAdvice(matchedRules, entities, language = 'en') {
  const advice = new Set();
  const ruleCategories = new Set(matchedRules.map((r) => r.category));
  const isHi = language === 'hi';

  // 1. OTP / Credential Harvesting
  if (ruleCategories.has('credential_harvesting')) {
    advice.add(
      isHi
        ? 'बैंक या कोई भी आधिकारिक संस्था कभी भी फोन या एसएमएस पर आपका ओटीपी, यूपीआई पिन या पासवर्ड नहीं मांगती। किसी से साझा न करें।'
        : 'Never share OTPs, PINs, CVVs, or passwords with anyone. Banks and official agencies will never ask for them.'
    );
  }

  // 2. Suspicious URLs / Links
  if (entities.urls.length > 0 || ruleCategories.has('malicious_software') || ruleCategories.has('banking_kyc')) {
    advice.add(
      isHi
        ? 'संदिग्ध संदेश में दिए गए लिंक पर क्लिक न करें। हमेशा आधिकारिक वेबसाइट को अपने ब्राउज़र में अलग से खोलकर जांचें।'
        : 'Do not click links supplied in unsolicited messages. Always verify domains independently through official portals.'
    );
  }

  // 3. Utility / Disconnection
  if (ruleCategories.has('utility_disconnection')) {
    advice.add(
      isHi
        ? 'बिजली या उपयोगिता बिल की स्थिति केवल आधिकारिक डिस्कॉम ऐप या आधिकारिक वेबसाइट पर ही जांचें। व्यक्तिगत नंबर पर कॉल न करें।'
        : 'Verify utility payment status exclusively through the official DISCOM portal or electricity bill app, not personal phone numbers.'
    );
  }

  // 4. Digital Arrest / Police Impersonation
  if (ruleCategories.has('digital_arrest')) {
    advice.add(
      isHi
        ? 'भारतीय कानून में "डिजिटल अरेस्ट" का कोई प्रावधान नहीं है। पुलिस या सीबीआई कभी भी व्हाट्सएप/स्काइप वीडियो कॉल पर गिरफ्तारी नहीं करती।'
        : 'Indian law enforcement does not conduct arrests or judicial verification via Skype or WhatsApp video calls.'
    );
  }

  // 5. Job & Task Scams
  if (ruleCategories.has('job_fraud')) {
    advice.add(
      isHi
        ? 'साधारण कार्यों के लिए पैसे कमाने का झांसा देने वाले टेलीग्राम या व्हाट्सएप ग्रुपों से दूर रहें। कभी भी "प्रीपेड टास्क" के लिए पैसे न भेजें।'
        : 'Avoid Telegram channels promising daily income for social media tasks. Legitimate jobs never require advance deposits.'
    );
  }

  // 6. Lottery & Advance-Fee
  if (ruleCategories.has('lottery_reward')) {
    advice.add(
      isHi
        ? 'जिस लॉटरी में आपने भाग नहीं लिया, वह आप कभी नहीं जीत सकते। इनाम पाने के लिए कभी कोई शुल्क या टैक्स न दें।'
        : 'You cannot win a contest or lottery you never entered. Real organizations do not demand processing fees to release prizes.'
    );
  }

  // 7. Courier & Customs Scams
  if (ruleCategories.has('courier_customs_fraud')) {
    advice.add(
      isHi
        ? 'कूरियर या डाक विभाग कभी भी एसएमएस पर पार्सल छुड़ाने के लिए ऑनलाइन पैसे नहीं मांगता। आधिकारिक ट्रैकिंग नंबर से सीधे वेबसाइट पर स्थिति जांचें।'
        : 'India Post, FedEx, or customs officials never demand payment via unofficial SMS links to release parcels. Verify tracking on official websites only.'
    );
  }

  // 8. UPI Collect Request & PIN Trap
  if (ruleCategories.has('payment_collect_fraud')) {
    advice.add(
      isHi
        ? 'ध्यान रखें: पैसे प्राप्त करने के लिए कभी भी UPI PIN डालने की आवश्यकता नहीं होती। UPI PIN केवल पैसे भेजने (कटने) पर ही डाला जाता है।'
        : 'CRITICAL: You never need to enter your UPI PIN to receive money or refunds. Entering a PIN will instantly debit your account.'
    );
  }

  // 9. Investment & Guaranteed Returns Fraud
  if (ruleCategories.has('investment_fraud')) {
    advice.add(
      isHi
        ? 'असामान्य रूप से उच्च या गारंटीकृत रिटर्न का वादा करने वाले किसी भी टेलीग्राम या अज्ञात ट्रेडिंग चैनल में पैसे निवेश न करें। यह पोंजी/धोखाधड़ी है।'
        : 'Never invest through WhatsApp/Telegram trading channels promising guaranteed or double returns. Unregulated schemes are high-risk financial fraud.'
    );
  }

  // 10. General / Baseline Advice if high risk detected
  if (matchedRules.length > 0) {
    advice.add(
      isHi
        ? 'यदि आपको वित्तीय नुकसान हुआ है या संदेह है, तो तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत दर्ज करें।'
        : 'If you suspect financial cyber fraud, report immediately to the National Cyber Helpline 1930 or visit https://www.cybercrime.gov.in/.'
    );
  } else {
    // Clean/Benign message
    advice.add(
      isHi
        ? 'इस संदेश में कोई स्पष्ट घोटाला संकेत नहीं मिले। फिर भी अज्ञात संपर्कों से आने वाले किसी भी वित्तीय अनुरोध पर सतर्क रहें।'
        : 'No obvious fraudulent indicators were detected. Continue exercising caution when dealing with unverified senders.'
    );
  }

  return Array.from(advice);
}

/**
 * Extracts verbatim evidence excerpts from the submitted text for matched threat rules.
 * Extracts context around the triggering keywords (up to 80 chars) to provide transparent proof.
 *
 * @param {string} text - Raw input text
 * @param {Array<{ ruleId: string, category: string }>} matchedRules
 * @returns {Array<{ ruleId: string, category: string, excerpt: string }>}
 */
export function extractEvidenceExcerpts(text, matchedRules = []) {
  if (!text || typeof text !== 'string' || matchedRules.length === 0) {
    return [];
  }

  const excerpts = [];
  const seenExcerpts = new Set();

  const patternKeywords = {
    URGENT_UTILITY_DISCONNECTION: /(?:electricity|bijli|power-cut|disconnection|cut off|tonight|contact officer)[^.\n]{0,50}/i,
    BANKING_KYC_THREAT: /(?:bank|account|a\/c|pan|aadhaar|blocked|deactivated|suspended|update kyc|kyc pending)[^.\n]{0,50}/i,
    DIGITAL_ARREST_COERCION: /(?:cbi|police|customs|digital arrest|video call|illegal parcel|narcotics)[^.\n]{0,50}/i,
    CREDENTIAL_HARVESTING_OTP: /(?:otp|password|upi pin|atm pin|cvv|share|enter|send|provide)[^.\n]{0,50}/i,
    SUSPICIOUS_APK_DOWNLOAD: /(?:\.apk|anydesk|quicksupport|teamviewer|screen share|install app)[^.\n]{0,50}/i,
    TASK_JOB_ADVANCE_FEE: /(?:part[\s\-]?time|work from home|youtube like|telegram|prepaid task|daily income)[^.\n]{0,50}/i,
    LOTTERY_PRIZE_ADVANCE_FEE: /(?:lottery|lucky draw|kbc|winner|cash prize|processing fee|tax deposit)[^.\n]{0,50}/i,
    SUSPICIOUS_LOAN_OFFER: /(?:instant loan|without cibil|no documents|0% interest|processing fee)[^.\n]{0,50}/i,
    COURIER_CUSTOMS_FEE_SCAM: /(?:fedex|dhl|indiapost|speedpost|parcel|delivery fee|customs duty|reschedule)[^.\n]{0,50}/i,
    UPI_COLLECT_PIN_SCAM: /(?:upi|collect request|enter pin|receive money|refund|cashback)[^.\n]{0,50}/i,
    HIGH_YIELD_INVESTMENT_SCAM: /(?:guaranteed returns?|double money|crypto trading|100% profit|vip signal)[^.\n]{0,50}/i,
    EXTREME_URGENCY_PRESSURE: /(?:immediately|urgent|within \d+ hours?|today itself|last chance|legal action)[^.\n]{0,50}/i,
    GOVT_BANK_IMPERSONATION: /(?:rbi|income tax|trai|customs|police)[^.\n]{0,50}/i,
  };

  for (const rule of matchedRules) {
    const regex = patternKeywords[rule.ruleId];
    if (regex) {
      const match = regex.exec(text);
      if (match) {
        const snippet = match[0].trim();
        if (snippet && !seenExcerpts.has(snippet)) {
          seenExcerpts.add(snippet);
          excerpts.push({
            ruleId: rule.ruleId,
            category: rule.category,
            excerpt: `"...${snippet}..."`,
          });
        }
      }
    }
  }

  return excerpts;
}
