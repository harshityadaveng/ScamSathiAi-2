import { isSafeHostname } from './ssrfProtection.service.js';

let mockRdapHandler = null;

/**
 * Injects a mock RDAP handler for testing.
 * @param {Function|null} handler
 */
export function setMockRdapHandler(handler) {
  mockRdapHandler = handler;
}

/**
 * Fetches domain registration intelligence using public RDAP protocol.
 *
 * @param {string} registeredDomain - Root registered domain (e.g. "example.com")
 * @returns {Promise<object>} Structured RDAP check report
 */
export async function checkRdapIntel(registeredDomain) {
  if (mockRdapHandler) {
    return mockRdapHandler(registeredDomain);
  }

  const timestamp = new Date().toISOString();

  if (!registeredDomain || !isSafeHostname(registeredDomain)) {
    return {
      name: 'domain_registration',
      status: 'error',
      source: 'rdap',
      timestamp,
      explanation: 'Invalid domain name or private/internal host provided.',
      data: null,
    };
  }

  // Raw IP addresses do not have domain RDAP registration records
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(registeredDomain)) {
    return {
      name: 'domain_registration',
      status: 'no_data',
      source: 'rdap',
      timestamp,
      explanation: 'Target is a raw IP address; domain registration records do not apply.',
      data: null,
    };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    // Use standard public RDAP service
    const endpoint = `https://rdap.org/domain/${encodeURIComponent(registeredDomain)}`;

    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'ScamSathiAI-SecurityBot/1.0',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      return {
        name: 'domain_registration',
        status: 'no_data',
        source: 'rdap',
        timestamp,
        explanation: 'RDAP database returned 404 (domain uncatalogued or TLD registry not participating in RDAP).',
        data: null,
      };
    }

    if (response.status === 429) {
      return {
        name: 'domain_registration',
        status: 'unavailable',
        source: 'rdap',
        timestamp,
        explanation: 'RDAP query rate-limited by upstream registry service.',
        data: null,
      };
    }

    if (!response.ok) {
      return {
        name: 'domain_registration',
        status: 'unavailable',
        source: 'rdap',
        timestamp,
        explanation: `RDAP registry returned HTTP ${response.status}.`,
        data: null,
      };
    }

    const rdapData = await response.json();

    // Extract Registration Date and Expiration Date from RFC 9083 events
    let registrationDate = null;
    let expirationDate = null;

    if (Array.isArray(rdapData.events)) {
      for (const ev of rdapData.events) {
        if (ev.eventAction === 'registration' || ev.eventAction === 'created') {
          registrationDate = ev.eventDate;
        } else if (ev.eventAction === 'expiration') {
          expirationDate = ev.eventDate;
        }
      }
    }

    // Extract Registrar name from entities
    let registrarName = null;
    if (Array.isArray(rdapData.entities)) {
      for (const entity of rdapData.entities) {
        if (Array.isArray(entity.roles) && entity.roles.includes('registrar')) {
          if (entity.vcardArray && Array.isArray(entity.vcardArray[1])) {
            const fnItem = entity.vcardArray[1].find((item) => item[0] === 'fn');
            if (fnItem && fnItem[3]) {
              registrarName = fnItem[3];
              break;
            }
          }
          if (!registrarName && entity.handle) {
            registrarName = entity.handle;
          }
        }
      }
    }

    // Calculate domain age
    let ageDays = null;
    let ageYears = null;
    let isYoungDomain = false;
    let isVeryNewDomain = false;

    if (registrationDate) {
      const regTime = new Date(registrationDate).getTime();
      if (!isNaN(regTime)) {
        ageDays = Math.max(0, Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24)));
        ageYears = parseFloat((ageDays / 365.25).toFixed(1));
        isVeryNewDomain = ageDays < 30;
        isYoungDomain = ageDays < 90;
      }
    }

    return {
      name: 'domain_registration',
      status: 'success',
      source: 'rdap',
      timestamp,
      explanation: registrationDate
        ? `Registered on ${registrationDate.split('T')[0]} (${ageDays} days / ${ageYears} years old).`
        : 'RDAP record found, but registration timestamp was not provided by registry.',
      data: {
        registrationDate,
        expirationDate,
        ageDays,
        ageYears,
        registrar: registrarName || 'Not disclosed by registry',
        isYoungDomain,
        isVeryNewDomain,
      },
    };
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    return {
      name: 'domain_registration',
      status: isTimeout ? 'unavailable' : 'error',
      source: 'rdap',
      timestamp,
      explanation: isTimeout ? 'RDAP query timed out.' : `RDAP check failed: ${err.message}`,
      data: null,
    };
  }
}
