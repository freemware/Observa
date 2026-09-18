// Observa cookie reader — background/cookies.js — M3, extended v0.12.0.
//
// Reads cookie METADATA for the active tab's URL using chrome.cookies.getAll().
//
// v0.12.0: also runs classify/exposure.js's pattern detectors against each
// cookie's VALUE (the one field this file previously discarded entirely,
// per this file's own now-superseded "never reads cookie values" note) to
// check whether it looks like it carries an email, phone number, ZIP, or
// similar pattern — requested directly, so users can see not just a
// cookie's declared category but what it actually appears to contain.
// The full raw value is still never returned, stored, or logged here —
// only whatever detectValueExposure() matches (the narrow substring, e.g.
// just the email address, not the whole cookie), same redact-by-default/
// reveal-on-demand treatment the UI already gives request-based exposures.
// See classify/exposure.js's header comment for the full reasoning.
//
// Provenance: OBSERVED — every field comes directly from chrome.cookies API.
// Exception: risk flags (isTracking, longLived) are INFERRED from metadata.

import { detectValueExposure } from '../classify/exposure.js';

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * Fetch cookie metadata for a URL. Returns normalized cookie descriptors.
 * @param {string} url - full page URL
 * @returns {Promise<CookieMeta[]>}
 *
 * @typedef {Object} CookieMeta
 * @property {string}  name
 * @property {string}  domain
 * @property {string}  path
 * @property {boolean} secure
 * @property {boolean} httpOnly   - true = inaccessible to page JS; only chrome.cookies can read it
 * @property {string}  sameSite   - 'strict' | 'lax' | 'no_restriction' | 'unspecified'
 * @property {boolean} session    - true = expires when browser closes
 * @property {number|null} expiresAt   - Unix ms, null for session cookies
 * @property {number|null} daysUntilExpiry - null for session cookies
 * @property {boolean} longLived  - INFERRED: persistent and expires > 90 days from now
 * @property {Array<object>} exposures - (v0.12.0) pattern matches found in the cookie's
 *   value, same shape as a request's exposures; the value itself is never included
 * @property {string}  provenance
 */
export async function getCookiesForUrl(url) {
  if (!url) return [];

  let rawCookies;
  try {
    rawCookies = await chrome.cookies.getAll({ url });
  } catch (err) {
    console.error('[Observa] cookies.getAll failed:', err.message);
    return [];
  }

  const now = Date.now();

  return rawCookies.map(c => {
    const expiresAt = c.session ? null : Math.round(c.expirationDate * 1000);
    const daysUntilExpiry = expiresAt === null
      ? null
      : Math.round((expiresAt - now) / (1000 * 60 * 60 * 24));
    const longLived = expiresAt !== null && (expiresAt - now) > NINETY_DAYS_MS;
    // c.value is read here only to run the local pattern detectors; it is
    // not captured into the returned object below in any form — only
    // whatever detectValueExposure() extracts (redacted + the narrow
    // matched substring, per cookie) survives past this point.
    const exposures = detectValueExposure(c.name, c.value);

    return {
      name:            c.name,
      domain:          c.domain,
      path:            c.path,
      secure:          c.secure,
      httpOnly:        c.httpOnly,
      sameSite:        c.sameSite,        // 'strict'|'lax'|'no_restriction'|'unspecified'
      session:         c.session,
      expiresAt,
      daysUntilExpiry,
      longLived,                          // INFERRED
      exposures,                          // (v0.12.0) OBSERVED/INFERRED per finding — see classify/exposure.js
      provenance:      'Observed',
    };
    // The cookie's full raw value is intentionally never included above.
  });
}

/**
 * Summarize a list of CookieMeta into headline counts.
 * @param {CookieMeta[]} cookies
 */
export function summarizeCookies(cookies) {
  return {
    total:      cookies.length,
    session:    cookies.filter(c => c.session).length,
    persistent: cookies.filter(c => !c.session).length,
    longLived:  cookies.filter(c => c.longLived).length,
    httpOnly:   cookies.filter(c => c.httpOnly).length,
    secure:     cookies.filter(c => c.secure).length,
    sameSiteStrict: cookies.filter(c => c.sameSite === 'strict').length,
    sameSiteLax:    cookies.filter(c => c.sameSite === 'lax').length,
    sameSiteNone:   cookies.filter(c => c.sameSite === 'no_restriction').length,
  };
}
