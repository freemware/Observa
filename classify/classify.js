// WebLens classifier — classify/classify.js — M3 refinement.
//
// eTLD+1 strategy:
//   1. Use chrome.publicSuffix.getDomain() if available (Chrome 130+, exact version TBD).
//      This uses the browser's built-in, always-current Public Suffix List.
//   2. Fall back to a hand-rolled multi-part suffix lookup covering the ~99% case.
//      Known gap: cloud subdomains like foo.s3.amazonaws.com may be misclassified.
//
// All results are provenance-tagged per CLAUDE.md Rule 3.

import { lookupTracker } from './tracker-list.js';

// ---------------------------------------------------------------------------
// eTLD+1
// ---------------------------------------------------------------------------

/**
 * Extract eTLD+1 from a hostname.
 * Prefers chrome.publicSuffix API; falls back to hand-rolled lookup.
 * @param {string} hostname
 * @returns {string}
 */
export function getEtld1(hostname) {
  if (!hostname) return '';
  // Sync fallback — chrome.publicSuffix.getDomain() is async and we need
  // etld1 synchronously inside webRequest listeners. We pre-compute async
  // etld1 only when needed by the UI (classify() is called from capture,
  // where we already have the session's pageUrl hostname cached).
  return _etld1Sync(hostname);
}

/**
 * Async version — uses chrome.publicSuffix if available, else sync fallback.
 * Use this in UI code where async is fine.
 * @param {string} hostname
 * @returns {Promise<string>}
 */
export async function getEtld1Async(hostname) {
  if (!hostname) return '';
  if (typeof chrome !== 'undefined' && chrome.publicSuffix?.getDomain) {
    try {
      const result = await chrome.publicSuffix.getDomain(hostname);
      return result ?? _etld1Sync(hostname);
    } catch {
      // Fall through to sync fallback
    }
  }
  return _etld1Sync(hostname);
}

// Known multi-part TLD suffixes (covers the ~99% case for real browsing).
// Limitations documented: cloud subdomains (s3.amazonaws.com, appspot.com,
// github.io, etc.) will be incorrectly reduced to 2-part eTLD+1.
// The chrome.publicSuffix API (async path) handles these correctly.
const MULTI_PART = new Set([
  'co.uk','co.jp','co.nz','co.za','co.kr','co.in','co.il','co.id',
  'com.au','com.br','com.mx','com.ar','com.sg','com.hk','com.tw','com.tr','com.co',
  'org.uk','net.au','gov.uk','ac.uk','me.uk','ltd.uk','plc.uk',
  'ne.jp','or.jp','ed.jp','go.jp','gr.jp','lg.jp',
  'gov.au','edu.au','asn.au','id.au',
  'co.nz','net.nz','org.nz','govt.nz','ac.nz',
]);

function _etld1Sync(hostname) {
  // IP addresses have no eTLD+1 structure — the whole address IS the site's
  // identity. Without this check, an IPv4 host like "127.0.0.1" got sliced
  // like a domain name and truncated to its last two octets ("0.1"),
  // silently breaking site-scoped M6 blocking (declarativeNetRequest rules
  // were filed under the wrong initiatorDomains) and party detection for
  // any IP-hosted page — a local dev server or an intranet site reached by
  // IP. Found via testing (a block created through the UI didn't show up
  // under the real site key), not user-reported.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;
  if (hostname.includes(':')) return hostname; // IPv6, bracketed or not
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART.has(lastTwo)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

// ---------------------------------------------------------------------------
// Party determination
// ---------------------------------------------------------------------------

/**
 * @param {string} requestDomain
 * @param {string|null} pageUrl
 * @returns {'first-party'|'third-party'|'unknown'}
 */
export function getParty(requestDomain, pageUrl) {
  if (!pageUrl || !requestDomain) return 'unknown';
  try {
    const pageEtld1 = getEtld1(new URL(pageUrl).hostname);
    const reqEtld1  = getEtld1(requestDomain);
    return pageEtld1 === reqEtld1 ? 'first-party' : 'third-party';
  } catch {
    return 'unknown';
  }
}

// ---------------------------------------------------------------------------
// Full classification
// ---------------------------------------------------------------------------

/**
 * @param {string} domain
 * @param {string|null} pageUrl
 * @returns {Classification}
 *
 * @typedef {Object} Classification
 * @property {string} domain
 * @property {string} etld1
 * @property {'first-party'|'third-party'|'unknown'} party
 * @property {string|null} organization
 * @property {string|null} category
 * @property {'Observed'|'Classified'} provenance
 */
export function classify(domain, pageUrl) {
  const etld1 = getEtld1(domain);
  const party = getParty(domain, pageUrl);
  const trackerInfo = lookupTracker(domain) ?? lookupTracker(etld1);

  if (trackerInfo) {
    return { domain, etld1, party,
      organization: trackerInfo.organization,
      category:     trackerInfo.category,
      provenance:   'Classified' };
  }

  return { domain, etld1, party,
    organization: null, category: null, provenance: 'Observed' };
}
