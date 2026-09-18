// Observa session history — background/history.js — M5.
//
// Durable, opt-in, off-by-default. One summarized record per first-party
// site per calendar day: counts only (third-party count, cookie count,
// tracker-match count, cross-site-heuristic count, long-lived cookie
// count). Never stores raw requests, URLs, or cookie names/values.
//
// Stored in chrome.storage.local (existing `storage` permission). Recording
// is a no-op unless the user has enabled it via settings.js.

import { getSettings } from './settings.js';

const HISTORY_PREFIX = 'observa:history:';
const INDEX_KEY = 'observa:historyIndex';

// Caps — bound chrome.storage.local growth. A site keeps at most the last
// MAX_DAYS_PER_SITE calendar days with activity; the extension as a whole
// remembers at most MAX_SITES distinct sites, evicting the least-recently
// updated site's entire history when a new site would exceed the cap.
const MAX_DAYS_PER_SITE = 30;
const MAX_SITES = 200;

function _dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10); // YYYY-MM-DD, UTC
}

/**
 * @param {string} pageEtld1
 * @param {{thirdPartyCount:number, trackerCount:number,
 *          cookieCount:number, longLivedCookieCount:number}} summary
 */
export async function recordSessionSummary(pageEtld1, summary) {
  const settings = await getSettings();
  if (!settings.historyEnabled || !pageEtld1) return;

  const key = HISTORY_PREFIX + pageEtld1;
  const stored = await chrome.storage.local.get(key);
  const days = stored[key] ?? [];
  const today = _dayKey(Date.now());

  let entry = days.find(d => d.date === today);
  if (!entry) {
    entry = {
      date: today, sessions: 0, thirdPartyCount: 0, trackerCount: 0,
      cookieCount: 0, longLivedCookieCount: 0,
    };
    days.push(entry);
  }

  // Same-day re-visits: keep the high-water mark per metric rather than
  // summing, so re-loading a page 5 times doesn't inflate counts 5x.
  entry.thirdPartyCount     = Math.max(entry.thirdPartyCount,     summary.thirdPartyCount ?? 0);
  entry.trackerCount        = Math.max(entry.trackerCount,        summary.trackerCount ?? 0);
  entry.cookieCount         = Math.max(entry.cookieCount,         summary.cookieCount ?? 0);
  entry.longLivedCookieCount= Math.max(entry.longLivedCookieCount,summary.longLivedCookieCount ?? 0);
  entry.sessions += 1;

  days.sort((a, b) => a.date < b.date ? -1 : 1);
  const trimmed = days.slice(-MAX_DAYS_PER_SITE);

  await chrome.storage.local.set({ [key]: trimmed });
  await _touchIndex(pageEtld1);
}

async function _touchIndex(pageEtld1) {
  const stored = await chrome.storage.local.get(INDEX_KEY);
  let index = stored[INDEX_KEY] ?? [];
  index = index.filter(e => e.etld1 !== pageEtld1);
  index.push({ etld1: pageEtld1, lastWrite: Date.now() });

  if (index.length > MAX_SITES) {
    index.sort((a, b) => a.lastWrite - b.lastWrite);
    const evicted = index.splice(0, index.length - MAX_SITES);
    const removeKeys = evicted.map(e => HISTORY_PREFIX + e.etld1);
    if (removeKeys.length) await chrome.storage.local.remove(removeKeys);
  }

  await chrome.storage.local.set({ [INDEX_KEY]: index });
}

/**
 * @param {string} pageEtld1
 * @returns {Promise<Array>} daily summaries, oldest first
 */
export async function getHistoryFor(pageEtld1) {
  if (!pageEtld1) return [];
  const key = HISTORY_PREFIX + pageEtld1;
  const stored = await chrome.storage.local.get(key);
  return stored[key] ?? [];
}

export async function clearAllHistory() {
  const stored = await chrome.storage.local.get(INDEX_KEY);
  const index = stored[INDEX_KEY] ?? [];
  const keys = index.map(e => HISTORY_PREFIX + e.etld1);
  keys.push(INDEX_KEY);
  if (keys.length) await chrome.storage.local.remove(keys);
}
