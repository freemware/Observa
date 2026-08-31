// WebLens tracker/cookie list refresh — background/list-refresh.js (v0.11.0)
//
// Opt-in, off by default. Fetches the same two upstream sources the bundled
// classify/tracker-list.js and classify/cookie-db.js snapshots were
// generated from, parses them into the exact same shape those modules
// already use, sanity-checks the result, and stores it in
// chrome.storage.local as an overlay those modules check before falling
// back to the bundled data (see loadLiveTrackerOverlay/loadLiveCookieDbOverlay
// in each). A failed or disabled refresh always degrades to exactly today's
// bundled-only behavior — it can only add freshness, never remove data.
//
// This is the one place WebLens makes a network request of its own (every
// other request is triggered by the site the user is visiting, not by
// WebLens). It fetches only these two fixed, publicly-documented URLs —
// never anything derived from browsing activity — and sends nothing.
//
// Sources (same as the bundled snapshots' attribution):
//   Disconnect Tracking Protection list — CC BY-NC-SA 4.0
//   https://github.com/disconnectme/disconnect-tracking-protection
//   Open Cookie Database — CC0
//   https://github.com/jkwakman/Open-Cookie-Database

import { getSettings } from './settings.js';
import { loadLiveTrackerOverlay } from '../classify/tracker-list.js';
import { loadLiveCookieDbOverlay } from '../classify/cookie-db.js';

const DISCONNECT_URL = 'https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json';
const COOKIE_DB_URL = 'https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/master/open-cookie-database.csv';

const META_KEY = 'weblens:listsMeta';
const ALARM_NAME = 'weblens-list-refresh';
// Once a day. Both upstream sources are maintained lists, not live feeds —
// Disconnect's and Open Cookie Database's own commit history runs on the
// order of days-to-weeks, not hours — so daily already checks noticeably
// more often than the data underneath it actually changes. Reconsidered as
// part of turning this on-by-default in v0.11.2: shortening the interval
// would add outbound requests with no real freshness gain and cut against
// the "minimal self-initiated egress" posture the project otherwise holds
// itself to, so the interval itself is unchanged — only the default (see
// settings.js) moved from opt-in to on.
const REFRESH_PERIOD_MINUTES = 24 * 60;

// Disconnect's raw category names -> WebLens's 8-category taxonomy. Email/
// EmailAggressive are intentionally excluded — the bundled snapshot never
// included them either, so this keeps refreshed data consistent with the
// categories the rest of the UI (badges, findings, etc.) already knows.
const CATEGORY_MAP = {
  Advertising: 'Advertising',
  Content: 'Content',
  Analytics: 'Analytics',
  FingerprintingInvasive: 'Fingerprinting',
  FingerprintingGeneral: 'Fingerprinting',
  'Anti-fraud': 'Anti-fraud',
  Social: 'Social',
  ConsentManagers: 'Consent',
  Cryptomining: 'Cryptomining',
};

// Sanity floors — reject a parsed result that looks corrupted (e.g. GitHub
// served an HTML error page, or the upstream schema changed underneath us)
// rather than silently overlaying broken/tiny data over the good bundled
// snapshot. Set comfortably below current counts to tolerate normal drift.
const MIN_TRACKER_DOMAINS = 2000;
const MIN_COOKIE_EXACT = 800;
const MIN_COOKIE_WILDCARD = 50;

// Exported (in addition to the internal call sites below) so the parsing
// logic itself can be unit-tested directly against real sample data without
// needing chrome.* APIs or a network call — see test/list-refresh-unit.mjs.
// A handful of domains (e.g. doubleclick.net) appear under more than one
// Disconnect category — it serves ads AND is used for fingerprinting.
// First match wins rather than last, so iteration order over the JSON
// object doesn't silently flip a domain's category on every refresh; this
// also matches the bundled snapshot's own existing classification for the
// domains checked against it (e.g. doubleclick.net stays "Advertising").
export function parseDisconnectList(json) {
  const out = {};
  const categories = json?.categories ?? {};
  for (const [rawCategory, entries] of Object.entries(categories)) {
    const category = CATEGORY_MAP[rawCategory];
    if (!category || !Array.isArray(entries)) continue;
    for (const entryWrapper of entries) {
      for (const [orgName, urlMap] of Object.entries(entryWrapper)) {
        for (const domains of Object.values(urlMap)) {
          if (!Array.isArray(domains)) continue;
          for (const domain of domains) {
            if (typeof domain === 'string' && domain && !(domain in out)) out[domain] = [orgName, category];
          }
        }
      }
    }
  }
  return out;
}

// Minimal RFC4180-ish single-line CSV field splitter — sufficient for this
// specific file, which (checked against the live source) never embeds a
// newline inside a quoted field, only commas and literal quotes ("").
export function splitCsvLine(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = false;
      } else cur += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      fields.push(cur); cur = '';
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

export function parseCookieCsv(text) {
  const lines = text.split('\n').filter(l => l.trim().length);
  const exact = {};
  const wildcard = [];
  // Skip header row.
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    const [, platform, category, name, , description, retention, controller, , wildcardFlag] = cols;
    if (!name) continue;
    const entry = { p: platform || '', c: category || '', d: description || '', r: retention || '', dc: controller || '' };
    if (wildcardFlag === '1') {
      wildcard.push({ n: name, ...entry });
    } else if (!(name in exact)) {
      exact[name] = entry;
    }
  }
  return { exact, wildcard };
}

async function fetchText(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.text();
}

/**
 * Fetch + parse + sanity-check + store both lists. Never throws — returns a
 * result object; callers (message handler, alarm) decide what to do with it.
 * @returns {Promise<{ok:boolean, trackerCount?:number, cookieExactCount?:number, cookieWildcardCount?:number, error?:string, checkedAt:number}>}
 */
export async function refreshLists() {
  const checkedAt = Date.now();
  try {
    const [disconnectText, cookieCsvText] = await Promise.all([
      fetchText(DISCONNECT_URL),
      fetchText(COOKIE_DB_URL),
    ]);

    const trackerMap = parseDisconnectList(JSON.parse(disconnectText));
    const trackerCount = Object.keys(trackerMap).length;
    if (trackerCount < MIN_TRACKER_DOMAINS) {
      throw new Error(`Parsed tracker list looks too small (${trackerCount} domains) — refusing to overwrite the bundled list.`);
    }

    const cookieDb = parseCookieCsv(cookieCsvText);
    const cookieExactCount = Object.keys(cookieDb.exact).length;
    const cookieWildcardCount = cookieDb.wildcard.length;
    if (cookieExactCount < MIN_COOKIE_EXACT || cookieWildcardCount < MIN_COOKIE_WILDCARD) {
      throw new Error(`Parsed cookie database looks too small (${cookieExactCount} exact, ${cookieWildcardCount} wildcard) — refusing to overwrite the bundled database.`);
    }

    await chrome.storage.local.set({
      'weblens:liveTrackerList': trackerMap,
      'weblens:liveCookieDb': cookieDb,
    });
    // Reload the in-memory overlays immediately so this refresh takes
    // effect without waiting for the next service-worker restart.
    await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);

    const meta = { lastSuccess: checkedAt, lastChecked: checkedAt, trackerCount, cookieExactCount, cookieWildcardCount, error: null };
    await chrome.storage.local.set({ [META_KEY]: meta });
    return { ok: true, trackerCount, cookieExactCount, cookieWildcardCount, checkedAt };
  } catch (err) {
    const prior = await chrome.storage.local.get(META_KEY);
    const meta = { ...(prior[META_KEY] ?? {}), lastChecked: checkedAt, error: String(err?.message ?? err) };
    await chrome.storage.local.set({ [META_KEY]: meta });
    return { ok: false, error: String(err?.message ?? err), checkedAt };
  }
}

export async function getListsMeta() {
  const stored = await chrome.storage.local.get(META_KEY);
  return stored[META_KEY] ?? null;
}

/** Clears the live overlays and metadata, reverting to the bundled snapshots. */
export async function clearLiveLists() {
  await chrome.storage.local.remove(['weblens:liveTrackerList', 'weblens:liveCookieDb', META_KEY]);
  await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);
}

/** Called once at service-worker startup. Loads whatever overlay already
 * exists in storage (no network call), and arms/disarms the periodic alarm
 * to match the current setting. */
export async function initListRefresh() {
  await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);
  const settings = await getSettings();
  if (settings.listRefreshEnabled) {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: REFRESH_PERIOD_MINUTES });
  } else {
    chrome.alarms.clear(ALARM_NAME);
  }
}

/** Called from settings.js's setSetting flow when listRefreshEnabled changes. */
export async function onListRefreshSettingChanged(enabled) {
  if (enabled) {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: REFRESH_PERIOD_MINUTES });
  } else {
    chrome.alarms.clear(ALARM_NAME);
  }
}

chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_NAME) return;
  const settings = await getSettings();
  if (!settings.listRefreshEnabled) return; // setting may have changed since the alarm fired
  await refreshLists();
});
