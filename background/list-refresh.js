// Observa tracker/cookie list refresh — background/list-refresh.js (v0.11.0)
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
// This is the one place Observa makes a network request of its own (every
// other request is triggered by the site the user is visiting, not by
// Observa). It fetches only these two fixed, publicly-documented URLs —
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

const META_KEY = 'observa:listsMeta';
const ALARM_NAME = 'observa-list-refresh';
// A separate one-shot used to catch up after a failure or a long gap. Kept
// distinct from the periodic alarm so a retry never disturbs the regular
// schedule.
const CATCHUP_ALARM = 'observa-list-catchup';
const CATCHUP_DELAY_MINUTES = 2;        // after startup, once data looks stale
const RETRY_BASE_MINUTES = 30;          // after a failed refresh
const RETRY_MAX_MINUTES = 6 * 60;

/**
 * Exponential backoff for a failed refresh, capped.
 *
 * Exported so it can be unit-tested directly: the e2e suite reaches the real
 * upstream successfully, which means the failure path never runs there. An
 * untested retry is how a list quietly stops updating on the machines where it
 * matters most — the ones that are frequently offline.
 *
 * @param {number} consecutiveFailures 1 for the first failure
 * @returns {number} minutes to wait before retrying
 */
export function retryDelayMinutes(consecutiveFailures) {
  const n = Math.max(1, Math.floor(consecutiveFailures || 1));
  return Math.min(RETRY_BASE_MINUTES * 2 ** (n - 1), RETRY_MAX_MINUTES);
}
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

// Disconnect's raw category names -> Observa's 8-category taxonomy. Email/
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

async function fetchText(url, etag) {
  // A conditional request: if the upstream file has not changed, GitHub
  // answers 304 with no body. Both lists change on the order of days-to-weeks,
  // so most daily checks transfer nothing — which keeps a daily cadence honest
  // against the project's "minimal self-initiated egress" posture.
  const headers = etag ? { 'If-None-Match': etag } : undefined;
  const res = await fetch(url, { cache: 'no-store', headers });
  if (res.status === 304) return { notModified: true, text: null, etag };
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return { notModified: false, text: await res.text(), etag: res.headers.get('etag') };
}

/**
 * Arms the periodic alarm WITHOUT disturbing an existing schedule.
 *
 * chrome.alarms.create() is documented as replacing a same-named alarm, which
 * would restart the 24-hour countdown every time this runs. Since this runs at
 * every service-worker startup, and an MV3 worker restarts constantly, that
 * would mean the alarm never fires on an extension as active as this one.
 *
 * Measured behaviour in Chromium 141 disagrees with the documentation:
 * re-creating with identical parameters left `scheduledTime` untouched (12ms
 * delta, not 24 hours). Rather than depend on either — documented behaviour
 * would break the refresh, observed behaviour is undocumented and could change
 * — only create the alarm when it is actually missing or has the wrong period.
 * That is correct under both.
 */
async function ensurePeriodicAlarm() {
  const existing = await chrome.alarms.get(ALARM_NAME).catch(() => null);
  if (existing && existing.periodInMinutes === REFRESH_PERIOD_MINUTES) return;
  await chrome.alarms.create(ALARM_NAME, { periodInMinutes: REFRESH_PERIOD_MINUTES });
}

/** How stale is the stored data, in minutes? Infinity if never fetched. */
async function minutesSinceLastSuccess() {
  const stored = await chrome.storage.local.get(META_KEY);
  const last = stored[META_KEY]?.lastSuccess;
  if (typeof last !== 'number') return Infinity;
  return (Date.now() - last) / 60000;
}

/**
 * Fetch + parse + sanity-check + store both lists. Never throws — returns a
 * result object; callers (message handler, alarm) decide what to do with it.
 * @returns {Promise<{ok:boolean, trackerCount?:number, cookieExactCount?:number, cookieWildcardCount?:number, error?:string, checkedAt:number}>}
 */
export async function refreshLists() {
  const checkedAt = Date.now();
  try {
    const priorMeta = (await chrome.storage.local.get(META_KEY))[META_KEY] ?? {};
    const [disconnectRes, cookieRes] = await Promise.all([
      fetchText(DISCONNECT_URL, priorMeta.trackerEtag),
      fetchText(COOKIE_DB_URL, priorMeta.cookieEtag),
    ]);

    // Nothing changed upstream: the stored lists are already current. Record
    // the successful check so staleness is measured from now, not from the
    // last time the bytes happened to differ.
    if (disconnectRes.notModified && cookieRes.notModified) {
      const meta = {
        ...priorMeta, lastSuccess: checkedAt, lastChecked: checkedAt,
        error: null, notModified: true,
        consecutiveFailures: 0, nextRetryAt: null,
      };
      await chrome.storage.local.set({ [META_KEY]: meta });
      await chrome.alarms.clear(CATCHUP_ALARM);
      return { ok: true, notModified: true, checkedAt,
               trackerCount: priorMeta.trackerCount, cookieExactCount: priorMeta.cookieExactCount,
               cookieWildcardCount: priorMeta.cookieWildcardCount };
    }

    const disconnectText = disconnectRes.notModified ? null : disconnectRes.text;
    const cookieCsvText = cookieRes.notModified ? null : cookieRes.text;

    // One side may be unchanged while the other moved; re-fetch the unchanged
    // one unconditionally rather than storing a half-updated pair.
    const disconnectFinal = disconnectText ?? (await fetchText(DISCONNECT_URL)).text;
    const cookieFinal = cookieCsvText ?? (await fetchText(COOKIE_DB_URL)).text;

    const trackerMap = parseDisconnectList(JSON.parse(disconnectFinal));
    const trackerCount = Object.keys(trackerMap).length;
    if (trackerCount < MIN_TRACKER_DOMAINS) {
      throw new Error(`Parsed tracker list looks too small (${trackerCount} domains) — refusing to overwrite the bundled list.`);
    }

    const cookieDb = parseCookieCsv(cookieFinal);
    const cookieExactCount = Object.keys(cookieDb.exact).length;
    const cookieWildcardCount = cookieDb.wildcard.length;
    if (cookieExactCount < MIN_COOKIE_EXACT || cookieWildcardCount < MIN_COOKIE_WILDCARD) {
      throw new Error(`Parsed cookie database looks too small (${cookieExactCount} exact, ${cookieWildcardCount} wildcard) — refusing to overwrite the bundled database.`);
    }

    await chrome.storage.local.set({
      'observa:liveTrackerList': trackerMap,
      'observa:liveCookieDb': cookieDb,
    });
    // Reload the in-memory overlays immediately so this refresh takes
    // effect without waiting for the next service-worker restart.
    await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);

    const meta = {
      lastSuccess: checkedAt, lastChecked: checkedAt,
      trackerCount, cookieExactCount, cookieWildcardCount, error: null,
      trackerEtag: disconnectRes.etag ?? null,
      cookieEtag: cookieRes.etag ?? null,
      notModified: false,
      consecutiveFailures: 0, nextRetryAt: null,
    };
    await chrome.storage.local.set({ [META_KEY]: meta });
    // A successful refresh clears any pending retry.
    await chrome.alarms.clear(CATCHUP_ALARM);
    return { ok: true, trackerCount, cookieExactCount, cookieWildcardCount, checkedAt };
  } catch (err) {
    const prior = await chrome.storage.local.get(META_KEY);
    const priorMeta = prior[META_KEY] ?? {};
    // Back off, but keep trying. Without this a single offline moment meant
    // waiting a full day for the next scheduled attempt — on a laptop that is
    // closed and reopened, that is how a list quietly goes weeks out of date.
    const failures = (priorMeta.consecutiveFailures ?? 0) + 1;
    const delay = retryDelayMinutes(failures);
    const meta = {
      ...priorMeta, lastChecked: checkedAt,
      error: String(err?.message ?? err),
      consecutiveFailures: failures,
      nextRetryAt: checkedAt + delay * 60000,
    };
    await chrome.storage.local.set({ [META_KEY]: meta });
    await chrome.alarms.create(CATCHUP_ALARM, { delayInMinutes: delay });
    return { ok: false, error: String(err?.message ?? err), checkedAt, retryInMinutes: delay };
  }
}

export async function getListsMeta() {
  const stored = await chrome.storage.local.get(META_KEY);
  return stored[META_KEY] ?? null;
}

/** Clears the live overlays and metadata, reverting to the bundled snapshots. */
export async function clearLiveLists() {
  await chrome.storage.local.remove(['observa:liveTrackerList', 'observa:liveCookieDb', META_KEY]);
  await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);
}

/** Called once at service-worker startup. Loads whatever overlay already
 * exists in storage (no network call), and arms/disarms the periodic alarm
 * to match the current setting. */
export async function initListRefresh() {
  await Promise.all([loadLiveTrackerOverlay(), loadLiveCookieDbOverlay()]);
  const settings = await getSettings();
  if (!settings.listRefreshEnabled) {
    await chrome.alarms.clear(ALARM_NAME);
    await chrome.alarms.clear(CATCHUP_ALARM);
    return;
  }

  await ensurePeriodicAlarm();

  // Catch up on a gap the periodic alarm cannot close by itself.
  //
  // A periodic alarm only tells you when the NEXT tick is due; it says nothing
  // about ticks that never happened. A laptop closed for a fortnight, a machine
  // that was offline at every scheduled moment, or an alarm lost across an
  // extension update all leave the data stale with a perfectly healthy-looking
  // schedule. Measuring the data's own age is the only way to notice.
  //
  // Deliberately a short delay rather than an immediate fetch: startup is
  // already the busiest moment for the worker, and nothing here is urgent.
  const staleMinutes = await minutesSinceLastSuccess();
  if (staleMinutes > REFRESH_PERIOD_MINUTES) {
    const pending = await chrome.alarms.get(CATCHUP_ALARM).catch(() => null);
    if (!pending) await chrome.alarms.create(CATCHUP_ALARM, { delayInMinutes: CATCHUP_DELAY_MINUTES });
  }
}

/** Called from settings.js's setSetting flow when listRefreshEnabled changes. */
export async function onListRefreshSettingChanged(enabled) {
  if (enabled) {
    await ensurePeriodicAlarm();
  } else {
    await chrome.alarms.clear(ALARM_NAME);
    await chrome.alarms.clear(CATCHUP_ALARM);
  }
}

chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_NAME && alarm.name !== CATCHUP_ALARM) return;
  const settings = await getSettings();
  if (!settings.listRefreshEnabled) return; // setting may have changed since the alarm fired
  await refreshLists();
});
