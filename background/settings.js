// WebLens settings store — background/settings.js — M5.
//
// Single small object in chrome.storage.local holding opt-in, off-by-default
// feature flags. Kept separate from history.js so it can depend on this
// without a circular import.
//
// Per CLAUDE.md Rule 6: module-level cache is a performance optimization
// only, never the source of truth — it's always safe to fall back to a
// fresh storage read if the service worker restarted and the cache is gone.

const SETTINGS_KEY = 'weblens:settings';
// theme: 'system' (follow OS) | 'light' | 'dark'. Purely cosmetic, stored
// alongside historyEnabled since it's the same "small local preference
// object" — no new storage area, no new permission.
// listRefreshEnabled: periodically re-fetches the same two upstream
// tracker/cookie sources the bundled snapshots were generated from — see
// background/list-refresh.js. Introduced opt-in/off in v0.11.0; switched to
// on-by-default in v0.11.2 per explicit user direction, so the lists stay
// current without requiring a trip to settings. Still a single toggle the
// user can turn off at any time, and still the only outbound request
// WebLens itself ever makes (two fixed public URLs, no browsing data).
const DEFAULTS = Object.freeze({ historyEnabled: false, theme: 'system', listRefreshEnabled: true });
const BOOLEAN_KEYS = new Set(['historyEnabled', 'listRefreshEnabled']);

let _cache = null;

async function _ensure() {
  if (_cache) return _cache;
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  _cache = { ...DEFAULTS, ...(stored[SETTINGS_KEY] ?? {}) };
  return _cache;
}

// Keep the cache correct if settings change from another context (e.g. the
// dashboard's settings panel writes directly... it doesn't; it always goes
// through setSetting() below via message passing. This listener is a safety
// net for any future direct-write path.)
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[SETTINGS_KEY]) {
    _cache = { ...DEFAULTS, ...(changes[SETTINGS_KEY].newValue ?? {}) };
  }
});

/** @returns {Promise<{historyEnabled:boolean, theme:'system'|'light'|'dark'}>} */
export async function getSettings() {
  return _ensure();
}

/**
 * @param {'historyEnabled'|'theme'} key
 * @param {boolean|string} value
 */
export async function setSetting(key, value) {
  const current = await _ensure();
  const next = { ...current, [key]: BOOLEAN_KEYS.has(key) ? !!value : value };
  _cache = next;
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}
