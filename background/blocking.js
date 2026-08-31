// WebLens site-scoped blocking — background/blocking.js — M6 (Verify & Protect).
//
// This is WebLens's first active intervention — everything before this
// module only observed. It exists solely as the mechanism behind an
// explicit user click ("Block this on this site"): WebLens never blocks
// proactively or based on classification alone, and never blocks anything
// the user didn't ask it to.
//
// Uses Manifest V3's declarativeNetRequest dynamic rules, scoped with both
// `requestDomains` (the tracker) and `initiatorDomains` (the site the user
// is on) so a block only applies to that one site — blocking a tracker
// here never affects it on other sites. Chrome persists dynamic rules
// across restarts on its own; the small index kept here just maps
// (site, tracker domain) -> rule id so WebLens can look up and toggle them.

const RULES_INDEX_KEY = 'weblens:blockRules'; // { [siteEtld1]: { [trackerDomain]: ruleId } }
const NEXT_ID_KEY = 'weblens:nextRuleId';

// Deliberately excludes 'main_frame' — WebLens must never block a top-level
// navigation, only resources a page pulls in from the tracker.
const BLOCK_RESOURCE_TYPES = [
  'script', 'xmlhttprequest', 'image', 'stylesheet', 'font',
  'media', 'websocket', 'ping', 'other', 'sub_frame', 'csp_report',
];

async function _getIndex() {
  const stored = await chrome.storage.local.get(RULES_INDEX_KEY);
  return stored[RULES_INDEX_KEY] ?? {};
}

async function _setIndex(idx) {
  await chrome.storage.local.set({ [RULES_INDEX_KEY]: idx });
}

async function _nextId() {
  const stored = await chrome.storage.local.get(NEXT_ID_KEY);
  const id = stored[NEXT_ID_KEY] ?? 1;
  await chrome.storage.local.set({ [NEXT_ID_KEY]: id + 1 });
  return id;
}

/** @returns {Promise<boolean>} */
export async function isBlocked(siteEtld1, trackerDomain) {
  const idx = await _getIndex();
  return !!idx[siteEtld1]?.[trackerDomain];
}

/** @returns {Promise<string[]>} tracker domains currently blocked on this site */
export async function getBlockedForSite(siteEtld1) {
  const idx = await _getIndex();
  return Object.keys(idx[siteEtld1] ?? {});
}

/**
 * Block one tracker domain, scoped to one site. Idempotent.
 * @param {string} siteEtld1
 * @param {string} trackerDomain
 */
export async function blockDomainOnSite(siteEtld1, trackerDomain) {
  if (!siteEtld1 || !trackerDomain) return;
  const idx = await _getIndex();
  idx[siteEtld1] = idx[siteEtld1] ?? {};
  if (idx[siteEtld1][trackerDomain]) return; // already blocked

  const id = await _nextId();
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [{
      id,
      priority: 1,
      action: { type: 'block' },
      condition: {
        requestDomains: [trackerDomain],
        initiatorDomains: [siteEtld1],
        resourceTypes: BLOCK_RESOURCE_TYPES,
      },
    }],
    removeRuleIds: [],
  });

  idx[siteEtld1][trackerDomain] = id;
  await _setIndex(idx);
}

/**
 * Unblock — the inverse of blockDomainOnSite, and the only "restore"
 * mechanism WebLens offers. There's no separate restore flow: blocking is
 * a toggle, and toggling it off is the undo.
 */
export async function unblockDomainOnSite(siteEtld1, trackerDomain) {
  const idx = await _getIndex();
  const id = idx[siteEtld1]?.[trackerDomain];
  if (!id) return;

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [id],
    addRules: [],
  });

  delete idx[siteEtld1][trackerDomain];
  if (Object.keys(idx[siteEtld1]).length === 0) delete idx[siteEtld1];
  await _setIndex(idx);
}

/** Removes every WebLens block, on every site. Used by "Clear all WebLens data". */
export async function clearAllBlocks() {
  const idx = await _getIndex();
  const allIds = Object.values(idx).flatMap(m => Object.values(m));
  if (allIds.length) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: allIds, addRules: [] });
  }
  await chrome.storage.local.remove(RULES_INDEX_KEY);
}
