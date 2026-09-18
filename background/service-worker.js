// Observa service worker — M4.

import { registerCaptureListeners } from './capture.js';
import { startSession, endSession, getSessionForTab, getAllSessionIds, clearSessionForTab } from './session.js';
import { getCookiesForUrl, summarizeCookies } from './cookies.js';
import { getSettings, setSetting } from './settings.js';
import { getHistoryFor, clearAllHistory } from './history.js';
import { isBlocked, getBlockedForSite, blockDomainOnSite, unblockDomainOnSite, clearAllBlocks } from './blocking.js';
import { initListRefresh, refreshLists, getListsMeta, clearLiveLists, onListRefreshSettingChanged } from './list-refresh.js';
import { analyzePolicyForTab, analyzeManualDocument, getPolicyIntelForTab, clearPolicyIntelForTab } from './policy-intel.js';

// Allow extension pages (dashboard) to read chrome.storage.session directly.
// Must be called before any storage writes.
chrome.storage.session.setAccessLevel({
  accessLevel: chrome.storage.AccessLevel.TRUSTED_AND_UNTRUSTED_CONTEXTS
}).catch(console.error);

// --- Listeners (synchronous, top level) ------------------------------------

registerCaptureListeners();
initListRefresh().catch(console.error);

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  // Don't capture sessions for extension pages themselves
  if (details.url.startsWith('chrome-extension://')) return;
  if (details.url.startsWith('chrome://')) return;
  await startSession(details.tabId, details.url);
  // A new top-level navigation means any Policy Intelligence result cached
  // for this tab belongs to the page that just left — clear it so the
  // dashboard doesn't show a stale policy analysis for a different site.
  await clearPolicyIntelForTab(details.tabId).catch(console.error);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await endSession(tabId);
  await clearPolicyIntelForTab(tabId).catch(console.error);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'observa:getSession') {
    getSessionForTab(message.tabId)
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:getCookies') {
    getCookiesForUrl(message.url)
      .then(cookies => sendResponse({ cookies, summary: summarizeCookies(cookies) }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:clearSession') {
    clearSessionForTab(message.tabId)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // Dashboard uses this — returns the most recent non-extension session
  if (message?.type === 'observa:getMostRecentSession') {
    getAllSessionIds()
      .then(async tabIds => {
        let best = null;
        for (const tabId of tabIds) {
          const session = await getSessionForTab(tabId);
          if (!session) continue;
          // Skip sessions for extension pages and empty sessions
          if (session.pageUrl?.startsWith('chrome-extension://')) continue;
          if (session.pageUrl?.startsWith('chrome://')) continue;
          if (!session.requests?.length) continue;
          if (!best || session.startedAt > best.startedAt) best = session;
        }
        sendResponse(best);
      })
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:getSessions') {
    getAllSessionIds()
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // ── M5: settings, history ──────────────────────────────────────────────────

  if (message?.type === 'observa:getSettings') {
    getSettings()
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:setSetting') {
    setSetting(message.key, message.value)
      .then(async (next) => {
        if (message.key === 'listRefreshEnabled') {
          await onListRefreshSettingChanged(!!message.value).catch(console.error);
        }
        sendResponse(next);
      })
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // ── v0.11.0: tracker/cookie list refresh (opt-in) ────────────────────────
  if (message?.type === 'observa:getListsMeta') {
    getListsMeta()
      .then(meta => sendResponse({ meta }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:refreshListsNow') {
    refreshLists()
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:clearLiveLists') {
    clearLiveLists()
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:getHistory') {
    getHistoryFor(message.etld1)
      .then(days => sendResponse({ days }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // Clears the opt-in history store. Per-tab session data has its own clear
  // path (observa:clearSession) and is intentionally untouched here.
  if (message?.type === 'observa:clearDurableData') {
    clearAllHistory()
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // ── M6: Verify & Protect — site-scoped blocking ────────────────────────────
  // Every call here is a direct response to an explicit user click. Observa
  // never blocks on its own initiative.

  if (message?.type === 'observa:isBlocked') {
    isBlocked(message.siteEtld1, message.domain)
      .then(blocked => sendResponse({ blocked }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:getBlockedForSite') {
    getBlockedForSite(message.siteEtld1)
      .then(domains => sendResponse({ domains }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:blockDomain') {
    blockDomainOnSite(message.siteEtld1, message.domain)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:unblockDomain') {
    unblockDomainOnSite(message.siteEtld1, message.domain)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:clearAllBlocks') {
    clearAllBlocks()
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  // ── Policy Intelligence ─────────────────────────────────────────────────
  // Auto-discovery + analysis runs only when the dashboard explicitly asks
  // for it (opening the Policy Intelligence view for a session), not
  // proactively on every page load — see background/policy-intel.js's
  // header comment for the full reasoning on the network egress involved.

  if (message?.type === 'observa:getPolicyIntel') {
    getPolicyIntelForTab(message.tabId)
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:analyzePolicy') {
    analyzePolicyForTab(message.tabId, message.pageUrl, { force: !!message.force })
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err) }));
    return true;
  }

  if (message?.type === 'observa:analyzeManualPolicy') {
    analyzeManualDocument(message.tabId, message.pageUrl, {
      docType: message.docType, url: message.url, text: message.text,
    })
      .then(sendResponse)
      .catch(err => sendResponse({ error: String(err?.message ?? err) }));
    return true;
  }
});
