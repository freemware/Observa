// WebLens session manager — M2.
// Owns session state. Exposes getPageUrlForTab() so capture.js can classify
// requests against the current page URL at capture time.

import { makeSession, hostnameFromUrl } from '../shared/schema.js';
import { getEtld1 } from '../classify/classify.js';
import { getSettings } from './settings.js';
import { getCookiesForUrl } from './cookies.js';
import { recordSessionSummary } from './history.js';

const _sessions = new Map();      // tabId -> Session
const _flushTimers = new Map();   // tabId -> setTimeout handle

const FLUSH_DELAY_MS = 500;
const SESSION_KEY = (tabId) => `session:tab-${tabId}`;
const INDEX_KEY = 'sessions:index';

// ---------------------------------------------------------------------------

export async function startSession(tabId, pageUrl) {
  const session = makeSession(tabId, pageUrl);
  _sessions.set(tabId, session);
  await _flushNow(tabId);
  await _updateIndex(tabId, 'add');
}

export async function endSession(tabId) {
  const session = await _getSession(tabId);
  if (!session) return;
  session.endedAt = Date.now();
  _sessions.set(tabId, session);
  await _flushNow(tabId);
  // Best-effort — history is opt-in and its own failure must never break
  // ordinary session teardown.
  _recordHistoryIfEnabled(session).catch(err =>
    console.error('[WebLens] history record failed:', err));
  _sessions.delete(tabId);
  _flushTimers.delete(tabId);
}

/**
 * M5 — summarize this session into history.js, but only if the user has
 * opted in. Counts only: never writes URLs, cookie names, or raw requests.
 */
async function _recordHistoryIfEnabled(session) {
  if (!session?.requests?.length || !session.pageUrl) return;
  const settings = await getSettings();
  if (!settings.historyEnabled) return;

  const pageEtld1 = getEtld1(hostnameFromUrl(session.pageUrl));

  const thirdParties = new Map(); // etld1 -> a representative request
  for (const r of session.requests) {
    if (r.party === 'third-party') thirdParties.set(r.etld1, r);
  }
  const trackerCount = [...thirdParties.values()]
    .filter(r => r.provenance === 'Classified').length;

  let cookieCount = 0, longLivedCookieCount = 0;
  try {
    const cookies = await getCookiesForUrl(session.pageUrl);
    cookieCount = cookies.length;
    longLivedCookieCount = cookies.filter(c => c.longLived).length;
  } catch { /* cookie read failed — history record still worth keeping */ }

  await recordSessionSummary(pageEtld1, {
    thirdPartyCount: thirdParties.size,
    trackerCount,
    cookieCount,
    longLivedCookieCount,
  });
}

export function handleRequest(request) {
  const session = _sessions.get(request.tabId);
  if (!session) return;
  session.requests.push(request);
  _scheduleFlush(request.tabId);
}

export function handleRequestComplete(requestId, tabId, statusCode) {
  const session = _sessions.get(tabId);
  if (!session) return;
  const req = session.requests.find(r => r.id === requestId);
  if (req) { req.status = 'completed'; req.statusCode = statusCode; }
  _scheduleFlush(tabId);
}

export function handleRequestError(requestId, tabId, error) {
  const session = _sessions.get(tabId);
  if (!session) return;
  const req = session.requests.find(r => r.id === requestId);
  // `error` is Chrome's net-error string (e.g. 'net::ERR_BLOCKED_BY_CLIENT'
  // for a declarativeNetRequest block, among other causes). Kept so the UI
  // can tell "blocked by an extension" apart from an ordinary network
  // failure — see shared/schema.js isBlockedError().
  if (req) { req.status = 'error'; req.error = error ?? null; }
  _scheduleFlush(tabId);
}

/**
 * Returns the page URL for a tab's active session, or null.
 * Used by capture.js to classify requests at capture time.
 * Synchronous — only checks in-memory map (storage read would be async
 * and we're inside a webRequest listener).
 */
export function getPageUrlForTab(tabId) {
  return _sessions.get(tabId)?.pageUrl ?? null;
}

export async function getSessionForTab(tabId) {
  if (_sessions.has(tabId)) return _sessions.get(tabId);
  return _readFromStorage(tabId);
}

export async function getAllSessionIds() {
  const stored = await chrome.storage.session.get(INDEX_KEY);
  return stored[INDEX_KEY] ?? [];
}

// ---------------------------------------------------------------------------

function _scheduleFlush(tabId) {
  if (_flushTimers.has(tabId)) return;
  const handle = setTimeout(() => {
    _flushTimers.delete(tabId);
    _flushNow(tabId).catch(console.error);
  }, FLUSH_DELAY_MS);
  _flushTimers.set(tabId, handle);
}

async function _flushNow(tabId) {
  const session = _sessions.get(tabId);
  if (!session) return;
  await chrome.storage.session.set({ [SESSION_KEY(tabId)]: session });
}

async function _getSession(tabId) {
  return _sessions.get(tabId) ?? _readFromStorage(tabId);
}

async function _readFromStorage(tabId) {
  const stored = await chrome.storage.session.get(SESSION_KEY(tabId));
  return stored[SESSION_KEY(tabId)] ?? null;
}

// Serializes the index's read-modify-write cycle. Without this, two tabs
// committing navigations close together (e.g. opening several tabs at once)
// can race: both read the same stored index before either writes it back,
// so whichever write lands second silently discards the other tab's entry
// from chrome.storage.session, and that tab disappears from
// weblens:getSessions even though its in-memory session data is intact.
// (v0.11.0 — found via a flaky multi-tab test, not user-reported, but a
// real correctness gap in existing M2 code.)
let _indexQueue = Promise.resolve();
function _updateIndex(tabId, action) {
  _indexQueue = _indexQueue.then(async () => {
    const stored = await chrome.storage.session.get(INDEX_KEY);
    const index = new Set(stored[INDEX_KEY] ?? []);
    if (action === 'add') index.add(tabId); else index.delete(tabId);
    await chrome.storage.session.set({ [INDEX_KEY]: [...index] });
  });
  return _indexQueue;
}

/**
 * Clear the session for a tab without ending it — used by the "clear" button.
 * Resets request list but keeps the session alive for new captures.
 */
export async function clearSessionForTab(tabId) {
  const session = await _getSession(tabId);
  if (!session) return;
  session.requests = [];
  session.startedAt = Date.now();
  _sessions.set(tabId, session);
  await _flushNow(tabId);
}
