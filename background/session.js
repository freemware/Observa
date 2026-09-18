// Observa session manager — M2.
// Owns session state. Exposes getPageUrlForTab() so capture.js can classify
// requests against the current page URL at capture time.

import { makeSession, hostnameFromUrl } from '../shared/schema.js';
import { getEtld1, classify } from '../classify/classify.js';
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
  _adoptNav(session);
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
    console.error('[Observa] history record failed:', err));
  _sessions.delete(tabId);
  _flushTimers.delete(tabId);
  _pendingNav.delete(tabId);
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

// ── The navigation request arrives before the session it belongs to ────────
// Chrome fires webRequest.onBeforeRequest for a top-level document BEFORE
// webNavigation.onCommitted, and it is onCommitted that starts the session for
// the page being navigated to. So at the moment the document request is seen,
// the only session that exists is the OUTGOING page's — or none at all on a
// fresh tab. The request was therefore either dropped on the floor or filed
// under the previous page and then discarded when startSession replaced it.
//
// Verified by navigating alpha -> beta and dumping storage: neither document
// request survived; the only captured request was a favicon.
//
// The consequences were not cosmetic. The page's own document never appeared in
// the request list, the request count was short by one, and — because
// shared/timing.js takes t0 from the first captured request — the load baseline
// was the first SUBRESOURCE, making every elapsed time too small and biasing
// the "after the page settled" classification.
//
// It is not only the document. Chrome's preload scanner starts fetching scripts
// and stylesheets as soon as it is parsing the HTML, which can happen before
// onCommitted reaches the extension. Those early subresources hit the same gap:
// ground-truth testing caught doubleclick.net/px.js — the first script tag on a
// page — arriving at the server but never appearing in the session.
//
// So every request is buffered briefly per tab, and startSession adopts the
// main-frame request matching the page it is starting PLUS everything that
// arrived after it. "After the navigation request for this URL" is what makes
// them provably part of this page rather than the previous one.
const _pendingNav = new Map();   // tabId -> Array<request>
const PENDING_NAV_TTL_MS = 30000;
const PENDING_NAV_MAX = 120;     // bounded: a tab can never accumulate

function _rememberPending(request) {
  const list = _pendingNav.get(request.tabId) ?? [];
  const now = Date.now();
  const fresh = list.filter(r => now - (r.timestamp ?? 0) < PENDING_NAV_TTL_MS);
  fresh.push(request);
  _pendingNav.set(request.tabId, fresh.slice(-PENDING_NAV_MAX));
}

function _adoptNav(session) {
  const list = _pendingNav.get(session.tabId);
  _pendingNav.delete(session.tabId);
  if (!list?.length) return;

  // Anchor on the MOST RECENT navigation request for this page. Reloading the
  // same URL leaves the previous load's requests in the buffer under the same
  // pageUrl; anchoring on the first match would pull that entire earlier page
  // view into the new session.
  let navIndex = -1;
  for (let i = list.length - 1; i >= 0; i--) {
    if (list[i].type === 'main_frame' && list[i].url === session.pageUrl) { navIndex = i; break; }
  }
  if (navIndex === -1) return;   // nothing provably belongs to this page

  // The navigation request, then anything captured after it. A main-frame
  // request for some OTHER url in that window is a navigation away and is not
  // adopted — it will be claimed by its own session.
  const mine = list.slice(navIndex).filter(r => r.type !== 'main_frame' || r.url === session.pageUrl);

  // Re-classify against the page we now know about.
  //
  // These were captured before any session existed, so capture.js had no page
  // URL to judge them against: classify(domain, null) yields party 'unknown',
  // and on a navigation from another site they were measured against the
  // PREVIOUS page — which marked a site's own subresources third-party.
  // Ground-truth testing caught both ("unknown != third-party" and
  // "third-party != first-party"). First/third-party is meaningless without a
  // page to be first-party TO, so it can only be decided here.
  for (const r of mine) {
    const c = classify(r.domain, session.pageUrl);
    r.party = c.party;
    r.organization = c.organization;
    r.category = c.category;
    r.provenance = c.provenance;
    r.etld1 = c.etld1 ?? r.etld1;
  }
  session.requests.push(...mine);
}

export function handleRequest(request) {
  _rememberPending(request);
  const session = _sessions.get(request.tabId);
  if (!session) return;
  // A main-frame request for a DIFFERENT url than the current session is the
  // navigation away from this page. It belongs to the page being loaded, not
  // to this one, and _adoptNav will hand it over when that session starts.
  if (request.type === 'main_frame' && request.url !== session.pageUrl) return;
  session.requests.push(request);
  _scheduleFlush(request.tabId);
}

// A navigation request can complete before the session that will adopt it
// exists, so its status update has to reach the pending buffer too — otherwise
// the page's own document is permanently stuck at "pending".
function _findRequest(tabId, requestId) {
  const inSession = _sessions.get(tabId)?.requests.find(r => r.id === requestId);
  if (inSession) return inSession;
  return (_pendingNav.get(tabId) ?? []).find(r => r.id === requestId) ?? null;
}

export function handleRequestComplete(requestId, tabId, statusCode) {
  const req = _findRequest(tabId, requestId);
  if (req) { req.status = 'completed'; req.statusCode = statusCode; }
  if (_sessions.has(tabId)) _scheduleFlush(tabId);
}

export function handleRequestError(requestId, tabId, error) {
  const req = _findRequest(tabId, requestId);
  // `error` is Chrome's net-error string (e.g. 'net::ERR_BLOCKED_BY_CLIENT'
  // for a declarativeNetRequest block, among other causes). Kept so the UI
  // can tell "blocked by an extension" apart from an ordinary network
  // failure — see shared/schema.js isBlockedError().
  if (req) { req.status = 'error'; req.error = error ?? null; }
  if (_sessions.has(tabId)) _scheduleFlush(tabId);
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
// observa:getSessions even though its in-memory session data is intact.
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
