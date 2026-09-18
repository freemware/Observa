// Observa Policy Intelligence — background/policy-intel.js
//
// Orchestrates the new feature: discover a site's own Privacy Policy, Terms
// of Use, and Cookie Policy links, fetch each document, extract structured
// findings (policy/extract.js), and cache the result per tab so re-opening
// the dashboard doesn't re-fetch/re-analyze every time.
//
// ── Network egress, stated plainly (CLAUDE.md Rule 2/4) ─────────────────────
// This module introduces a new kind of outbound request Observa makes: it
// fetches (a) the current tab's own page HTML, to scan for policy links —
// content the user's browser already loaded, not a new destination — and
// (b) the small number of policy documents that page links to (at most 3
// auto-discovered, plus whatever the user explicitly pastes a URL for).
// This is a deliberate, scoped extension of the same principle the v0.11.0
// list-refresh feature already established as Observa's first outbound
// request: unlike list-refresh's two fixed URLs, these URLs vary by site,
// so the scope discipline here is different — capped to a handful of
// same-site (or explicitly known hosted-policy) documents, fetched with
// credentials:'omit' (no cookies sent), never fetched proactively in the
// background on every page load, only when Policy Intelligence is actually
// opened for a session (a proximate user action, same discipline M6's
// blocking and list-refresh's manual refresh already follow) or when the
// user explicitly pastes a URL/text. No browsing data, identifiers, or
// cookies are sent — only a plain GET for a public document.
//
// ── Data retention ───────────────────────────────────────────────────────
// Results are cached in chrome.storage.session, scoped per tab, exactly like
// the rest of a tab's session data (background/session.js) — cleared
// automatically on browser restart, and cleared early whenever that tab
// navigates to a new page or closes (see clearPolicyIntelForTab, called from
// service-worker.js). This is intentionally the same tier as per-tab
// request/cookie data, not a new durable store — no new retention category
// needed in CONTEXT.md beyond noting the new module.
//
// This is informational analysis, not legal advice — every result carries
// that disclaimer, and the UI must not obscure it.

import { discoverPolicyLinks, rootCandidatesFor } from '../policy/discovery.js';
import { htmlToBlocks, plainTextToBlocks } from '../policy/textify.js';
import { extractFindings } from '../policy/extract.js';
import { CLAUSE_TAXONOMY } from '../policy/taxonomy.js';
import { summarizeObserved, comparePolicyToObserved } from '../policy/compare.js';
import { getSessionForTab } from './session.js';
import { getCookiesForUrl } from './cookies.js';

const KEY = (tabId) => `observa:policyIntel:tab-${tabId}`;
const FETCH_TIMEOUT_MS = 12000;
const MAX_AUTO_DOCS = 3; // privacy + terms + cookie — matches the spec's scope exactly, never more

const DOC_LABEL = { privacy: 'Privacy Policy', terms: 'Terms of Use', cookie: 'Cookie Policy' };

const DISCLAIMER = 'Observa provides informational analysis of this document’s own language. This is not legal advice, and Observa does not determine legal compliance.';

async function fetchText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      credentials: 'omit', // never send this site's cookies just to read a public policy page
      redirect: 'follow',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

function emptyResult(tabId, pageUrl) {
  return {
    tabId, pageUrl,
    status: 'idle',
    documents: [],
    findings: [],
    notFound: [],
    comparisons: [],
    notComparable: [],
    observed: null,
    error: null,
    disclaimer: DISCLAIMER,
    updatedAt: Date.now(),
  };
}

// ── The "silence" problem ──────────────────────────────────────────────────
// A category with no pattern match produces no finding, which leaves the user
// unable to tell "this policy has no arbitration clause" from "our patterns
// didn't recognize how this company worded theirs." Those are very different
// facts and rendering both as nothing quietly overstates our coverage. So the
// unmatched categories are returned explicitly, and the UI labels them as a
// limit of Observa's own pattern set — never as a statement about the policy.
// Only meaningful once at least one document has actually been read.
function unmatchedCategories(findings) {
  const covered = new Set(findings.map(f => f.category));
  return CLAUSE_TAXONOMY
    .filter(c => !covered.has(c.id))
    .map(c => ({ category: c.id, title: c.title }));
}

// Builds the observed-behavior side of the policy-vs-behavior comparison from
// data Observa already captured for this tab — no new observation, no new
// permission, nothing re-fetched. Defensive throughout: this runs inside the
// analyze path, and a failure to read session or cookie state should degrade
// the comparison to "not available" rather than fail the whole analysis.
async function gatherObserved(tabId, pageUrl) {
  let session = null;
  try { session = await getSessionForTab(tabId); } catch { session = null; }
  if (!session) return null;

  let cookies = [];
  try {
    if (pageUrl && /^https?:\/\//i.test(pageUrl)) cookies = await getCookiesForUrl(pageUrl) ?? [];
  } catch { cookies = []; }

  try { return summarizeObserved(session, cookies); } catch { return null; }
}

// Shared tail for both the auto and manual analysis paths: attach the
// unmatched-category list and, when session data is available, the
// declared-vs-observed comparison.
async function withAnalysis(tabId, pageUrl, result) {
  const findings = result.findings ?? [];
  const notFound = result.documents.some(d => d.ok !== false) ? unmatchedCategories(findings) : [];
  const observed = await gatherObserved(tabId, pageUrl);
  let comparisons = [], notComparable = [];
  if (observed) {
    try {
      ({ comparisons, notComparable } = comparePolicyToObserved(findings, observed));
    } catch { comparisons = []; notComparable = []; }
  }
  return { ...result, notFound, observed, comparisons, notComparable };
}

export async function getPolicyIntelForTab(tabId) {
  const stored = await chrome.storage.session.get(KEY(tabId));
  return stored[KEY(tabId)] ?? null;
}

async function save(tabId, result) {
  await chrome.storage.session.set({ [KEY(tabId)]: result });
  return result;
}

export async function clearPolicyIntelForTab(tabId) {
  await chrome.storage.session.remove(KEY(tabId));
}

/**
 * Auto-discovery + analysis for the page currently loaded in `tabId`.
 * Triggered by the dashboard when the user opens Policy Intelligence for a
 * session — not run automatically on every page load. Never throws; a
 * partial or total failure is reflected in the returned object's `status`/
 * `error` fields so the UI can show an honest "couldn't find/fetch this"
 * state instead of silently showing nothing.
 * @param {number} tabId
 * @param {string} pageUrl
 * @param {{force?:boolean}} [opts]
 */
export async function analyzePolicyForTab(tabId, pageUrl, opts = {}) {
  if (!opts.force) {
    const existing = await getPolicyIntelForTab(tabId);
    if (existing && existing.pageUrl === pageUrl && existing.status === 'done') return existing;
  }
  if (!pageUrl || !/^https?:\/\//i.test(pageUrl)) {
    return save(tabId, { ...emptyResult(tabId, pageUrl), status: 'error', error: 'No page to analyze.' });
  }

  let result = { ...emptyResult(tabId, pageUrl), status: 'discovering' };
  await save(tabId, result);

  let pageHtml;
  try {
    pageHtml = await fetchText(pageUrl);
  } catch (err) {
    // Discovery failed, but the user can still paste a URL/text manually —
    // this is not a fatal error for the feature as a whole.
    return save(tabId, {
      ...result, status: 'error',
      error: `Couldn't re-fetch this page to look for policy links (${String(err?.message ?? err)}). You can still paste a URL or text below.`,
    });
  }

  let links = discoverPolicyLinks(pageHtml, pageUrl).slice(0, MAX_AUTO_DOCS);

  // Nothing on this page. Before giving up, try the site's own root — a
  // logged-in app shell (mail.yahoo.com and friends) renders its footer in
  // JavaScript and serves HTML with no legal links at all, while the same
  // site's root page carries them. Bounded to the URLs rootCandidatesFor()
  // returns: same registrable domain, root path, at most two, no recursion.
  let discoveredVia = 'page';
  if (!links.length) {
    for (const rootUrl of rootCandidatesFor(pageUrl)) {
      let rootHtml;
      try { rootHtml = await fetchText(rootUrl); } catch { continue; }
      // Links are resolved against the URL they were found on, not the page
      // the user is sitting on — a relative /legal/privacy on the root means
      // the root's origin.
      const rootLinks = discoverPolicyLinks(rootHtml, rootUrl).slice(0, MAX_AUTO_DOCS);
      if (rootLinks.length) {
        links = rootLinks;
        discoveredVia = 'site-root';
        result = { ...result, rootSearched: rootUrl };
        break;
      }
    }
  }
  result = { ...result, discoveredVia };

  result = { ...result, status: 'analyzing' };
  await save(tabId, result);

  const documents = [];
  const findings = [];

  for (const link of links) {
    const title = DOC_LABEL[link.type] ?? link.type;
    try {
      const html = await fetchText(link.url);
      const blocks = htmlToBlocks(html);
      // Carry the document's own URL onto each finding so the UI can build a
      // deep link straight to the matched clause without having to join
      // findings back to the document list by title.
      const docFindings = extractFindings(blocks, { sourceDocument: title })
        .map(f => ({ ...f, sourceUrl: link.url }));
      documents.push({
        type: link.type, title, url: link.url, discoveredVia: 'auto',
        confidence: link.confidence, charCount: html.length,
        fetchedAt: Date.now(), ok: true,
      });
      findings.push(...docFindings);
    } catch (err) {
      documents.push({
        type: link.type, title, url: link.url, discoveredVia: 'auto',
        confidence: link.confidence, ok: false,
        error: String(err?.message ?? err), fetchedAt: Date.now(),
      });
    }
  }

  result = await withAnalysis(tabId, pageUrl, { ...result, status: 'done', documents, findings, updatedAt: Date.now() });
  return save(tabId, result);
}

/**
 * Manual "Analyze Policy" path — a pasted URL or pasted text, for a document
 * type of the user's choosing (or discovery failed / found nothing for it).
 * Merges into whatever is already cached for this tab rather than replacing
 * it, so pasting a Terms of Use after auto-discovery already found a
 * Privacy Policy adds to the picture instead of discarding it.
 * @param {number} tabId
 * @param {string} pageUrl
 * @param {{docType:string, url?:string, text?:string}} input
 */
export async function analyzeManualDocument(tabId, pageUrl, input) {
  const docType = input?.docType || 'other';
  const title = DOC_LABEL[docType] ?? 'Pasted document';

  let blocks, sourceMeta;
  if (input?.url) {
    let html;
    try {
      html = await fetchText(input.url);
    } catch (err) {
      throw new Error(`Couldn't fetch that URL (${String(err?.message ?? err)}).`);
    }
    blocks = htmlToBlocks(html);
    sourceMeta = { url: input.url, charCount: html.length };
  } else if (input?.text && input.text.trim()) {
    blocks = plainTextToBlocks(input.text);
    sourceMeta = { url: null, charCount: input.text.length };
  } else {
    throw new Error('Paste a URL or the policy text to analyze.');
  }

  // A pasted-text document has no URL to deep-link into; a pasted URL does.
  const docFindings = extractFindings(blocks, { sourceDocument: title })
    .map(f => ({ ...f, sourceUrl: input?.url ?? null }));

  const existing = (await getPolicyIntelForTab(tabId)) ?? emptyResult(tabId, pageUrl);
  const documents = [
    ...existing.documents,
    { type: docType, title, discoveredVia: 'manual', ok: true, fetchedAt: Date.now(), ...sourceMeta },
  ];
  const findings = [...existing.findings, ...docFindings];

  const result = await withAnalysis(tabId, existing.pageUrl || pageUrl, {
    ...existing, pageUrl: existing.pageUrl || pageUrl, status: 'done', documents, findings, updatedAt: Date.now(),
  });
  return save(tabId, result);
}
