// Observa — shared/session-signals.js
//
// Turns a captured session (requests + readable cookies) into the inputs
// computeVerdict() expects.
//
// ── Why this is shared ─────────────────────────────────────────────────────
// The popup and the Overview must not disagree about the same page. They were
// separately computing their own counts, which is how "Policy concerns 2"
// ended up above "No notable findings" in v0.22.0 — two correct numbers, one
// screen, no shared source. The popup now shows a verdict too, so the same
// trap is open again unless both read from one function.
//
// ── What this will and will not assert ─────────────────────────────────────
//   1. Only what reaches a DIFFERENT company counts. A site sending its own
//      session id to itself is how staying logged in works; a form posting
//      your email back to the same site is the form working. Those are
//      reported separately and never escalate a verdict.
//   2. Tracker categories that describe delivery rather than profiling
//      (Content/CDN, Anti-fraud, Consent) are not tracking — see
//      TRACKING_CATEGORIES in shared/verdict.js.
//   3. A pattern match is not proof the value is real, accurate or the
//      visitor's — the same limit classify/exposure.js documents.
//
// Pure function over plain data — no chrome.* APIs, no DOM.

import { detectExposures } from '../classify/exposure.js';
import { TRACKING_CATEGORIES, mostSignificantCategory } from './verdict.js';

const PERSONAL_TYPES = new Set(['email', 'phone', 'geo', 'zip']);

const TYPE_LABEL = {
  email: 'email address', phone: 'phone number', geo: 'approximate location',
  zip: 'ZIP/postal code', id: 'tracking identifier',
  campaign: 'campaign parameter', page: 'page path',
};

/**
 * Which companies reached this page under more than one domain.
 *
 * A page contacting doubleclick.net, google-analytics.com and gstatic.com looks
 * like three strangers in a domain list and is one company. The reverse
 * confusion is just as bad: a user seeing "3 other companies" for what is
 * really one company's own infrastructure reads more sharing than happened.
 * The grouping already exists on the Third Parties screen; this makes it
 * available to the Overview, where the count is actually read.
 *
 * Only third parties count — a site's own subdomains are not "another company".
 * Counts DISTINCT registrable domains, not requests: eight calls to one domain
 * is one domain, and saying otherwise would inflate the number.
 *
 * @param {Array<{party?:string, organization?:string|null, etld1?:string, domain?:string}>} domains
 * @returns {Array<{organization:string, domains:string[]}>} sorted, largest first
 */
export function orgConcentration(domains = []) {
  const byOrg = new Map();
  for (const d of domains) {
    if (d?.party !== 'third-party') continue;
    const org = d.organization;
    if (!org) continue; // unknown ownership is not a claim we can make
    const key = d.etld1 || d.domain;
    if (!key) continue;
    if (!byOrg.has(org)) byOrg.set(org, new Set());
    byOrg.get(org).add(key);
  }
  return [...byOrg.entries()]
    .filter(([, set]) => set.size >= 2)
    .map(([organization, set]) => ({ organization, domains: [...set].sort() }))
    .sort((a, b) => b.domains.length - a.domains.length || a.organization.localeCompare(b.organization));
}

/**
 * @param {{requests?:Array<object>, cookies?:Array<object>}} session
 * @returns {{thirdPartyCount:number, domainCount:number, byCategory:Record<string,number>,
 *            trackingDomainCount:number, personalDataTypes:string[], trackingIdCount:number,
 *            personalDataTypesFirstParty:string[], trackingIdCountFirstParty:number,
 *            requestCount:number}}
 */
export function summarizeSessionSignals(session = {}) {
  const requests = session.requests ?? [];
  const cookies = session.cookies ?? [];

  // Group by OWNING COMPANY, exactly as the dashboard's buildDomainMap does.
  //
  // This used to group by eTLD+1, so youtube.com's five Google-owned domains
  // (gstatic, ytimg, ggpht, googleapis, google.com) counted as five separate
  // parties. The popup then announced "this page contacted 6 other companies"
  // while the dashboard correctly said 1 — two screens describing the same
  // page differently, and the popup's word was the wrong one: those are
  // domains, not companies.
  const byKey = new Map();
  const distinctDomains = new Set();
  for (const r of requests) {
    const etld1 = r.etld1 || r.domain;
    if (!etld1) continue;
    distinctDomains.add(etld1);
    // Keyed by PARTY as well as owner. youtube.com is Google-owned, and so are
    // gstatic/ytimg/ggpht — grouping on the organisation alone folded the site
    // the user is actually on into a "third party" company. The site you are
    // visiting is never another company, whoever owns it.
    const party = r.party === 'third-party' ? 'third' : 'first';
    const key = r.organization ? `${party}:org:${r.organization}` : `${party}:dom:${etld1}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        party: r.party, organization: r.organization ?? null,
        categories: new Set(), category: null, etld1s: new Set(), requests: [],
      });
    }
    const entry = byKey.get(key);
    entry.etld1s.add(etld1);
    if (r.category) entry.categories.add(r.category);
    entry.requests.push(r);
  }
  for (const entry of byKey.values()) {
    entry.category = mostSignificantCategory([...entry.categories]);
  }

  const domains = [...byKey.values()];
  const byCategory = {};
  for (const d of domains) if (d.category) byCategory[d.category] = (byCategory[d.category] ?? 0) + 1;

  const personal = new Set();
  const personalFirstParty = new Set();
  let trackingIdCount = 0;
  let trackingIdCountFirstParty = 0;

  const note = (type, isThirdParty) => {
    const label = TYPE_LABEL[type] ?? type;
    if (PERSONAL_TYPES.has(type)) (isThirdParty ? personal : personalFirstParty).add(label);
    else if (type === 'id') { if (isThirdParty) trackingIdCount++; else trackingIdCountFirstParty++; }
  };

  for (const d of domains) {
    const isThirdParty = d.party === 'third-party';
    for (const r of d.requests) {
      // Use the exposures captured AT REQUEST TIME. They are the only record of
      // anything matched in a POST body: `requestBody` is deliberately never
      // stored (see shared/schema.js), so re-deriving from the URL alone
      // silently loses every body match. That is what made the popup report
      // "Looks reasonable" on a page where the dashboard had found a tracking
      // identifier. detectExposures is kept only as a fallback for a record
      // that predates exposure capture.
      const found = r.exposures ?? detectExposures(r.url, r.requestBody) ?? [];
      for (const e of found) note(e.type, isThirdParty);
    }
  }
  // Cookie values carry exposures too. A cookie readable for this site is
  // first-party by definition of how it was fetched, so it never escalates —
  // but it is still reported.
  for (const c of cookies) {
    for (const e of c.exposures ?? []) note(e.type, false);
  }

  const thirdPartyGroups = domains.filter(d => d.party === 'third-party');

  return {
    requestCount: requests.length,
    // Companies, not domains. Both are reported so a surface can say
    // "5 domains belonging to 1 company" without recomputing either.
    domainCount: distinctDomains.size,
    companyCount: domains.length,
    thirdPartyCount: thirdPartyGroups.length,
    thirdPartyDomainCount: new Set(
      thirdPartyGroups.flatMap(d => [...d.etld1s])
    ).size,
    byCategory,
    trackingDomainCount: domains.filter(d => TRACKING_CATEGORIES.has(d.category)).length,
    personalDataTypes: [...personal],
    trackingIdCount,
    personalDataTypesFirstParty: [...personalFirstParty],
    trackingIdCountFirstParty,
  };
}
