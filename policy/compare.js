// Observa Policy Intelligence — policy/compare.js
//
// Compares what a site's own policy *declares* against what Observa actually
// *observed* the page do in this session. This is the one thing a generic
// "summarize this policy" tool structurally cannot do: Observa already
// watched the network while the page loaded, so it can put the sentence and
// the behavior side by side.
//
// ── The epistemics here matter more than the code ──────────────────────────
// Getting this wrong would mean Observa accusing sites of lying based on
// evidence that doesn't support it, which is exactly what CLAUDE.md Rule 3
// ("never claim visibility Observa does not have") exists to prevent. So:
//
//   1. A comparison is never a verdict. Each one stands alone with its own
//      status and its own caveat — nothing is rolled up into a page-level
//      "trustworthy / untrustworthy" score. That is the Summarization Rule
//      (see CONTEXT.md), and this feature deliberately does not need an
//      exception to it.
//   2. "Tension" means the declared text and the observed behavior are hard
//      to reconcile *on their face* — it explicitly does not mean the company
//      is lying or breaking the law. Almost every tension here has a lawful
//      explanation, and the caveat on each one says what it is.
//   3. A data *sale* is never inferred from observed traffic. Seeing an
//      ad-tech domain load is not evidence that data was sold, and Observa
//      cannot see what a request's payload was used for downstream or what
//      contracts govern it. "We do not sell your data" plus observed ad-tech
//      is therefore reported as context, never as tension.
//   4. Observa sees that a request was made, not what was in it or what was
//      done with it. Every observed claim here is at that level.
//   5. Categories Observa has no way to check at all (arbitration, retention,
//      AI training, and most of the taxonomy) are reported as explicitly not
//      comparable rather than silently omitted, so the absence of a
//      comparison is never mistaken for a clean bill of health.
//
// Both exports are pure functions over plain data so they can be unit-tested
// without a browser or any chrome.* API.

// The observed-side category vocabulary comes from classify/tracker-list.js
// (Disconnect's categories, capitalized): Advertising, Analytics, Social,
// Fingerprinting, Cryptomining, Content, Anti-fraud, Consent.
import { TRACKING_CATEGORIES, mostSignificantCategory } from '../shared/verdict.js';

const CAT_ADVERTISING = 'Advertising';
const CAT_ANALYTICS = 'Analytics';

// Clause categories where an observation can say something real. Everything
// else in the taxonomy is declared-only — see notComparable below.
const CHECKABLE = new Set(['thirdPartySharing', 'advertising', 'dataSale', 'browsingActivity']);

const MAX_LISTED_DOMAINS = 8;

/**
 * Reduces a captured session (plus, optionally, the cookies read for it) to
 * the small summary the comparison rules need. Pure — takes the session
 * object, returns a plain object.
 * @param {{pageUrl?:string, requests?:Array<object>}|null} session
 * @param {Array<object>} [cookies] - CookieMeta objects from background/cookies.js
 */
export function summarizeObserved(session, cookies = []) {
  const byDomain = new Map();
  for (const req of session?.requests ?? []) {
    if (req?.party !== 'third-party') continue;
    const key = req.etld1 || req.domain;
    if (!key) continue;
    if (!byDomain.has(key)) {
      byDomain.set(key, {
        etld1: key,
        organization: req.organization ?? null,
        categories: new Set(),
        category: null,
        requestCount: 0,
      });
    }
    const entry = byDomain.get(key);
    entry.requestCount++;
    // A domain's first request may be unclassified while a later one carries
    // the organization/category. Collect them all and pick the most
    // consequential afterwards — taking whichever landed first made the label
    // depend on network ordering rather than on the site.
    if (req.category) entry.categories.add(req.category);
    if (!entry.organization && req.organization) entry.organization = req.organization;
  }

  for (const entry of byDomain.values()) {
    entry.category = mostSignificantCategory([...entry.categories]);
  }

  const thirdPartyDomains = [...byDomain.values()].sort((a, b) => b.requestCount - a.requestCount);
  const byCategory = {};
  for (const d of thirdPartyDomains) {
    if (d.category) byCategory[d.category] = (byCategory[d.category] ?? 0) + 1;
  }

  let hostname = null;
  try { hostname = session?.pageUrl ? new URL(session.pageUrl).hostname : null; } catch { hostname = null; }

  return {
    hostname,
    thirdPartyDomains,
    thirdPartyCount: thirdPartyDomains.length,
    // "Tracker" must mean tracker. Content (CDNs, fonts), Anti-fraud and
    // Consent are classified third parties, not profiling ones — counting them
    // made a page that loaded Google Fonts report one more tracking service
    // than it had, and disagreed with the Overview's own tile.
    trackerCount: thirdPartyDomains.filter(d => TRACKING_CATEGORIES.has(d.category)).length,
    byCategory,
    cookieCount: Array.isArray(cookies) ? cookies.length : 0,
  };
}

function domainsInCategory(observed, category) {
  return observed.thirdPartyDomains.filter(d => d.category === category);
}

function listDomains(domains) {
  return domains.slice(0, MAX_LISTED_DOMAINS).map(d => ({
    etld1: d.etld1,
    organization: d.organization,
    category: d.category,
    requestCount: d.requestCount,
  }));
}

function declaredFrom(finding) {
  return {
    summary: finding.summary,
    tone: finding.tone,
    sourceDocument: finding.sourceDocument,
    section: finding.section ?? null,
    evidence: finding.evidence,
    evidenceFull: finding.evidenceFull ?? null,
    evidenceOffset: finding.evidenceOffset ?? null,
    matchText: finding.matchText ?? null,
    confidence: finding.confidence,
  };
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * @param {Array<object>} findings - from policy/extract.js
 * @param {ReturnType<typeof summarizeObserved>} observed
 * @returns {{comparisons:Array<object>, notComparable:Array<{category:string,title:string}>}}
 */
export function comparePolicyToObserved(findings, observed) {
  const comparisons = [];
  const notComparable = [];
  const seenNotComparable = new Set();

  for (const f of findings ?? []) {
    if (!CHECKABLE.has(f.category)) {
      if (!seenNotComparable.has(f.category)) {
        seenNotComparable.add(f.category);
        notComparable.push({ category: f.category, title: f.title });
      }
      continue;
    }

    const declared = declaredFrom(f);
    const base = { category: f.category, declared, provenance: 'Declared vs Observed' };

    // ── Third-party sharing ────────────────────────────────────────────────
    if (f.category === 'thirdPartySharing') {
      const tp = observed.thirdPartyDomains;
      if (f.tone === 'good' && tp.length > 0) {
        comparisons.push({
          ...base,
          id: 'thirdPartySharing:tension',
          status: 'tension',
          title: 'Policy says it does not share with third parties — but this page contacted third parties',
          observedText: `While this page loaded, your browser sent requests to ${plural(tp.length, 'third-party domain', 'third-party domains')}${observed.trackerCount ? `, ${observed.trackerCount} of which match known tracking services` : ''}.`,
          observedDomains: listDomains(tp),
          caveat: 'This is not proof the policy is false. Most policies treat vendors acting on the company’s behalf ("service providers" or "processors") as separate from "sharing," and many of these domains are likely that. Observa can also only see that a request was made — not what it contained or what the receiving company did with it.',
        });
      } else if (f.tone === 'good' && tp.length === 0) {
        comparisons.push({
          ...base,
          id: 'thirdPartySharing:consistent',
          status: 'consistent',
          title: 'Policy says it does not share with third parties — and no third-party requests were seen',
          observedText: 'This page made no third-party requests during this session.',
          observedDomains: [],
          caveat: 'This covers only the page you visited, in this one session. Other pages, later sessions, or server-side sharing that happens after a request arrives are all invisible to Observa.',
        });
      } else if (f.tone !== 'good' && tp.length > 0) {
        comparisons.push({
          ...base,
          id: 'thirdPartySharing:consistent',
          status: 'consistent',
          title: 'Policy discloses third-party sharing, and third-party requests were observed',
          observedText: `The policy says information may be shared with third parties, and this page did contact ${plural(tp.length, 'third-party domain', 'third-party domains')}.`,
          observedDomains: listDomains(tp),
          caveat: 'Consistency here means the disclosure matches the observable behavior — it is not a judgment about whether the sharing itself is reasonable.',
        });
      }
      continue;
    }

    // ── Targeted advertising ───────────────────────────────────────────────
    if (f.category === 'advertising') {
      const adDomains = domainsInCategory(observed, CAT_ADVERTISING);
      if (f.tone === 'good' && adDomains.length > 0) {
        comparisons.push({
          ...base,
          id: 'advertising:tension',
          status: 'tension',
          title: 'Policy says it does not use targeted advertising — but advertising trackers loaded',
          observedText: `This page contacted ${plural(adDomains.length, 'domain', 'domains')} classified as advertising services.`,
          observedDomains: listDomains(adDomains),
          caveat: 'An advertising domain loading is not the same as your data being used to target ads at you — it may be serving non-personalized ads, or measuring delivery. The classification also comes from a public tracker list, which can be out of date or wrong for a given domain.',
        });
      } else if (f.tone !== 'good' && adDomains.length > 0) {
        comparisons.push({
          ...base,
          id: 'advertising:consistent',
          status: 'consistent',
          title: 'Policy discloses advertising use, and advertising trackers were observed',
          observedText: `The policy discloses advertising use, and this page contacted ${plural(adDomains.length, 'advertising domain', 'advertising domains')}.`,
          observedDomains: listDomains(adDomains),
          caveat: 'The disclosure matches what loaded. Whether the amount of ad tracking is acceptable is your call, not Observa’s.',
        });
      } else if (f.tone === 'good' && adDomains.length === 0) {
        comparisons.push({
          ...base,
          id: 'advertising:consistent',
          status: 'consistent',
          title: 'Policy says it does not use targeted advertising — and no advertising trackers loaded',
          observedText: 'No domains classified as advertising services were contacted during this session.',
          observedDomains: [],
          caveat: 'Only this page, in this session. An advertising domain that is not on the bundled tracker list would also not be counted here.',
        });
      }
      continue;
    }

    // ── Sale of data — deliberately never reported as tension ──────────────
    if (f.category === 'dataSale') {
      const adDomains = domainsInCategory(observed, CAT_ADVERTISING);
      if (f.tone === 'good' && adDomains.length > 0) {
        comparisons.push({
          ...base,
          id: 'dataSale:context',
          status: 'context',
          title: 'Policy says it does not sell your data — worth knowing what did load',
          observedText: `This page contacted ${plural(adDomains.length, 'advertising domain', 'advertising domains')}. That is context for the "we do not sell" statement, not a contradiction of it.`,
          observedDomains: listDomains(adDomains),
          caveat: 'Observa cannot observe a sale, and nothing here suggests one occurred. This is shown because several US state privacy laws regulate "sharing for cross-context behavioral advertising" alongside "sale," so a policy can truthfully say it does not sell while still sharing data for advertising. Read the policy’s own definition of "sell" to see which it means.',
        });
      }
      continue;
    }

    // ── Browsing / activity data ───────────────────────────────────────────
    if (f.category === 'browsingActivity') {
      const analyticsDomains = domainsInCategory(observed, CAT_ANALYTICS);
      if (analyticsDomains.length > 0) {
        comparisons.push({
          ...base,
          id: 'browsingActivity:consistent',
          status: 'consistent',
          title: 'Policy describes activity tracking, and analytics services were observed',
          observedText: `This page contacted ${plural(analyticsDomains.length, 'domain', 'domains')} classified as analytics services.`,
          observedDomains: listDomains(analyticsDomains),
          caveat: 'Analytics is common and often necessary for a site to function. This confirms the disclosure matches observable behavior, nothing more.',
        });
      }
      continue;
    }
  }

  return { comparisons, notComparable };
}
