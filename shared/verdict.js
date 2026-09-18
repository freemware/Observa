// Observa — shared/verdict.js
//
// Produces the one-line worded verdict shown at the top of the Overview.
//
// ── Why this exists, and the rule it bends ─────────────────────────────────
// CONTEXT.md's Summarization Rule forbids "a 0-100 rating, letter grade, 'risk
// level' as a composite page-level score, or any composite number implying
// measured severity." A requested redesign put a 68/100 Trust Score dial at the
// top of the Overview. That number was declined and this was chosen instead: a
// **worded band with no number**, which keeps the at-a-glance answer users
// expect without inventing precision that the underlying evidence cannot
// support. There is no arithmetic here — no weights, no points, no average —
// only named conditions, so there is nothing to mistake for a measurement.
//
// The other half of the bargain: a verdict must never be a black box. Every
// band comes back with the specific `reasons` that produced it, each naming the
// real observation behind it, and the UI is expected to show them directly
// under the verdict rather than hiding them behind a tooltip. If the reasons
// list is empty the band is 'reasonable' by definition — we never assert a
// concern we cannot immediately justify.
//
// Confidence is reported separately and is about *coverage*, not severity: it
// says how much of the picture Observa actually got (did we see traffic, did we
// find and read a policy), never how sure we are that a site is bad.
//
// Pure function over plain data — no chrome.* APIs, no DOM — so it is directly
// unit-testable.

// Observed tracker categories that speak to intent strongly enough to name
// on their own. Vocabulary comes from classify/tracker-list.js (Disconnect).
const SEVERE_CATEGORIES = ['Fingerprinting', 'Cryptomining'];
const PROFILING_CATEGORIES = ['Advertising', 'Social'];

// Which Disconnect categories actually describe tracking.
//
// Content (CDNs, fonts, embedded media), Anti-fraud and Consent are on the
// list because they are *identifiable third parties*, not because they profile
// you. Counting them as trackers is how a page that loaded Google Fonts and
// its own Supabase backend was reported as having "shared your activity with
// 2 other companies" — neither of which shares your activity with anyone.
export const TRACKING_CATEGORIES = new Set([
  'Advertising', 'Analytics', 'Social', 'Fingerprinting', 'Cryptomining',
]);

// When one company reaches a page under several domains with different
// categories, the group must be described by its most consequential one.
//
// buildDomainMap() groups by owning organisation, and took whichever category
// happened to arrive FIRST. Google serves both doubleclick.net (Advertising)
// and gstatic.com (Content); if the CDN request landed first, the whole Google
// group was labelled Content — and since Content is excluded from the tracker
// count, an active ad network disappeared from "Trackers matched" depending on
// network timing. Ordering is not a fact about the site.
const CATEGORY_SIGNIFICANCE = [
  'Cryptomining', 'Fingerprinting', 'Advertising', 'Social', 'Analytics',
  'Anti-fraud', 'Consent', 'Content',
];

/**
 * @param {Array<string|null|undefined>} categories
 * @returns {string|null} the most consequential category present, or null
 */
export function mostSignificantCategory(categories = []) {
  const present = new Set(categories.filter(Boolean));
  for (const c of CATEGORY_SIGNIFICANCE) if (present.has(c)) return c;
  // A category we don't rank is still a category — return it rather than
  // silently dropping a classification we did make.
  return present.size ? [...present][0] : null;
}

const BANDS = {
  reasonable: { band: 'reasonable', label: 'Looks reasonable', icon: 'check-circle' },
  // Was "Use with caution" — which tells the reader how to feel about a page
  // rather than what was on it, and landed on ordinary sites. The band names
  // the finding; the reasons underneath say exactly what it was. Same
  // reasoning that rejected the numeric score.
  caution:    { band: 'caution',    label: 'Tracking present',  icon: 'alert-triangle' },
  concern:    { band: 'concern',    label: 'High concern',      icon: 'alert-triangle' },
};

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * @param {{
 *   thirdPartyCount?: number,
 *   byCategory?: Record<string, number>,
 *   personalDataTypes?: string[],   // exposure labels observed leaving the page
 *   trackingIdCount?: number,       // tracking-ID params observed
 *   policyTensions?: number,        // comparisons with status 'tension'
 *   policyConcerns?: number,        // policy findings with tone 'concern'
 *   policyDocsRead?: number,
 *   requestCount?: number,
 * }} input
 * @returns {{band:string,label:string,icon:string,headline:string,
 *            reasons:Array<{key:string,text:string,severity:'high'|'medium'}>,
 *            confidence:'high'|'medium'|'low', confidenceWhy:string}}
 */
export function computeVerdict(input = {}) {
  const thirdPartyCount = input.thirdPartyCount ?? 0;
  const byCategory = input.byCategory ?? {};
  const personalDataTypes = input.personalDataTypes ?? [];
  const trackingIdCount = input.trackingIdCount ?? 0;
  const policyTensions = input.policyTensions ?? 0;
  const policyDocsRead = input.policyDocsRead ?? 0;
  const requestCount = input.requestCount ?? 0;

  const reasons = [];

  // ── High-severity conditions ─────────────────────────────────────────────
  if (personalDataTypes.length) {
    reasons.push({
      key: 'personalData',
      severity: 'high',
      text: `Requests from this page carried what looks like personal information: ${personalDataTypes.slice(0, 3).join(', ')}.`,
    });
  }
  for (const cat of SEVERE_CATEGORIES) {
    if (byCategory[cat]) {
      reasons.push({
        key: `category:${cat}`,
        severity: 'high',
        text: `${plural(byCategory[cat], 'domain', 'domains')} matched as ${cat.toLowerCase()}.`,
      });
    }
  }
  if (policyTensions) {
    reasons.push({
      key: 'policyTension',
      severity: 'high',
      text: `${plural(policyTensions, 'claim', 'claims')} in this site's own policy didn't line up with what loaded.`,
    });
  }

  // ── Medium-severity conditions ───────────────────────────────────────────
  const profilingCount = PROFILING_CATEGORIES.reduce((n, c) => n + (byCategory[c] ?? 0), 0);
  if (profilingCount) {
    reasons.push({
      key: 'profiling',
      severity: 'medium',
      text: `${plural(profilingCount, 'domain', 'domains')} matched as advertising or social trackers.`,
    });
  }
  if (trackingIdCount) {
    reasons.push({
      key: 'trackingId',
      severity: 'medium',
      text: `${plural(trackingIdCount, 'tracking identifier was', 'tracking identifiers were')} seen in outgoing requests.`,
    });
  }
  if (byCategory.Analytics) {
    reasons.push({
      key: 'analytics',
      severity: 'medium',
      text: `${plural(byCategory.Analytics, 'analytics domain', 'analytics domains')} recorded activity on this page.`,
    });
  }

  const hasHigh = reasons.some(r => r.severity === 'high');
  const hasMedium = reasons.some(r => r.severity === 'medium');
  const chosen = hasHigh ? BANDS.concern : hasMedium ? BANDS.caution : BANDS.reasonable;

  // ── Headline ─────────────────────────────────────────────────────────────
  // Deliberately a different sentence from reasons[0]: the headline says what
  // kind of thing was found, the reasons below say exactly what. Repeating the
  // first reason verbatim just reads as a rendering bug.
  let headline;
  if (chosen.band === 'reasonable') {
    headline = thirdPartyCount === 0
      ? 'Nothing on this page reached outside the site itself.'
      : `This page contacted ${plural(thirdPartyCount, 'other company', 'other companies')}, none of which matched a known tracker.`;
  } else if (reasons.some(r => r.key === 'personalData')) {
    headline = 'Something that looks like your personal information left this page.';
  } else if (reasons.some(r => r.key.startsWith('category:'))) {
    headline = 'This page loaded techniques that can identify your device across sites.';
  } else if (reasons.some(r => r.key === 'policyTension')) {
    headline = 'What this site says in its policy and what it actually did don’t line up.';
  } else {
    // Describe the reason that actually triggered the band. The old text —
    // "This page shared your activity with N other companies" — used the raw
    // third-party count, which includes CDNs, fonts and the site's own backend.
    // On a page whose only third parties were Google Fonts and Supabase it
    // asserted sharing that never happened.
    const trackingThirdParties = [...TRACKING_CATEGORIES]
      .reduce((n, c) => n + (byCategory[c] ?? 0), 0);
    if (profilingCount) {
      headline = `${plural(profilingCount, 'company is', 'companies are')} building an advertising or social profile from this visit.`;
    } else if (byCategory.Analytics) {
      headline = `${plural(byCategory.Analytics, 'analytics company', 'analytics companies')} recorded what you did on this page.`;
    } else if (trackingIdCount) {
      headline = `An identifier that can link your visits was sent to ${plural(trackingThirdParties || thirdPartyCount, 'other company', 'other companies')}.`;
    } else {
      headline = `This page contacted ${plural(thirdPartyCount, 'other company', 'other companies')}.`;
    }
  }

  // ── Confidence is about coverage, not severity ───────────────────────────
  let confidence, confidenceWhy;
  if (requestCount > 0 && policyDocsRead > 0) {
    confidence = 'high';
    confidenceWhy = `Based on ${plural(requestCount, 'request', 'requests')} observed and ${plural(policyDocsRead, 'policy document', 'policy documents')} read.`;
  } else if (requestCount > 0) {
    confidence = 'medium';
    confidenceWhy = `Based on ${plural(requestCount, 'request', 'requests')} observed. No policy document has been analyzed for this page yet.`;
  } else if (policyDocsRead > 0) {
    confidence = 'medium';
    confidenceWhy = `Based on ${plural(policyDocsRead, 'policy document', 'policy documents')} read. No network activity was captured for this page.`;
  } else {
    confidence = 'low';
    confidenceWhy = 'Little was captured for this page yet — reload it with Observa active.';
  }

  return { ...chosen, headline, reasons, confidence, confidenceWhy };
}
