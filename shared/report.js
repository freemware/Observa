// Observa — shared/report.js
//
// Assembles everything Observa found for one captured session into a single
// structured report, optionally redacted.
//
// ── One build, three outputs ───────────────────────────────────────────────
// The preview, the HTML download, the printed PDF and anything copied to share
// all render from the object this returns. Nothing re-derives its own numbers.
// That is deliberate: the v0.22.0 bug ("Policy concerns 2" above "No notable
// findings") happened because two surfaces counted the same thing separately,
// and a report that disagrees with the screen it came from would be worse.
//
// ── What this will and will not assert ─────────────────────────────────────
//   1. Only what was actually observed or read. Nothing here is generated to
//      fill a section — an empty section says it is empty and why.
//   2. A report is a snapshot of ONE page visit, not an audit of a site. The
//      `limitations` list says so in the document itself, and is built from
//      the real state of this scan (no policy read, JS-rendered footer, etc.)
//      rather than being boilerplate.
//   3. Redaction removes values, never findings. A redacted report still says
//      an email address was seen leaving the page and where it went; it just
//      does not print the address.
//   4. Cookie VALUES are never available here — background/cookies.js never
//      captures them. The sensitive surface is the pattern matches taken from
//      those values (`exposure.raw`), and request URLs.
//
// Pure functions over plain data — no chrome.* APIs, no DOM.

import { TRACKING_CATEGORIES } from './verdict.js';

export const REDACTED = '[redacted]';

// Query parameters whose values should never survive redaction. Matched
// case-insensitively against the parameter NAME, as a substring, because real
// sites use endless variants (uid, user_id, userId, _uid...).
const SENSITIVE_PARAM_HINTS = [
  'email', 'mail', 'phone', 'tel', 'name', 'addr', 'zip', 'postal',
  'lat', 'lon', 'geo', 'loc',
  'token', 'auth', 'session', 'sid', 'sess', 'jwt', 'bearer', 'key', 'secret',
  'password', 'passwd', 'pwd',
  'uid', 'userid', 'user', 'cid', 'clientid', 'gid', 'fbp', 'fbc', 'idfa', 'adid',
  'id',
];

function isSensitiveParam(name) {
  if (!name) return false;
  const n = String(name).toLowerCase();
  return SENSITIVE_PARAM_HINTS.some(h => n.includes(h));
}

/**
 * A URL safe to print in a report. With redaction on, every query value whose
 * parameter name looks sensitive is replaced; the parameter NAMES are kept,
 * because "this request carried a parameter called email" is the finding and
 * removing it would hide the point of the report.
 */
export function safeUrl(url, redact) {
  if (!url) return '';
  if (!redact) return url;
  let u;
  try { u = new URL(url); } catch { return String(url).split('?')[0]; }
  const params = [...u.searchParams.keys()];
  for (const k of params) {
    if (isSensitiveParam(k)) u.searchParams.set(k, REDACTED);
  }
  // A fragment can carry tokens too and is never load-bearing for a report.
  u.hash = '';
  return u.toString();
}

function safeValue(value, redact) {
  if (redact) return REDACTED;
  return value ?? null;
}

// Chrome's webRequest timeStamp is epoch milliseconds, so real captures are
// fine. A missing or bogus value would render as "1 Jan 1970", which states a
// scan date that is certainly wrong — say we don't know instead of inventing.
const PLAUSIBLE_AFTER = Date.UTC(2000, 0, 1);

function fmtDate(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms < PLAUSIBLE_AFTER) return null;
  try { return new Date(ms).toISOString(); } catch { return null; }
}

/**
 * The honest limits of THIS scan, derived from its actual state.
 * Never boilerplate: each line is here because something specific about this
 * capture makes it true.
 */
export function buildLimitations(input = {}) {
  const {
    requestCount = 0, policyStatus = null, policyDocsRead = 0,
    policyDocumentsFound = 0, cookieCount = 0, exposureCount = 0,
    pageCount = 1,
  } = input;

  const out = [];

  out.push(
    'This report covers a single page visit, not a whole site. Other pages, ' +
    'other sessions and anything that happened before Observa was running are ' +
    'not included.'
  );
  out.push(
    'Observa sees network requests, cookies readable for this site, and the ' +
    'text of policy documents it could fetch. It cannot see clicks, typing, ' +
    'page content, or what a company does with data after it is received.'
  );

  if (exposureCount > 0) {
    out.push(
      'A pattern match means something shaped like a given data type was ' +
      'present in a request — not proof the value is real, accurate, or yours.'
    );
  }
  if (requestCount === 0) {
    out.push('No network requests were captured for this page, so there is nothing to report about its behaviour.');
  }
  if (cookieCount === 0) {
    out.push('No cookies were readable for this site at scan time. Cookies set later, or restricted to other paths, would not appear.');
  }

  if (policyDocsRead > 0) {
    out.push(
      `Policy findings come from pattern matching over ${policyDocsRead} ` +
      `document${policyDocsRead === 1 ? '' : 's'}. A clause worded unusually, or a ` +
      'document Observa did not discover, would not be found. Absence of a ' +
      'finding is a limit of the scanner, not a statement about the policy.'
    );
    out.push('Policy analysis is informational and is not legal advice.');
  } else if (policyStatus === 'error') {
    out.push('This site’s policy could not be fetched, so no policy findings are included. That is not a finding about the policy.');
  } else if (policyDocumentsFound > 0) {
    out.push('A link to this site’s policy was found but the document could not be read, so no policy findings are included.');
  } else if (policyStatus === 'done') {
    out.push(
      'No policy document was found for this site, so no policy findings are ' +
      'included. Many logged-in applications render their footer links in ' +
      'JavaScript, which Observa cannot read.'
    );
  } else {
    out.push('No policy has been analysed for this page, so no policy findings are included.');
  }

  out.push(
    'Requests that arrived after the page finished loading are labelled as ' +
    'such. Observa cannot tell whether one was caused by something you did, a ' +
    'timer, or a background refresh — those look identical to it.'
  );

  if (pageCount > 1) out.push(`${pageCount} pages were captured in this session.`);

  return out;
}

/**
 * @param {{
 *   session?: object, cookies?: Array<object>, domains?: Array<object>,
 *   verdict?: object, inventory?: object, findings?: Array<object>,
 *   policy?: object, redact?: boolean, generatedAt?: number, version?: string,
 * }} input
 * @returns {object} the report
 */
export function buildReport(input = {}) {
  const redact = !!input.redact;
  const session = input.session ?? {};
  const cookies = input.cookies ?? [];
  const domains = input.domains ?? [];
  const policy = input.policy ?? null;
  const requests = session.requests ?? [];

  const firstTs = requests.length ? Math.min(...requests.map(r => r.timestamp ?? Infinity)) : null;
  const policyDocs = (policy?.documents ?? []);
  const policyDocsRead = policyDocs.filter(d => d.ok !== false).length;

  const thirdParties = domains
    .filter(d => d.party === 'third-party')
    .map(d => ({
      company: d.organization || d.domain,
      organizationKnown: !!d.organization,
      domains: [...(d.etld1s ?? new Set([d.etld1 ?? d.domain]))].sort(),
      category: d.category ?? null,
      isTracker: TRACKING_CATEGORIES.has(d.category),
      requestCount: (d.requests ?? []).length,
    }))
    .sort((a, b) => b.requestCount - a.requestCount);

  const exposures = (input.inventory?.rows ?? [])
    .filter(r => r.observed)
    .map(r => ({
      label: r.label,
      type: r.type,
      sources: r.sources ?? [],
      parameter: r.evidence?.paramName ?? null,
      // The value is the sensitive part. Redacted reports keep the finding and
      // drop the value; unredacted reports print what was actually observed.
      value: safeValue(r.evidence?.raw ?? r.evidence?.redacted ?? null, redact),
      // The partially-masked form Observa shows by default in the UI.
      masked: r.evidence?.redacted ?? null,
      sharedWith: (r.sharedWith ?? []).map(s => s.organization || s.domain),
      occurrences: r.occurrences ?? 0,
      timing: r.timing?.label ?? null,
      timingPhase: r.timing?.phase ?? null,
      sensitive: !!r.sensitive,
      risk: r.risk ?? null,
      confidence: r.confidence ?? null,
      disclosed: r.disclosureKnown ? !!r.disclosed : null,
      evidenceUrl: safeUrl(r.evidence?.url ?? null, redact),
    }));

  const cookieRows = cookies.map(c => ({
    name: c.name,
    domain: c.domain ?? null,
    // background/cookies.js never captures cookie values, so there is no value
    // to print or to redact — say so rather than implying one was withheld.
    valueCaptured: false,
    expiresAt: fmtDate(c.expiresAt),
    session: !!c.session,
    longLived: !!c.longLived,
    sameSite: c.sameSite ?? null,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    // Pattern matches taken FROM the value are the sensitive surface.
    matches: (c.exposures ?? []).map(e => ({
      label: e.label,
      value: safeValue(e.raw ?? e.redacted ?? null, redact),
    })),
  }));

  const policyFindings = (policy?.findings ?? []).map(f => ({
    title: f.title,
    category: f.category,
    tone: f.tone,
    importance: f.importance ?? null,
    confidence: f.confidence ?? null,
    sourceDocument: f.sourceDocument ?? null,
    section: f.section ?? null,
    // Policy text is the company's own published wording — not personal data,
    // so it survives redaction. Redacting it would gut the report's evidence.
    evidence: f.evidence ?? null,
    sourceUrl: f.sourceUrl ?? null,
  }));

  const comparisons = (policy?.comparisons ?? []).map(c => ({
    status: c.status,
    title: c.title,
    declaredQuote: c.declared?.evidence ?? null,
    declaredSource: c.declared?.sourceDocument ?? null,
    declaredSection: c.declared?.section ?? null,
    observedText: c.observedText ?? null,
    caveat: c.caveat ?? null,
  }));

  return {
    meta: {
      // A page URL can itself carry tokens in its query string.
      siteUrl: safeUrl(session.pageUrl ?? null, redact),
      host: (() => { try { return new URL(session.pageUrl).hostname; } catch { return session.pageUrl ?? null; } })(),
      scannedAt: fmtDate(firstTs),
      generatedAt: fmtDate(input.generatedAt ?? Date.now()),
      version: input.version ?? null,
      redacted: redact,
    },
    overview: {
      verdict: input.verdict
        ? {
            band: input.verdict.band,
            label: input.verdict.label,
            headline: input.verdict.headline,
            reasons: (input.verdict.reasons ?? []).map(r => r.text),
            confidence: input.verdict.confidence,
            confidenceWhy: input.verdict.confidenceWhy,
          }
        : null,
      counts: {
        requests: requests.length,
        firstPartyDomains: domains.filter(d => d.party === 'first-party').length,
        thirdPartyCompanies: thirdParties.length,
        trackers: thirdParties.filter(t => t.isTracker).length,
        cookies: cookies.length,
        dataTypes: exposures.length,
        policyDocumentsRead: policyDocsRead,
      },
    },
    findings: (input.findings ?? [])
      .filter(f => (f?.severity ?? 'medium') !== 'none')
      .map(f => ({ severity: f.severity ?? 'medium', title: f.title, detail: f.detail ?? f.body ?? '' })),
    requests: {
      total: requests.length,
      firstParty: requests.filter(r => r.party === 'first-party').length,
      thirdParty: requests.filter(r => r.party === 'third-party').length,
      byType: requests.reduce((acc, r) => {
        const t = r.type || 'other';
        acc[t] = (acc[t] ?? 0) + 1;
        return acc;
      }, {}),
    },
    thirdParties,
    cookies: cookieRows,
    exposures,
    policy: {
      status: policy?.status ?? null,
      documents: policyDocs.map(d => ({
        title: d.title ?? d.type ?? 'Document',
        url: d.url ?? null,
        ok: d.ok !== false,
        error: d.ok === false ? (d.error ?? 'could not be fetched') : null,
        discoveredVia: d.discoveredVia ?? null,
      })),
      findings: policyFindings,
      comparisons,
      notFound: (policy?.notFound ?? []).map(n => n.title),
    },
    limitations: buildLimitations({
      requestCount: requests.length,
      policyStatus: policy?.status ?? null,
      policyDocsRead,
      policyDocumentsFound: policyDocs.length,
      cookieCount: cookies.length,
      exposureCount: exposures.length,
    }),
  };
}
