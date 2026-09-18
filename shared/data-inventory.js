// Observa — shared/data-inventory.js
//
// Joins what Observa *observed* leaving the page (classify/exposure.js matches
// on requests and cookie values) against what the site's policy *discloses*
// (policy/extract.js findings), and produces one row per data type.
//
// This is the product thesis expressed at the data-type level, and it is the
// only place the two halves meet per-datum rather than per-clause. The row that
// matters most is "observed but not disclosed": something that looks like your
// data left the page, and nothing in the documents we read mentions that
// category.
//
// ── What this will and will not assert ─────────────────────────────────────
//   1. "Observed" means a pattern matched in a request or cookie value. It is
//      NOT a claim that the value is real, accurate, or actually yours — the
//      same limit classify/exposure.js already documents.
//   2. "Not disclosed" means *Observa's patterns found no policy language for
//      that category in the documents it read*. It is not a finding that the
//      policy is silent, and never a legal conclusion. A policy that words a
//      disclosure unusually, or a document that wasn't discovered, both land
//      here — so the UI must word it as a limit of the scanner.
//   3. There is deliberately no `purpose` and no non-cookie `retention` field.
//      A redesign mockup showed both ("Security, analytics, fraud prevention",
//      "30-90 days" for an IP address); neither is observable from network
//      traffic, and inventing them would be exactly the fabrication CLAUDE.md
//      Rule 3 forbids. Cookie expiry is real and is carried where it exists.
//   4. Confidence stays high/medium/low. The mockup's "94%" is invented
//      precision the underlying evidence cannot support.
//
// Pure function over plain data — no chrome.* APIs, no DOM.

import { classifyTiming } from './timing.js';

// Which clause category in policy/taxonomy.js a given observed exposure type
// would be disclosed under, if the policy discloses it at all.
export const TYPE_TO_CATEGORY = {
  email: 'personalData',
  phone: 'personalData',
  zip: 'locationData',
  geo: 'locationData',
  id: 'deviceIdentifiers',
  page: 'browsingActivity',
  campaign: 'browsingActivity',
};

// The "what is collected" half of the taxonomy — the only categories that
// describe data types. The rest of the taxonomy (arbitration, retention,
// liability...) is about terms, not data, and has no place on this screen.
export const COLLECTION_CATEGORIES = {
  personalData: 'Personal information',
  sensitiveData: 'Sensitive information',
  locationData: 'Location data',
  browsingActivity: 'Browsing / activity data',
  deviceIdentifiers: 'Device identifiers',
};

// Types whose match carries real-world risk if it is genuinely the visitor's.
const SENSITIVE_TYPES = new Set(['email', 'phone', 'geo']);

function riskFor(type) {
  if (SENSITIVE_TYPES.has(type)) return 'high';
  if (type === 'id' || type === 'zip') return 'medium';
  return 'low';
}

// An exposure carrying an explicitly named parameter is stronger evidence than
// a bare regex hit on a value, and exposure.js already distinguishes these via
// `provenance` ('Observed' vs 'Inferred').
function confidenceFor(exposure) {
  if (exposure?.provenance === 'Inferred') return 'medium';
  return exposure?.paramName ? 'high' : 'medium';
}

// Source keys come from classify/exposure.js's scanEntries() calls.
const SOURCE_LABEL = { query: 'Request parameter', body: 'Request body', cookie: 'Cookie value' };

/**
 * @param {{
 *   domains?: Array<{domain:string, organization?:string|null, category?:string|null,
 *                    exposures?: Array<object>, requestCount?:number}>,
 *   policyFindings?: Array<object>,
 *   policyDocsRead?: number,
 *   t0?: number|null,        // first request timestamp (load baseline)
 *   settleMs?: number,       // end of the initial load burst, from shared/timing.js
 * }} input
 * @returns {{rows:Array<object>, counts:{all:number,observed:number,policyOnly:number,notDisclosed:number,sensitive:number}}}
 */
export function buildDataInventory(input = {}) {
  const domains = input.domains ?? [];
  const policyFindings = input.policyFindings ?? [];
  const policyDocsRead = input.policyDocsRead ?? 0;
  const t0 = input.t0 ?? null;
  const settleMs = input.settleMs ?? 3000;

  // Which collection categories the policy actually speaks to, and the finding
  // that says so (used to cite a section on the row).
  const disclosedBy = new Map();
  for (const f of policyFindings) {
    if (f?.category && f.category in COLLECTION_CATEGORIES && !disclosedBy.has(f.category)) {
      disclosedBy.set(f.category, f);
    }
  }

  // ── Observed rows, grouped by data type across every domain ──────────────
  const byType = new Map();
  for (const d of domains) {
    for (const e of d.exposures ?? []) {
      if (!e?.type) continue;
      if (!byType.has(e.type)) {
        byType.set(e.type, {
          type: e.type,
          label: e.label || e.type,
          observed: true,
          occurrences: 0,
          sharedWith: [],
          sources: new Set(),
          evidence: null,
          firstTs: null,
          lastTs: null,
        });
      }
      const row = byType.get(e.type);
      row.occurrences++;
      if (typeof e.firstTs === 'number') row.firstTs = row.firstTs == null ? e.firstTs : Math.min(row.firstTs, e.firstTs);
      if (typeof e.lastTs === 'number') row.lastTs = row.lastTs == null ? e.lastTs : Math.max(row.lastTs, e.lastTs);
      row.sources.add(SOURCE_LABEL[e.source] ?? e.source ?? 'Request');
      if (!row.sharedWith.some(s => s.domain === d.domain)) {
        row.sharedWith.push({ domain: d.domain, organization: d.organization ?? null, category: d.category ?? null });
      }
      // Keep the first match as the citable evidence, preferring one that
      // names a parameter over a bare value hit.
      if (!row.evidence || (!row.evidence.paramName && e.paramName)) {
        row.evidence = { ...e, domain: d.domain };
      }
    }
  }

  const rows = [];
  for (const row of byType.values()) {
    const category = TYPE_TO_CATEGORY[row.type] ?? null;
    const disclosedFinding = category ? disclosedBy.get(category) ?? null : null;
    // With no policy read at all, "not disclosed" would be meaningless — we
    // simply don't know yet, and saying otherwise would be an assertion we
    // can't support.
    const disclosureKnown = policyDocsRead > 0;
    rows.push({
      ...row,
      sources: [...row.sources],
      category,
      categoryLabel: category ? COLLECTION_CATEGORIES[category] : null,
      disclosureKnown,
      disclosed: disclosureKnown ? !!disclosedFinding : null,
      policy: disclosedFinding
        ? {
            sourceDocument: disclosedFinding.sourceDocument,
            section: disclosedFinding.section ?? null,
            sectionId: disclosedFinding.sectionId ?? null,
            sourceUrl: disclosedFinding.sourceUrl ?? null,
            evidence: disclosedFinding.evidence,
            matchText: disclosedFinding.matchText ?? null,
          }
        : null,
      sensitive: SENSITIVE_TYPES.has(row.type),
      // Timing is judged on the LAST sighting: a value sent during load and
      // again after the page settled is the interesting case, and reporting
      // only the first sighting would hide it.
      timing: classifyTiming(row.lastTs, t0, settleMs),
      risk: riskFor(row.type),
      confidence: confidenceFor(row.evidence),
      policyOnly: false,
    });
  }

  // ── Policy-only rows: the document says a category is collected, but
  // nothing matching it was seen on this page. Not a contradiction — most
  // collection happens server-side or on pages we didn't visit. ────────────
  const observedCategories = new Set(rows.map(r => r.category).filter(Boolean));
  for (const [category, finding] of disclosedBy) {
    if (observedCategories.has(category)) continue;
    rows.push({
      type: `policy:${category}`,
      label: COLLECTION_CATEGORIES[category],
      observed: false,
      policyOnly: true,
      occurrences: 0,
      sharedWith: [],
      sources: ['Privacy policy'],
      category,
      categoryLabel: COLLECTION_CATEGORIES[category],
      disclosureKnown: true,
      disclosed: true,
      policy: {
        sourceDocument: finding.sourceDocument,
        section: finding.section ?? null,
        sectionId: finding.sectionId ?? null,
        sourceUrl: finding.sourceUrl ?? null,
        evidence: finding.evidence,
        matchText: finding.matchText ?? null,
      },
      evidence: null,
      timing: { phase: 'unknown', elapsedMs: null, label: '—', provenance: 'Inferred' },
      sensitive: category === 'sensitiveData',
      risk: category === 'sensitiveData' ? 'medium' : 'low',
      confidence: finding.confidence ?? 'medium',
    });
  }

  // Most consequential first: observed-but-undisclosed, then by risk, then by
  // how often it was seen.
  const RISK_ORDER = { high: 0, medium: 1, low: 2 };
  rows.sort((a, b) => {
    const aUndisclosed = a.observed && a.disclosed === false ? 0 : 1;
    const bUndisclosed = b.observed && b.disclosed === false ? 0 : 1;
    if (aUndisclosed !== bUndisclosed) return aUndisclosed - bUndisclosed;
    if (a.observed !== b.observed) return a.observed ? -1 : 1;
    const r = RISK_ORDER[a.risk] - RISK_ORDER[b.risk];
    if (r !== 0) return r;
    return b.occurrences - a.occurrences;
  });

  return {
    rows,
    counts: {
      all: rows.length,
      observed: rows.filter(r => r.observed).length,
      policyOnly: rows.filter(r => r.policyOnly).length,
      notDisclosed: rows.filter(r => r.observed && r.disclosed === false).length,
      sensitive: rows.filter(r => r.sensitive).length,
      afterLoad: rows.filter(r => r.timing?.phase === 'later').length,
    },
  };
}
