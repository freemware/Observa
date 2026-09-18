// Observa — shared/overview-concerns.js
//
// Builds the Overview's "Top concerns" rows AND the number the "Policy
// concerns" tile displays, from one function, so the two cannot disagree.
//
// ── Why this exists ────────────────────────────────────────────────────────
// It was previously two separate expressions inline in renderOverview(). The
// tile counted every policy finding with tone:'concern'; the card rendered
// network findings plus policy *comparisons* with status:'tension'. Concerning
// clauses had no path into the card at all, so a real session (bbc.com) showed
//
//     Policy concerns        2
//     Top concerns    →  "No notable findings for this session"
//
// Two individually-correct numbers that read as a contradiction. Deriving both
// from one call makes that state unrepresentable rather than merely fixed.
//
// ── What this will and will not assert ─────────────────────────────────────
//   1. A policy clause is *Declared*, not Observed. Rows sourced from policy
//      wording carry provenance 'Declared' and quote the document; they never
//      assert that the described behavior happened (CLAUDE.md Rule 3).
//   2. buildSessionFindings() appends a synthetic severity:'none' all-clear row
//      when it finds nothing. That is a reassurance, not a concern, and is
//      filtered out here — rendering it in a concerns list is what produced
//      the contradiction above.
//   3. Only importance:'high' clauses surface. Lower-importance ones are
//      counted in `lesserCount` and pointed at Policy detail, never dropped
//      silently.
//
// Pure function over plain data — no chrome.* APIs, no DOM.

// Network and cookie findings are NOT capped. buildSessionFindings() already
// only emits a row when something real matched, and slicing to three silently
// dropped observations the user had no way to know existed — on a busy page
// "1 advertising trackers active" and "N third-party scripts executing" simply
// never appeared. Policy clauses stay capped because a long document can
// produce many, and the remainder is reported rather than dropped.
const MAX_TENSION_ROWS = 2;
const MAX_POLICY_ROWS = 2;

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

/**
 * @param {{
 *   sessionFindings?: Array<{severity?:string, title?:string, detail?:string, body?:string, evidence?:string}>,
 *   comparisons?: Array<{status?:string, title?:string, observedText?:string, declared?:object}>,
 *   policyFindings?: Array<{tone?:string, importance?:string, title?:string, evidence?:string,
 *                           sourceDocument?:string, section?:string}>,
 *   policyAnalyzed?: boolean,
 * }} input
 * @returns {{rows:Array<object>, tileCount:number|null, lesserCount:number}}
 */
export function buildOverviewConcerns(input = {}) {
  const sessionFindings = input.sessionFindings ?? [];
  const comparisons = input.comparisons ?? [];
  const policyFindings = input.policyFindings ?? [];
  const policyAnalyzed = !!input.policyAnalyzed;

  const concerning = policyFindings.filter(f => f?.tone === 'concern');
  const high = concerning.filter(f => f.importance === 'high');

  const rows = [];

  // Network + cookie observations. The synthetic all-clear row is not a
  // concern and must never appear in a concerns list. Worst first, so the
  // most serious thing on the page is always the first thing read.
  const observed = sessionFindings
    .filter(f => (f?.severity ?? 'medium') !== 'none')
    .map(f => ({
      severity: (f.severity ?? 'medium').toLowerCase(),
      title: f.title ?? 'Finding',
      body: f.detail ?? f.body ?? '',
      evidence: f.evidence ?? '',
      provenance: f.provenance ?? 'Observed',
      evidenceView: f.evidenceView ?? 'orgs',
      evidenceDomain: f.evidenceDomain ?? null,
    }))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 1) - (SEVERITY_ORDER[b.severity] ?? 1));
  rows.push(...observed);

  // Policy-vs-observed tensions: the document says one thing, the page did
  // another. Both halves are already carried on the comparison.
  for (const c of comparisons.filter(c => c?.status === 'tension').slice(0, MAX_TENSION_ROWS)) {
    rows.push({
      severity: 'high',
      title: c.title,
      body: c.observedText,
      evidence: `${c.declared?.sourceDocument ?? 'Policy'}${c.declared?.section ? ` · ${c.declared.section}` : ''}`,
      provenance: 'Declared vs Observed',
    });
  }

  // High-importance clauses from the policy's own wording — the set the tile
  // counts. The body quotes the document rather than characterising behavior.
  for (const f of high.slice(0, MAX_POLICY_ROWS)) {
    rows.push({
      severity: 'high',
      title: f.title ?? 'Policy clause',
      body: f.evidence ? `The policy says: “${f.evidence}”` : '',
      evidence: `${f.sourceDocument ?? 'Policy'}${f.section ? ` · ${f.section}` : ''} — declared, not observed`,
      provenance: 'Declared',
    });
  }

  // A count is only earned by actually reading a document.
  //
  // `policyAnalyzed` was true whenever a policy-intel object existed — including
  // when the fetch had FAILED. So a page whose scan card read "Couldn't reach
  // this site's policy" still printed a confident 0 beside it, which asserts
  // "we checked, there are none" about a document nobody read. Same overclaim
  // the rest of this module exists to prevent; the test is whether a document
  // came back, not whether we tried.
  // `policyDocsRead` is authoritative when the caller supplies it. Callers that
  // don't (older tests, and any surface that genuinely only knows "a policy was
  // analyzed") fall back to the previous meaning rather than silently losing
  // their count. dashboard.js passes it.
  const haveReadSomething = input.policyDocsRead === undefined
    ? policyAnalyzed
    : input.policyDocsRead > 0;

  return {
    rows,
    // null, not 0, when nothing was read — the tile renders an em dash.
    tileCount: haveReadSomething ? high.length : null,
    lesserCount: concerning.length - high.length,
    // The card caps how many clauses it shows. If the tile counts more than
    // that, the difference must be stated — an unexplained "4" above two rows
    // is a milder version of the same contradiction this module exists to
    // prevent.
    hiddenCount: Math.max(0, high.length - MAX_POLICY_ROWS),
  };
}
