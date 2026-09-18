// Observa Policy Intelligence — policy/extract.js
//
// Runs the fixed clause taxonomy (policy/taxonomy.js) against a document's
// text blocks (policy/textify.js) and produces structured findings.
//
// Detection method: local pattern/keyword matching, same technique
// classify/tracker-list.js and classify/cookie-db.js already use for domain
// and cookie classification — no external AI call, no network request beyond
// fetching the policy document itself (see background/policy-intel.js).
// Per CLAUDE.md Rule 3 and this feature's explicit spec: a finding is never
// emitted unless the matched text is actually present in the document, and
// the exact matched sentence/paragraph is always carried as `evidence` so
// the claim can be checked against the source. A category with no matching
// signal anywhere in the document simply produces no finding — Observa does
// not claim a topic is "not addressed" just because its own patterns didn't
// recognize the phrasing; that would be a false negative dressed up as a
// fact. Provenance for every finding here is "Classified" (matched against a
// known pattern set), the same provenance tracker/cookie classification
// already uses for the same reason.
//
// Known limitation, stated plainly rather than glossed over: this is
// pattern matching, not comprehension. A policy that describes a concerning
// practice in unusual wording the taxonomy doesn't recognize will produce no
// finding for that topic, and a policy that merely mentions a term in an
// unrelated context could produce a false positive. Confidence levels exist
// specifically to communicate this — "low confidence" means the match is
// more likely to be an artifact of the wording, not a confirmed clause.

import { CLAUSE_TAXONOMY } from './taxonomy.js';

// Short, plain-language one-liners for the collapsed finding card — the
// "headline" a normal user reads before deciding whether to expand for
// evidence. Keyed by category id, then by the tone that actually matched
// (a category can read very differently depending on which signal fired —
// see taxonomy.js). Falls back to the category's longer `why` text if no
// template exists for that exact tone, so a category is never left blank.
const SUMMARY_TEMPLATES = {
  personalData:           { neutral: 'The document lists what personal information is collected about you.' },
  sensitiveData:          { concern: 'The document says sensitive data (health, financial, ID, or biometric) may be collected.' },
  locationData:           { concern: 'Your location may be collected.', good: 'The document says it does not collect your location.' },
  browsingActivity:       { neutral: 'Your browsing or usage activity on this site or app is tracked.' },
  deviceIdentifiers:      { neutral: 'Device or advertising identifiers may be collected.' },
  thirdPartySharing:      { concern: 'Information may be shared with advertising, analytics, or business partners.', good: 'The document says it does not share your information with third parties.' },
  advertising:            { concern: 'The company says information may be used for targeted advertising.', good: 'The document says it does not use targeted or interest-based advertising.' },
  dataSale:               { concern: 'The document allows selling or sharing your personal data with third parties for value.', good: 'The document says it does not sell your personal information.' },
  dataFromOtherCompanies: { neutral: 'The company may combine your data with information it gets from other companies.' },
  retention:              { concern: 'Some information may remain after you delete your account.', good: 'The document gives a specific data retention period.' },
  deletion:               { good: 'The policy describes a way to request deletion of your personal information.', concern: 'The document suggests some data cannot be deleted.' },
  optOutRights:           { good: 'The document describes privacy rights you can exercise, like access or opt-out.', concern: 'These rights may not apply to everyone reading this document.' },
  aiTraining:             { concern: 'Your content or data may be used to train AI or machine-learning models.', good: 'The document offers a way to opt out of AI training, or says it doesn’t use your data that way.' },
  policyChanges:          { neutral: 'This policy can change over time.', good: 'The company says it will notify you of material changes.', concern: 'Continuing to use the service after a change may count as accepting it, with no separate notice guaranteed.' },
  arbitration:            { concern: 'Certain disputes may have to be handled through binding arbitration instead of court.' },
  classActionWaiver:      { concern: 'You may be giving up the right to join a class-action lawsuit.' },
  autoRenewal:            { concern: 'This subscription or plan may renew automatically unless you cancel.' },
  contentOwnership:       { concern: 'The company may receive a broad license to use content you upload.', good: 'The document says you keep ownership of what you post.' },
  limitationOfLiability:  { concern: 'The company limits how much you can recover if something goes wrong.' },
};
function summaryFor(categoryId, tone, fallback) {
  return SUMMARY_TEMPLATES[categoryId]?.[tone] ?? fallback;
}

// ── Negation guard ─────────────────────────────────────────────────────────
// Found while testing the policy-vs-observed comparison: several concern
// patterns are negation-blind. "We do not share your personal information
// with third parties" contains the exact substring "share your personal
// information with third parties", so the concern signal matched it and the
// clause was reported as evidence that the company DOES share — the precise
// inverse of what the document says.
//
// That is the worst class of error this feature can make: it accuses a
// company of something its policy explicitly disclaims, with a real quote
// underneath it as apparent proof. So the rule is absolute — a concerning
// finding is never emitted from text that is grammatically negated. The
// reassuring reading is still available, because the taxonomy carries
// explicit tone:'good' signals for these same clauses that match the negation
// directly.
//
// This is deliberately conservative: a missed concern is a gap, a fabricated
// one is a lie. Anchored to the end of the preceding window so only a negator
// attached to this clause counts, not one from an earlier sentence.
const NEGATION_BEFORE = /\b(?:do|does|did|will|would|shall|can|could|may|might|must)\s+not\s+$|\b(?:don'?t|doesn'?t|didn'?t|won'?t|can'?t|cannot|shan'?t)\s+$|\bnever\s+$|\bwithout\s+$|\bno\s+$|\bnor\s+$|\bneither\s+$/i;

function isNegated(text, matchIndex) {
  return NEGATION_BEFORE.test(text.slice(Math.max(0, matchIndex - 30), matchIndex));
}

// Returns the first match of `re` in `text`, skipping negated occurrences when
// asked. Scans all occurrences rather than only String.match's first, so a
// negated mention early in a paragraph doesn't hide a genuine one later in it.
function findMatch(text, re, skipNegated) {
  const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
  const scanner = new RegExp(re.source, flags);
  let m;
  while ((m = scanner.exec(text)) !== null) {
    if (m[0].length === 0) { scanner.lastIndex++; continue; }
    if (skipNegated && isNegated(text, m.index)) continue;
    return m;
  }
  return null;
}

const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
function bumpConfidence(level) {
  if (level === 'low') return 'medium';
  if (level === 'medium') return 'high';
  return 'high';
}
// A match found only inside a table-of-contents blob is a section *heading*,
// not the clause itself — the topic is really mentioned, but the quote backing
// it is weak. Demote rather than drop, so the finding survives while the
// confidence level tells the truth about what it rests on.
function demoteConfidence(level) {
  if (level === 'high') return 'medium';
  if (level === 'medium') return 'low';
  return 'low';
}

// The heading a matched clause sits under, plus that heading's own anchor id
// when the source HTML gave it one. The id is what lets the UI link to the
// section of the live document rather than only to the quoted sentence — see
// policy/locate.js.
function nearestPrecedingHeading(blocks, index) {
  for (let i = index - 1; i >= 0; i--) {
    if (blocks[i].type === 'heading') {
      return { text: blocks[i].text, anchorId: blocks[i].anchorId || null };
    }
  }
  return { text: null, anchorId: null };
}

// ── Quote quality ──────────────────────────────────────────────────────────
// Found against the live New York Times privacy policy: the evidence quote is
// what makes a finding checkable, and a bad quote actively destroys trust. Two
// failures showed up there.
//
// First, a fixed-radius slice starts mid-word — "…nother law). We use this
// information…" reads like the tool is broken. Quotes now snap outward to
// sentence boundaries, and to a word boundary at worst.
//
// Second, and worse: this regex segmenter has no DOM, so a page's table of
// contents collapses into a single "paragraph" — "2. (E) We Carry Out
// Administrative or Legal Tasks 2. (F) We Offer Sweepstakes…". Quoting that as
// "what the policy says" presents a list of section headings as substantive
// language. looksLikeIndex() spots those so extractFindings can prefer real
// prose, and only fall back to an index block rather than lose the finding.
const ENUM_MARKER = /\(\s*[A-Za-z0-9]{1,3}\s*\)/g;
const NUMBERED_HEAD = /(?:^|\s)\d+\.\s+(?=[A-Z])/g;

function looksLikeIndex(text) {
  if ((text.match(ENUM_MARKER) || []).length >= 4) return true;
  if ((text.match(NUMBERED_HEAD) || []).length >= 5) return true;
  return false;
}

function sentenceSnippet(text, matchIndex, matchLength, maxLen = 300) {
  const budget = Math.max(40, Math.floor((maxLen - matchLength) / 2));
  let start = Math.max(0, matchIndex - budget);
  let end = Math.min(text.length, matchIndex + matchLength + budget);

  // Snap the start forward to just after the previous sentence end, or at
  // minimum to a word boundary, so a quote never opens mid-word.
  const head = text.slice(start, matchIndex);
  const sentBreak = head.lastIndexOf('. ');
  if (sentBreak >= 0) start += sentBreak + 2;
  else if (start > 0) {
    const sp = head.indexOf(' ');
    if (sp >= 0) start += sp + 1;
  }

  // Snap the end back to the first sentence end after the match, else a word
  // boundary.
  const tailFrom = matchIndex + matchLength;
  const tail = text.slice(tailFrom, end);
  const tailBreak = tail.search(/[.!?](?:\s|$)/);
  if (tailBreak >= 0) end = tailFrom + tailBreak + 1;
  else {
    const sp = tail.lastIndexOf(' ');
    if (sp > 0) end = tailFrom + sp;
  }

  let snippet = text.slice(start, end).trim();
  if (start > 0) snippet = '…' + snippet;
  if (end < text.length) snippet = snippet + '…';
  return snippet;
}

// A heading that is really just the document's own title ("The New York Times
// Company Privacy Policy" under a document already labelled "Privacy Policy")
// tells the reader nothing, so it is dropped rather than shown as the section.
function normalizeLabel(s) {
  return String(s ?? '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
}
function isJustDocumentTitle(headingText, sourceDocument) {
  if (!headingText) return true;
  const h = normalizeLabel(headingText);
  const d = normalizeLabel(sourceDocument);
  if (!h || !d) return false;
  return h === d || (h.length < 60 && h.includes(d));
}

// The whole paragraph the match sits in, so the UI can show the clause in
// context rather than a clipped fragment — reading "we do not sell your
// personal information" is very different from reading the sentence that
// follows it. Offsets are returned alongside so the exact matched phrase can
// be highlighted inside that paragraph without the renderer having to re-run
// the regex (which it can't — the taxonomy lives in the service worker).
// Very long paragraphs are windowed around the match rather than returned
// whole, so one badly-segmented block can't dump 40KB into the UI.
function paragraphAround(text, matchIndex, matchLength, maxLen = 1200) {
  if (text.length <= maxLen) return { text, offset: matchIndex, truncated: false };
  const radius = Math.max(0, Math.floor((maxLen - matchLength) / 2));
  const start = Math.max(0, matchIndex - radius);
  const end = Math.min(text.length, start + maxLen);
  return { text: text.slice(start, end), offset: matchIndex - start, truncated: true };
}

/**
 * @param {{type:'heading'|'para', text:string}[]} blocks
 * @param {{sourceDocument:string}} ctx - which document this text came from
 *   (e.g. "Privacy Policy", "Terms of Use", or a user-supplied label for a
 *   manually pasted document)
 * @returns {Array<{
 *   category:string, title:string, tone:'concern'|'neutral'|'good',
 *   importance:'high'|'medium'|'low', explanation:string,
 *   recommendation:string, sourceDocument:string, section:string|null,
 *   evidence:string, evidenceFull:string, evidenceOffset:number,
 *   evidenceTruncated:boolean, matchText:string,
 *   confidence:'high'|'medium'|'low', provenance:'Classified'
 * }>}
 */
export function extractFindings(blocks, ctx) {
  const sourceDocument = ctx?.sourceDocument ?? 'Policy document';
  const paraBlocks = blocks
    .map((b, index) => ({ ...b, index }))
    .filter(b => b.type === 'para');

  const findings = [];

  for (const category of CLAUSE_TAXONOMY) {
    // Best match PER TONE, not per category.
    //
    // This used to keep a single `best` per category — the earliest matching
    // block won outright, and an opposing-tone match became a footnote on the
    // explanation. On a real policy that silently deleted information: a
    // document saying both "click Do Not Sell or Share My Personal
    // Information" and "we do not sell your personal information to data
    // brokers" reported one concern about selling and dropped the disclaimer
    // entirely. A policy that speaks to a topic twice, in two directions, is
    // a fact about the policy — flattening it to whichever sentence appeared
    // first is a loss, and in that case an actively misleading one.
    const bestByTone = new Map(); // tone -> { blockIndex, block, signal, match, indexLike }

    for (const signal of category.signals) {
      const signalTone = signal.tone ?? category.defaultTone;
      let firstForSignal = null;
      for (const block of paraBlocks) {
        const m = findMatch(block.text, signal.re, signalTone === 'concern');
        if (!m) continue;
        const candidate = { block, match: m, indexLike: looksLikeIndex(block.text) };
        // Prefer real prose over a table-of-contents blob, but fall back to
        // the index block rather than dropping the finding entirely — the
        // topic genuinely is mentioned, the quote is just weaker.
        if (!candidate.indexLike) { firstForSignal = candidate; break; }
        if (!firstForSignal) firstForSignal = candidate;
      }
      if (!firstForSignal) continue;

      // Within a tone, prefer the STRONGEST evidence, not the earliest.
      // Document order is arbitrary with respect to quote quality: on a real
      // California-rights passage the medium-confidence opt-out link sentence
      // appeared before the high-confidence "we do not sell your personal
      // information", so the weaker sentence was the one quoted back to the
      // user. Rank by confidence first, then fall back to document order.
      const CONF_RANK = { high: 0, medium: 1, low: 2 };
      const current = bestByTone.get(signalTone);
      const rank = s => CONF_RANK[s?.confidence ?? 'medium'] ?? 1;
      const better = !current
        || rank(signal) < rank(current.signal)
        || (rank(signal) === rank(current.signal) && firstForSignal.block.index < current.blockIndex);
      if (better) {
        bestByTone.set(signalTone, {
          blockIndex: firstForSignal.block.index,
          block: firstForSignal.block,
          signal,
          match: firstForSignal.match,
          indexLike: firstForSignal.indexLike,
        });
      }
    }

    if (!bestByTone.size) continue;

    // Emit in a stable, meaningful order: concern, then neutral, then good.
    const TONE_ORDER = ['concern', 'neutral', 'good'];
    const tonesMatched = TONE_ORDER.filter(t => bestByTone.has(t));

    for (const emitTone of tonesMatched) {
    const best = bestByTone.get(emitTone);
    // Another tone matched this same category — each emitted finding says so,
    // so a reader of any one of them knows the document cuts both ways.
    const otherToneAlsoMatched = tonesMatched.length > 1;

    const tone = best.signal.tone ?? category.defaultTone;
    const importance = best.signal.importance ?? (tone === 'good' ? 'low' : category.defaultImportance);
    let confidence = best.signal.confidence ?? 'medium';
    // A second, independently-matched signal for the same category and the
    // same tone reinforces the finding; conflicting-tone matches are left at
    // the matched signal's own confidence and noted in the explanation
    // instead — an actual mixed/ambiguous policy shouldn't be flattened into
    // false certainty either way.
    if (!otherToneAlsoMatched && !best.indexLike) confidence = bumpConfidence(confidence);
    if (best.indexLike) confidence = demoteConfidence(confidence);

    const heading = nearestPrecedingHeading(blocks, best.blockIndex);
    const section = isJustDocumentTitle(heading.text, sourceDocument) ? null : heading.text;
    const evidence = sentenceSnippet(best.block.text, best.match.index, best.match[0].length);
    const para = paragraphAround(best.block.text, best.match.index, best.match[0].length, 700);
    const matchText = best.match[0];

    let explanation = category.why;
    if (otherToneAlsoMatched) {
      explanation += ' Note: this document also contains other language on this same topic elsewhere that points the other way — worth reading both passages yourself rather than relying on a single line.';
    }

    findings.push({
      category: category.id,
      title: category.title,
      summary: summaryFor(category.id, tone, category.why),
      tone,
      importance,
      explanation,
      recommendation: category.recommendation,
      sourceDocument,
      section,
      // The section heading's own anchor id, when the document had one — used
      // to land the reader on the right section even if text-fragment
      // matching fails on the live page.
      sectionId: heading.anchorId,
      evidence,
      // Full surrounding paragraph + where the matched phrase sits inside it,
      // so the UI can show the clause in context with the exact phrase
      // highlighted, and so a deep link into the live document can be built
      // from `matchText` (see policy/locate.js).
      evidenceFull: para.text,
      evidenceOffset: para.offset,
      evidenceTruncated: para.truncated,
      matchText,
      confidence,
      provenance: 'Classified',
    });
    }
  }

  return findings;
}
