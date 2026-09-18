// Observa Policy Intelligence — policy/locate.js
//
// Builds a deep link that opens a policy document scrolled to, and
// highlighting, the exact sentence a finding was matched from — so "View
// Evidence" can be checked against the live document in one click instead of
// the user having to Ctrl-F for it themselves.
//
// ── How this works, and its real limits ────────────────────────────────────
// This uses the Text Fragments URL syntax (`#:~:text=`), a web-platform
// feature Chrome has supported since Chrome 80. The browser finds the quoted
// text in the loaded document, scrolls to it, and highlights it. Nothing is
// sent anywhere and no script runs on the target page — it is purely a URL
// fragment interpreted by the browser itself, which is why this needs no new
// permission and no content script.
//
// It is a best-effort affordance, not a guarantee, and the UI must not
// promise more than it can deliver. It fails to highlight (falling back to
// simply opening the document at the top, which is still useful) when:
//   - the site sends `Document-Policy: force-load-at-top`, which disables
//     text fragments deliberately;
//   - the page's rendered text differs from the fetched HTML we matched
//     against — most often because the policy is rendered by JavaScript, or
//     because whitespace/soft hyphens differ from what our text extraction
//     produced;
//   - the same text appears earlier in the document, in which case the
//     browser highlights the first occurrence rather than the one we matched.
// A text fragment also only activates on a full navigation (not a
// same-document one), which is what opening the link in a new tab does.
//
// Kept as its own module with no imports so it is trivially unit-testable and
// so the fragment-encoding rules live in exactly one place.

// Within a text fragment directive, `-`, `,` and `&` are structural
// delimiters (prefix-, textStart,textEnd, -suffix, and the &-separated
// directive list). encodeURIComponent leaves all three alone, so they have to
// be percent-encoded explicitly or a clause containing a comma silently
// truncates the match.
function encodeFragmentPart(s) {
  return encodeURIComponent(s)
    .replace(/-/g, '%2D')
    .replace(/,/g, '%2C')
    .replace(/&/g, '%26');
}

const WORDS_AT_EACH_END = 6;
const MAX_EXACT_LEN = 60;
const MIN_USABLE_LEN = 8;

// An HTML id, conservatively. Anything else is ignored rather than
// interpolated into a URL.
const SAFE_ID = /^[A-Za-z0-9\-_.:]{1,120}$/;

/**
 * Builds `<url>#<section-anchor>:~:text=<clause>` when the source document
 * gave its section heading an anchor, and `<url>#:~:text=<clause>` otherwise.
 *
 * Carrying both matters: the two halves fail independently. The text fragment
 * is the precise target (the exact sentence), but it can silently fail to
 * match — a JS-rendered page, `force-load-at-top`, whitespace differences.
 * The element anchor is coarser (the top of the section) but is plain,
 * long-standing fragment navigation that essentially always works. With both
 * present the browser applies the text fragment when it can and falls back to
 * the anchor when it can't, so a reader lands on the right section either way
 * instead of at the top of a 12,000-word document.
 *
 * @param {string|null|undefined} docUrl - the source document's URL. Null for
 *   a manually pasted document (there is nothing to link to), in which case
 *   this returns null and the UI shows the in-app evidence only.
 * @param {string|null|undefined} matchText - the exact text that matched.
 * @param {string|null|undefined} [sectionId] - the anchor id of the heading
 *   the clause sits under, from policy/textify.js.
 * @returns {string|null} a URL, or null when no useful link can be built.
 *   Never throws.
 */
export function buildEvidenceLink(docUrl, matchText, sectionId) {
  if (typeof docUrl !== 'string' || !/^https?:\/\//i.test(docUrl)) return null;
  const anchor = (typeof sectionId === 'string' && SAFE_ID.test(sectionId)) ? sectionId : '';
  // A section anchor alone is still a useful link even with no usable clause
  // text, so that case is handled before the match-length guard below.
  if (typeof matchText !== 'string') {
    return anchor ? `${docUrl.split('#')[0]}#${anchor}` : null;
  }

  // Collapse whitespace: our text extraction normalizes runs of whitespace,
  // and the browser's own text-fragment matching is whitespace-insensitive,
  // but the *URL* has to carry a single canonical form.
  const clean = matchText.replace(/\s+/g, ' ').trim();
  if (clean.length < MIN_USABLE_LEN) {
    return anchor ? `${docUrl.split('#')[0]}#${anchor}` : null;
  }

  let directive;
  if (clean.length <= MAX_EXACT_LEN) {
    directive = encodeFragmentPart(clean);
  } else {
    // For a long match the spec's own guidance is to anchor on the start and
    // end rather than quote the whole range — it is shorter, and it survives
    // small differences in the middle of the sentence (a stray tag, a
    // non-breaking space) that would otherwise break an exact-match attempt.
    const words = clean.split(' ');
    const start = words.slice(0, WORDS_AT_EACH_END).join(' ');
    const end = words.slice(-WORDS_AT_EACH_END).join(' ');
    if (!start || !end || start === end) {
      directive = encodeFragmentPart(clean.slice(0, MAX_EXACT_LEN));
    } else {
      directive = `${encodeFragmentPart(start)},${encodeFragmentPart(end)}`;
    }
  }

  // Drop any existing fragment on the document URL — a policy URL that
  // already points at an anchor would otherwise produce two fragments. The
  // section anchor sits before `:~:` (ordinary fragment) and the clause after
  // it (fragment directive); the anchor is encoded with plain
  // encodeURIComponent, not the fragment-part rules, since `-` and `,` carry
  // no special meaning outside the directive.
  const base = docUrl.split('#')[0];
  return `${base}#${anchor ? encodeURIComponent(anchor) : ''}:~:text=${directive}`;
}

/**
 * Splits a paragraph into the three pieces the UI needs to render it with the
 * matched phrase highlighted, without the renderer needing the original
 * regex. Returns null when the offsets don't line up (defensive — a stored
 * finding from an older version won't carry them).
 * @param {string} paragraph
 * @param {number} offset
 * @param {number} length
 * @returns {{before:string, match:string, after:string}|null}
 */
export function splitForHighlight(paragraph, offset, length) {
  if (typeof paragraph !== 'string') return null;
  if (!Number.isInteger(offset) || !Number.isInteger(length)) return null;
  if (offset < 0 || length <= 0 || offset + length > paragraph.length) return null;
  return {
    before: paragraph.slice(0, offset),
    match: paragraph.slice(offset, offset + length),
    after: paragraph.slice(offset + length),
  };
}
