// Observa Policy Intelligence — policy/textify.js
//
// Converts a fetched policy page's raw HTML, or manually pasted plain text,
// into an ordered list of {type:'heading'|'para', text} blocks so extract.js
// can attribute a matched clause to the section it appeared under ("Section
// if identifiable" per the Policy Intelligence spec).
//
// MV3 service workers have no DOM — no `document`, no `DOMParser` (verified:
// the service worker global scope exposes neither; this is why capture.js/
// classify.js never use one either). So HTML here is turned into text with
// regex, not a real parser. This is intentionally simple and will
// mis-segment unusual markup (heavy nested tables, JS-rendered content that
// never appears in the fetched HTML at all) — a known, documented limitation
// consistent with "do not aggressively crawl" and "keep it simple," not a
// silent claim of full HTML-parsing correctness.

const HEADING_TAGS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
const BLOCK_TAGS = ['p', 'div', 'li', 'tr', 'br', 'section', 'article', 'header', 'footer'];

const ENTITY_MAP = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“',
  mdash: '—', ndash: '–', hellip: '…',
};

function decodeEntities(str) {
  return str
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&([a-zA-Z]+);/g, (m, name) => ENTITY_MAP[name] ?? m);
}

// Real policy pages routinely prefix a heading with a decorative marker — a
// bullet glyph carried in the source text, a list marker, a dash, or an
// outline number. It is presentation, not part of the section's name, and it
// leaks straight into the UI ("Open at '• For Reader Surveys...'") and into
// the section label on every finding. Strip it once here so every consumer
// gets a clean name.
//
// Deliberately conservative about numbering: a leading "4." or "(b)" is
// removed, but a heading that *is* a number stays intact, and nothing is
// stripped if doing so would leave the heading empty.
const LEADING_MARKER = /^(?:[\u2022\u2023\u25AA\u25CF\u25E6\u00B7\u2043\u2219*\u2013\u2014-]+\s+|\(?\d{1,3}[.)]\s+|\(?[a-zA-Z][.)]\s+)/;

function cleanHeading(text) {
  let out = String(text ?? '').trim();
  // Loop so "• 4. Sharing" collapses fully, but bail rather than empty it out.
  for (let i = 0; i < 3; i++) {
    const next = out.replace(LEADING_MARKER, '').trim();
    if (!next || next === out) break;
    out = next;
  }
  return out.slice(0, 160);
}

// Pulls the anchor a reader could actually be sent to for this heading: the
// heading tag's own id/name, or an <a id>/<a name> nested directly inside it
// (a very common pattern in legal boilerplate, e.g.
// `<h2><a name="sharing"></a>Sharing</h2>`). Returns '' when there is none.
//
// This exists so a finding can deep-link to the *section* of a live policy
// document, not only to a quoted sentence — see policy/locate.js. Only
// characters valid in an HTML id are accepted, so a malformed attribute can
// never inject a delimiter into the sentinel or a fragment into a URL.
const SAFE_ID = /^[A-Za-z0-9\-_.:]{1,120}$/;

function anchorIdFrom(attrs, inner) {
  const fromAttrs = /\b(?:id|name)\s*=\s*["']([^"']+)["']/i.exec(attrs || '');
  if (fromAttrs && SAFE_ID.test(fromAttrs[1])) return fromAttrs[1];
  const fromAnchor = /<a\b[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']/i.exec(inner || '');
  if (fromAnchor && SAFE_ID.test(fromAnchor[1])) return fromAnchor[1];
  return '';
}

/**
 * @param {string} html
 * @param {number} [maxChars=400000] - hard cap so a huge/malformed page can't
 *   blow up processing time; truncation is honest, not silent (caller sees
 *   `truncated` in the returned meta via htmlToBlocks's second return value
 *   handled by policy-intel.js, not here — this function just enforces it).
 * @returns {{type:'heading'|'para', text:string, anchorId?:string|null}[]}
 */
export function htmlToBlocks(html, maxChars = 400000) {
  if (!html) return [];
  let src = html.length > maxChars ? html.slice(0, maxChars) : html;

  // Strip content that isn't page text at all.
  src = src.replace(/<!--[\s\S]*?-->/g, ' ');
  src = src.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  src = src.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  src = src.replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ');
  src = src.replace(/<nav[\s\S]*?<\/nav>/gi, ' '); // site nav text is not policy content

  // Mark headings with sentinels before stripping tags, so we can tell a
  // heading line apart from an ordinary paragraph once everything is plain
  // text.
  for (const tag of HEADING_TAGS) {
    const re = new RegExp(`<${tag}([^>]*)>([\\s\\S]*?)</${tag}>`, 'gi');
    src = src.replace(re, (_, attrs, inner) => `\nHEADING${anchorIdFrom(attrs, inner)}${inner}/HEADING\n`);
  }
  // Bold/strong text on its own short line is sometimes used as a heading in
  // simpler HTML (e.g. plain <p><strong>1. Information We Collect</strong></p>).
  // Only treated as a heading candidate later, based on length — marking it
  // here just preserves the option.
  src = src.replace(/<(strong|b)[^>]*>([\s\S]*?)<\/\1>/gi, (_, __, inner) => `STRONG${inner}/STRONG`);

  for (const tag of BLOCK_TAGS) {
    src = src.replace(new RegExp(`<${tag}[^>]*>`, 'gi'), '\n');
    src = src.replace(new RegExp(`</${tag}>`, 'gi'), '\n');
  }
  src = src.replace(/<\/?(ul|ol|table|thead|tbody)[^>]*>/gi, '\n');

  // Strip every remaining tag.
  src = src.replace(/<[^>]+>/g, '');
  src = decodeEntities(src);

  const lines = src.split('\n').map(l => l.replace(/[ \t ]+/g, ' ').trim()).filter(Boolean);

  const blocks = [];
  let paraBuf = [];
  const flushPara = () => {
    if (paraBuf.length) {
      blocks.push({ type: 'para', text: paraBuf.join(' ').trim() });
      paraBuf = [];
    }
  };

  for (let line of lines) {
    const headingMatch = line.match(/HEADING([\s\S]*?)([\s\S]*?)\/HEADING/);
    if (headingMatch) {
      flushPara();
      const anchorId = headingMatch[1] || null;
      const text = headingMatch[2].replace(/\/?STRONG/g, '').trim();
      if (text) { const clean = cleanHeading(text); if (clean) blocks.push({ type: 'heading', text: clean, anchorId }); }
      continue;
    }
    const strongMatch = line.match(/^STRONG([\s\S]*?)\/STRONG$/);
    if (strongMatch && strongMatch[1].trim().length > 0 && strongMatch[1].trim().length < 90) {
      flushPara();
      blocks.push({ type: 'heading', text: cleanHeading(strongMatch[1]), anchorId: null });
      continue;
    }
    // Any leftover sentinels inside a normal paragraph line (strong text
    // embedded mid-sentence, not a heading) — drop the markers, keep the text.
    line = line.replace(/\/?STRONG/g, '');
    paraBuf.push(line);
  }
  flushPara();

  return blocks.filter(b => b.text && b.text.length > 1);
}

// Heuristics for a manually pasted plain-text document (no HTML available).
// A line is treated as a heading when it's short, doesn't end mid-sentence,
// and looks structurally like a heading (numbered/lettered section, ALL
// CAPS, or Title Case standing alone between blank lines).
const HEADING_LIKE_RE = /^(\d+(\.\d+)*[.)]?\s+\S|[IVXLC]+[.)]\s+\S|section\s+\d|article\s+\d|part\s+\d|appendix\b)/i;

function looksLikeHeadingLine(line, isStandalone) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.length > 100) return false;
  if (/[.!?][")\]]?$/.test(trimmed) && trimmed.length > 40) return false; // long sentence-ending line
  if (HEADING_LIKE_RE.test(trimmed)) return true;
  const isAllCaps = trimmed === trimmed.toUpperCase() && /[A-Z]/.test(trimmed);
  if (isAllCaps && trimmed.length < 80) return true;
  if (isStandalone && trimmed.length < 70 && !trimmed.endsWith('.') && /^[A-Z0-9]/.test(trimmed)) return true;
  return false;
}

/**
 * @param {string} text - manually pasted policy text
 * @returns {{type:'heading'|'para', text:string}[]}
 */
export function plainTextToBlocks(text, maxChars = 400000) {
  if (!text) return [];
  const src = text.length > maxChars ? text.slice(0, maxChars) : text;
  const rawLines = src.split(/\r?\n/);

  const blocks = [];
  let paraBuf = [];
  const flushPara = () => {
    if (paraBuf.length) {
      blocks.push({ type: 'para', text: paraBuf.join(' ').trim() });
      paraBuf = [];
    }
  };

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i].trim();
    if (!line) { flushPara(); continue; }
    const prevBlank = i === 0 || !rawLines[i - 1].trim();
    const nextBlank = i === rawLines.length - 1 || !rawLines[i + 1]?.trim();
    if (looksLikeHeadingLine(line, prevBlank && nextBlank)) {
      flushPara();
      blocks.push({ type: 'heading', text: cleanHeading(line) });
      continue;
    }
    paraBuf.push(line);
  }
  flushPara();

  return blocks.filter(b => b.text && b.text.length > 1);
}
