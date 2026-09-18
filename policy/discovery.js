// Observa Policy Intelligence — policy/discovery.js
//
// Given the HTML of the page the user is already looking at, find obvious
// links to that same site's Privacy Policy, Terms of Use, and Cookie
// Policy. This does NOT fetch anything new by itself — it only scans HTML
// the caller already fetched (see background/policy-intel.js, which fetches
// the current tab's own page URL — content the user's browser already
// loaded — not a third-party site). Deliberately not a crawler: it looks at
// exactly one page (the one the user is on), prefers the footer where legal
// links conventionally live, and returns at most one link per document
// type. No recursion, no following of discovered links to search further.
//
// Same "no DOMParser in a service worker" constraint as textify.js — this
// uses regex over the raw HTML, not a real DOM. A site that renders its
// footer/legal links only via client-side JavaScript (a common pattern on
// JS-heavy single-page apps) will not be discoverable this way; that's a
// known, accepted gap for this version (manual paste/URL covers it) rather
// than a reason to add a content-script DOM scan, which would need the
// `scripting` permission Observa doesn't currently request.

const TYPE_KEYWORDS = {
  privacy: {
    hrefRe: /privacy[-_]?(policy|notice)?|privacidad|datenschutz/i,
    textRe: /privacy\s*(policy|notice|statement)?/i,
  },
  terms: {
    hrefRe: /terms[-_]?(of[-_]?(service|use)|and[-_]?conditions)?|\btos\b|conditions[-_]?of[-_]?use/i,
    textRe: /terms\s*(of\s*(service|use))?|terms\s*(and|&)\s*conditions/i,
  },
  cookie: {
    hrefRe: /cookie[-_]?(policy|notice|settings|preferences)?/i,
    textRe: /cookies?\s*(policy|notice|settings|preferences)?/i,
  },
};

// A small allowlist of common hosted-policy providers — sites frequently
// link out to one of these for their actual privacy/terms/cookie document
// rather than hosting it on their own domain. Cross-origin candidates are
// only accepted from this list; anything else cross-origin is skipped, to
// keep discovery scoped to "obvious, same-site or known-hosted" links, not
// an open-ended follow-anything crawl.
const KNOWN_POLICY_HOSTS = [
  'iubenda.com', 'termly.io', 'privacypolicies.com', 'trustarc.com',
  'onetrust.com', 'cookiebot.com', 'osano.com', 'termsfeed.com',
];

function extractAnchors(html) {
  const anchors = [];
  const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const text = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    anchors.push({ href: m[1], text });
    if (anchors.length > 4000) break; // hard cap — not a crawler, just a bound on one page's own link count
  }
  return anchors;
}

function extractFooterHtml(html) {
  // Last <footer>...</footer> if present (some pages have more than one
  // landmark named similarly; the last is usually the page-level footer).
  const matches = [...html.matchAll(/<footer\b[^>]*>([\s\S]*?)<\/footer>/gi)];
  if (matches.length) return matches[matches.length - 1][1];
  // Fallback: a generic footer-ish container by id/class, common outside
  // semantic <footer> markup.
  const idMatch = html.match(/<(?:div|section)[^>]*(?:id|class)=["'][^"']*footer[^"']*["'][^>]*>([\s\S]{0,20000}?)<\/(?:div|section)>/i);
  return idMatch ? idMatch[1] : null;
}

function sameEtld1(hostA, hostB) {
  // Cheap same-site check, good enough for a "prioritize" heuristic here —
  // the real eTLD+1 comparison (classify/classify.js) isn't imported into
  // this module to avoid a dependency for what's just a scoring hint, not a
  // security or party-classification decision.
  const parts = h => h.split('.').slice(-2).join('.');
  return parts(hostA) === parts(hostB);
}

function isAcceptableCrossOrigin(url) {
  return KNOWN_POLICY_HOSTS.some(host => url.hostname === host || url.hostname.endsWith('.' + host));
}

/**
 * Where else to look when the page the user is on yields no legal links.
 *
 * Logged-in application shells are the common case: mail.yahoo.com renders its
 * chrome in JavaScript, has no <footer> in the served HTML, and a fetch from
 * the service worker is unauthenticated anyway — so discovery finds nothing and
 * the whole Policy feature silently reports "no documents". The site's own
 * marketing root almost always carries the legal links the app shell does not.
 *
 * Deliberately bounded to at most two URLs on the SAME registrable domain, both
 * root paths. This is still not a crawler: no recursion, no guessing at policy
 * paths, no leaving the site.
 *
 * @param {string} pageUrl
 * @returns {string[]} absolute URLs, excluding pageUrl itself
 */
export function rootCandidatesFor(pageUrl) {
  let u;
  try { u = new URL(pageUrl); } catch { return []; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return [];

  // An IP literal has no registrable domain — slicing the last two labels off
  // 127.0.0.1 yields "0.1", which is not a host at all. Bracketed IPv6 is
  // likewise not something to take a root of.
  const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) || u.hostname.includes(':');
  if (isIpLiteral) return [];

  const parts = u.hostname.split('.');
  if (parts.length < 2) return [];
  const registrable = parts.slice(-2).join('.');

  // Keep any explicit port: dropping it would point the fallback at a
  // different server on the same host.
  const port = u.port ? `:${u.port}` : '';

  const out = [];
  for (const host of [registrable, `www.${registrable}`]) {
    const candidate = `${u.protocol}//${host}${port}/`;
    // Never re-fetch the page we already have in hand.
    if (host === u.hostname && (u.pathname === '/' || u.pathname === '')) continue;
    if (!out.includes(candidate)) out.push(candidate);
  }
  return out;
}

function classifyAnchor(anchor, pageUrl) {
  let url;
  try { url = new URL(anchor.href, pageUrl); } catch { return null; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  const pageHost = (() => { try { return new URL(pageUrl).hostname; } catch { return ''; } })();
  const sameSite = sameEtld1(url.hostname, pageHost);
  if (!sameSite && !isAcceptableCrossOrigin(url)) return null;

  for (const [type, kws] of Object.entries(TYPE_KEYWORDS)) {
    const hrefHit = kws.hrefRe.test(url.pathname) || kws.hrefRe.test(url.href);
    const textHit = anchor.text && kws.textRe.test(anchor.text);
    if (hrefHit || textHit) {
      return { type, url: url.href, linkText: anchor.text || null, strongMatch: hrefHit && textHit };
    }
  }
  return null;
}

/**
 * @param {string} html - the current page's own fetched HTML
 * @param {string} pageUrl - the current page's URL, for resolving relative links
 * @returns {Array<{type:'privacy'|'terms'|'cookie', url:string, linkText:string|null, confidence:'high'|'medium', foundIn:'footer'|'page'}>}
 */
export function discoverPolicyLinks(html, pageUrl) {
  if (!html || !pageUrl) return [];

  const footerHtml = extractFooterHtml(html);
  const results = new Map(); // type -> best candidate

  const consider = (anchors, foundIn) => {
    for (const anchor of anchors) {
      const hit = classifyAnchor(anchor, pageUrl);
      if (!hit) continue;
      const confidence = (foundIn === 'footer' || hit.strongMatch) ? 'high' : 'medium';
      const existing = results.get(hit.type);
      // Prefer: footer over page body, then strong (href+text) match over a
      // single-signal match, then keep the first one found (shortest
      // scan path, avoids flip-flopping on repeated near-identical links).
      if (!existing) {
        results.set(hit.type, { type: hit.type, url: hit.url, linkText: hit.linkText, confidence, foundIn });
      } else if (foundIn === 'footer' && existing.foundIn !== 'footer') {
        results.set(hit.type, { type: hit.type, url: hit.url, linkText: hit.linkText, confidence, foundIn });
      }
    }
  };

  if (footerHtml) consider(extractAnchors(footerHtml), 'footer');
  // Always also scan the whole page (cheap, same fetched HTML already in
  // memory) so a site without a semantic footer, or one whose legal links
  // sit elsewhere (a top nav, an "About" section), still gets found — footer
  // hits already recorded above simply won't be overwritten by a
  // lower-confidence page-wide hit for the same type.
  consider(extractAnchors(html), 'page');

  return [...results.values()];
}
