// WebLens dashboard — M4 + Story Mode + M5
// Fixes: removed live Anthropic API call, removed composite risk scores.
// Added: story mode toggle (Step 1) — plain-English page load narrative.
// M5: org-grouped bubble map, session history, opt-in settings panel.
// (The cross-site tracking heuristic that shipped briefly in M5 was removed
// — it tested as too confusing for the target user to act on.)

import { getEtld1 } from '../../classify/classify.js';
import { isBlockedError } from '../../shared/schema.js';
import { icon, CATEGORY_ICON_NAME } from '../icons.js';
import { applyStoredTheme, cycleTheme, setTheme } from '../theme.js';

const esc = s => s ? String(s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])) : '';

// ── Colours — same semantic hues in light and dark theme (see ui/theme.css);
// these mirror the CSS custom properties so Cytoscape (which needs literal
// color strings, not var()) and canvas drawing can use them directly. ──────
const CAT_CLR = {
  Advertising:   '#fb923c',
  Analytics:     '#60a5fa',
  Social:        '#a855f7',
  Fingerprinting:'#ec4899',
  Cryptomining:  '#ef4444',
  Content:       '#94a3b8',
  'Anti-fraud':  '#14b8a6',
  Consent:       '#eab308',
};
const C_FIRST='#4ade80', C_THIRD='#94a3b8', C_PAGE='#5b7cfa';

// Category icons — used in badges, legend, org cards. Pre-rendered as inline
// SVG strings (not emoji — see ui/icons.js) so every `${CAT_ICON[x]}`
// call site below picks this up automatically.
const CAT_ICON = Object.fromEntries(
  Object.entries(CATEGORY_ICON_NAME).map(([cat, name]) => [cat, icon(name, { size: 12 })])
);

// ── Static category explanations (Explained provenance) ──────────────────────
// No network calls. No API cost. Written once, reused for every session.
// Provenance: EXPLAINED — human-authored descriptions of known service categories.
const CATEGORY_EXPLANATIONS = {
  Advertising:
    'This domain belongs to an advertising network. It tracks which pages you visit across many websites to build a profile of your interests, then uses that profile to decide which ads to show you. It typically collects your browsing history, rough location, and device information.',
  Analytics:
    'This is an analytics service that helps the website owner understand how visitors use their site — things like which pages are popular, how long people stay, and where they click. It reports your behaviour on this page to a third party, not just to the site you\'re visiting.',
  Social:
    'This domain is owned by a social media platform. Even if you don\'t click any social buttons, the presence of this service lets the platform know you visited this page. If you\'re logged into that platform in another tab, it may be able to link this visit to your account.',
  Fingerprinting:
    'This service collects technical details about your browser and device — things like screen size, installed fonts, and graphics capabilities — to create a unique fingerprint that can identify you without using cookies. Fingerprints are harder to clear than cookies.',
  Cryptomining:
    'This script uses your computer\'s processing power to generate cryptocurrency for someone else. This happens in the background without your permission and will slow down your browser and increase your electricity use.',
  Content:
    'This domain delivers content that the website depends on — things like fonts, images, videos, or shared code libraries. It is typically a CDN (content delivery network) used to load resources faster. While usually benign, the server can still log your IP address and browser details.',
  'Anti-fraud':
    'This service helps the website detect bots, prevent account takeovers, and spot fraudulent transactions. It analyses patterns in how you interact with the page. The data it collects stays within a security context but does pass through a third-party system.',
  Consent:
    'This service manages cookie consent banners and records your privacy choices. It communicates your preferences to the other services on the page. Your consent selections may be stored and shared with advertising partners.',
};

const PARTY_EXPLANATIONS = {
  'first-party':
    'This domain is owned and operated by the same organisation as the website you\'re visiting. Requests to first-party domains are normal and expected — they deliver the page content itself.',
  'third-party':
    'This is a third-party domain — a separate company whose service has been embedded into this website. The website owner chose to include it, but it operates under its own privacy policy and may collect data independently.',
  unknown:
    'The relationship between this domain and the website you\'re visiting could not be determined.',
};

function getExplanation(category, organization, party, resourceTypes) {
  if (category && CATEGORY_EXPLANATIONS[category]) return CATEGORY_EXPLANATIONS[category];
  // Infer from resource types for unclassified domains
  if (party === 'third-party' && resourceTypes?.length) {
    if (resourceTypes.includes('font')) return 'This domain delivers web fonts to the page. Font CDNs can log your IP address and browser when the font is requested, but are not typically used for behavioural tracking.';
    if (resourceTypes.includes('media')) return 'This domain serves audio or video content. The media server can log your IP address and the content you played.';
    if (resourceTypes.includes('stylesheet')) return 'This domain delivers CSS stylesheets. Style resources are not typically used for tracking but the server can log your visit.';
    if (resourceTypes.includes('script')) return 'This is an unclassified third-party script. Scripts run with full access to the page and can read content, keystrokes, and behaviour — but this domain was not matched in the tracker list.';
    if (resourceTypes.includes('xmlhttprequest')) return 'This domain receives data sent in the background by the page. The content of these requests is not visible to WebLens.';
    if (resourceTypes.includes('image')) return 'This domain serves images, which may include invisible tracking pixels used to confirm the page was loaded.';
  }
  return PARTY_EXPLANATIONS[party] ?? PARTY_EXPLANATIONS.unknown;
}

// ── Flags engine (replaces risk scoring) ─────────────────────────────────────
// Provenance: INFERRED for cookie flags, CLASSIFIED for category flags.
// No composite level/score is produced — CONTEXT.md prohibits risk ratings.
function assessFlags(nodeData, cookies) {
  const flags = [];
  const tips  = [];
  const cat   = nodeData.category;
  const party = nodeData.party;

  // M5: nodeData.domain may now be an organization label (bubble-map
  // grouping), not a real hostname — cookie matching must check against
  // every real eTLD+1 folded into this bubble. (Shared with the exposure
  // aggregation below via cookiesForDomainEntry, v0.12.0 — same logic,
  // one place.)
  const domCookies = cookiesForDomainEntry(nodeData, cookies);

  if (cat === 'Fingerprinting') {
    flags.push({ icon:icon('search',{size:13}), text:'Browser fingerprinter — can identify you without cookies' });
    tips.push('Use Firefox with Enhanced Tracking Protection, or Brave, which blocks fingerprinting by default.');
    tips.push('Privacy Badger or uBlock Origin in advanced mode can block fingerprinting scripts.');
  }
  if (cat === 'Cryptomining') {
    flags.push({ icon:icon('zap',{size:13}), text:'Cryptocurrency miner — uses your CPU for mining' });
    tips.push('Install uBlock Origin and enable the "Malware domains" filter list.');
    tips.push('Consider reporting the site — cryptomining without consent may violate laws in your region.');
  }
  if (cat === 'Advertising' && party === 'third-party') {
    flags.push({ icon:icon('megaphone',{size:13}), text:'Third-party ad tracker — follows you across websites' });
    tips.push('uBlock Origin blocks most ad trackers by default.');
    tips.push('Opt out via the Global Privacy Control (GPC) browser signal — Firefox and Brave support it natively.');
  }
  if (cat === 'Analytics' && party === 'third-party') {
    flags.push({ icon:icon('bar-chart',{size:13}), text:'Third-party analytics — reports your behaviour to a third party' });
    tips.push('Privacy Badger automatically learns and blocks tracking analytics.');
  }
  if (cat === 'Social') {
    flags.push({ icon:icon('user',{size:13}), text:'Social widget — can track you even if you\'re not logged in' });
    tips.push('Facebook Container (Firefox) isolates Facebook tracking to a separate container.');
  }

  const longLived = domCookies.filter(c => c.longLived);
  if (longLived.length > 0) {
    flags.push({ icon:icon('clock',{size:13}), text:`${longLived.length} long-lived cookie${longLived.length>1?'s':''} — persists for more than 90 days` });
    tips.push('Clear cookies periodically via Settings → Privacy → Clear browsing data.');
  }

  const sameNone = domCookies.filter(c => c.sameSite === 'no_restriction');
  if (sameNone.length > 0) {
    flags.push({ icon:icon('globe',{size:13}), text:`${sameNone.length} cross-site cookie${sameNone.length>1?'s':''} — can be sent on any request to this domain` });
    tips.push('Cross-site cookies enable cross-site tracking. Blocking third-party cookies in browser settings limits this.');
  }

  const noHttpOnly = domCookies.filter(c => !c.httpOnly && !c.session);
  if (noHttpOnly.length > 0 && cat) {
    flags.push({ icon:icon('file-text',{size:13}), text:`${noHttpOnly.length} cookie${noHttpOnly.length>1?'s':''} readable by page scripts — not protected by HttpOnly` });
  }

  if (flags.length > 0 && tips.length === 0)
    tips.push('Consider using a privacy-focused browser extension like uBlock Origin to limit tracking.');

  return { flags, tips, domCookies };
}

// ── Story mode ────────────────────────────────────────────────────────────────
// Provenance: EXPLAINED — templated narrative over OBSERVED/CLASSIFIED data.
// No live AI generation. All sentences are static templates filled with counts.

const CAT_LABELS = {
  Advertising: 'advertising networks',
  Analytics: 'analytics services',
  Social: 'social media platforms',
  Fingerprinting: 'browser fingerprinters',
  Cryptomining: 'cryptocurrency miners',
  Content: 'content delivery networks',
  'Anti-fraud': 'anti-fraud services',
  Consent: 'consent management platforms',
};

function buildStory(session, cookies) {
  const reqs = session.requests ?? [];
  if (!reqs.length) return '<p style="color:var(--muted)">No requests captured for this session.</p>';

  const pageHost = (() => { try { return new URL(session.pageUrl).hostname; } catch { return session.pageUrl; } })();
  const totalMs  = reqs.length > 1
    ? Math.round(Math.max(...reqs.map(r=>r.timestamp)) - Math.min(...reqs.map(r=>r.timestamp)))
    : 0;

  // Domain map
  const domMap = new Map();
  for (const r of reqs) {
    const key = r.etld1 || r.domain;
    if (!domMap.has(key)) domMap.set(key, { ...r, requests: [] });
    domMap.get(key).requests.push(r);
  }
  const domains    = [...domMap.values()];
  const thirdParty = domains.filter(d => d.party === 'third-party');
  const firstParty = domains.filter(d => d.party === 'first-party');

  // Category buckets
  const catMap = new Map();
  for (const d of thirdParty) {
    if (!d.category) continue;
    if (!catMap.has(d.category)) catMap.set(d.category, []);
    catMap.get(d.category).push(d);
  }

  // Cookie summary
  const longLivedCookies  = cookies.filter(c => c.longLived);
  const crossSiteCookies  = cookies.filter(c => c.sameSite === 'no_restriction');
  const sessionCookiesArr = cookies.filter(c => c.session);

  const sentences = [];

  // Opening — what happened and how fast
  if (totalMs > 0) {
    sentences.push(`When you opened <strong>${esc(pageHost)}</strong>, your browser made <strong>${reqs.length} network request${reqs.length===1?'':'s'}</strong> over <strong>${totalMs.toLocaleString()}ms</strong> to load the page.`);
  } else {
    sentences.push(`When you opened <strong>${esc(pageHost)}</strong>, your browser made <strong>${reqs.length} network request${reqs.length===1?'':'s'}</strong> to load the page.`);
  }

  // First vs third party split
  if (thirdParty.length === 0) {
    sentences.push(`All ${firstParty.length} domain${firstParty.length===1?'':'s'} contacted belong to ${esc(pageHost)} — no third-party services were detected.`);
  } else {
    sentences.push(`Of the <strong>${domains.length} domain${domains.length===1?'':'s'}</strong> contacted, <strong>${thirdParty.length}</strong> ${thirdParty.length===1?'is':'are'} third-party — meaning they belong to companies other than ${esc(pageHost)}.`);
  }

  // Category breakdown
  if (catMap.size > 0) {
    const catParts = [...catMap.entries()]
      .sort((a,b) => b[1].length - a[1].length)
      .map(([cat, ds]) => `<strong>${ds.length}</strong> ${CAT_LABELS[cat] ?? cat.toLowerCase()}`);

    const joined = catParts.length === 1
      ? catParts[0]
      : catParts.slice(0,-1).join(', ') + ' and ' + catParts[catParts.length-1];
    sentences.push(`Among those third parties, WebLens identified ${joined}.`);
  }

  // Advertising callout
  const adDomains = catMap.get('Advertising') ?? [];
  if (adDomains.length > 0) {
    const orgs = [...new Set(adDomains.map(d=>d.organization).filter(Boolean))];
    if (orgs.length > 0) {
      const orgList = orgs.slice(0,3).map(o=>`<strong>${esc(o)}</strong>`).join(', ');
      const more = orgs.length > 3 ? ` and ${orgs.length-3} more` : '';
      sentences.push(`The advertising services include ${orgList}${more} — these can track your browsing history across multiple websites to build an advertising profile.`);
    }
  }

  // Fingerprinting callout
  const fpDomains = catMap.get('Fingerprinting') ?? [];
  if (fpDomains.length > 0) {
    sentences.push(`⚠️ <strong>${fpDomains.length} fingerprinting service${fpDomains.length===1?'':'s'}</strong> ${fpDomains.length===1?'was':'were'} detected. Unlike cookies, fingerprinting can identify you even after you clear your browser history.`);
  }

  // Cryptomining callout
  const cmDomains = catMap.get('Cryptomining') ?? [];
  if (cmDomains.length > 0) {
    sentences.push(`⚠️ <strong>${cmDomains.length} cryptocurrency miner${cmDomains.length===1?'':'s'}</strong> ${cmDomains.length===1?'was':'were'} detected. This uses your device's processing power without your permission.`);
  }

  // Cookies
  if (cookies.length > 0) {
    let cookieLine = `This page set <strong>${cookies.length} cookie${cookies.length===1?'':'s'}</strong>`;
    const parts = [];
    if (longLivedCookies.length)  parts.push(`${longLivedCookies.length} lasting more than 90 days`);
    if (crossSiteCookies.length)  parts.push(`${crossSiteCookies.length} that can follow you across other sites`);
    if (sessionCookiesArr.length) parts.push(`${sessionCookiesArr.length} that clear when your browser closes`);
    if (parts.length) cookieLine += ` — including ${parts.join(', ')}`;
    cookieLine += '.';
    sentences.push(cookieLine);
  } else {
    sentences.push('No cookies were detected for this page in the current browser session.');
  }

  // Closing honest caveat
  sentences.push(`<em style="opacity:.55;font-size:10px">Note: only requests made after the extension was active are shown. Some requests in the first moments of the page load may not appear. Server-to-server data sharing is not observable.</em>`);

  return sentences.map(s => `<p style="margin:0 0 10px;line-height:1.65">${s}</p>`).join('');
}

// ── State ─────────────────────────────────────────────────────────────────────
let cy = null, sessionCookies = [], allSessions = [], _currentDomainMap = new Map();
let storyVisible = false;
// M5 — opt-in settings (history only; the cross-site heuristic was removed).
let weblensSettings = { historyEnabled: false, listRefreshEnabled: true }; // placeholder until the real chrome.storage-backed settings load (see line ~2173); mirrors settings.js's DEFAULTS
// M6 — Verify & Protect: real domains currently blocked on the loaded
// session's site, and that site's eTLD+1.
let blockedForSite = new Set();
let _currentSiteEtld1 = null;
let _detailNodeData = null;

// ── Helpers ───────────────────────────────────────────────────────────────────
const hostOf = url => { try { return new URL(url).hostname; } catch { return url||'unknown'; } };

// M5 — group by owning organization when known, falling back to eTLD+1.
// Without this, one company's multiple domains (doubleclick.net,
// google-analytics.com, googletagmanager.com — all Google) render as
// separate bubbles even though the Organizations tab already merges them.
//
// `domain` stays the human-readable label shown in the UI (org name when
// grouped, else the eTLD+1). `etld1s` carries every real eTLD+1 folded into
// the bubble — that's what cookie-matching and other domain-identity checks
// must use instead of the (possibly org-name) `domain` field.
function buildDomainMap(session) {
  const map = new Map();
  for (const req of session.requests) {
    const reqEtld1 = req.etld1 || req.domain;
    const groupKey = req.organization ? `org:${req.organization}` : `dom:${reqEtld1}`;

    if (!map.has(groupKey)) {
      map.set(groupKey, {
        domain: req.organization || reqEtld1,   // display label
        etld1: reqEtld1,                         // representative eTLD+1 (first seen)
        etld1s: new Set(),                       // ALL real eTLD+1s in this bubble
        rawDomain: req.domain,
        requests: [],
        party: req.party,
        category: req.category,
        organization: req.organization,
        provenance: req.provenance,
      });
    }
    const entry = map.get(groupKey);
    entry.etld1s.add(reqEtld1);
    // Update category/org if this request has more info
    if (!entry.category && req.category) { entry.category = req.category; entry.organization = req.organization; }
    entry.requests.push(req);
  }
  return map;
}

// ── Sessions ──────────────────────────────────────────────────────────────────
async function loadAllSessions() {
  const tabIds = await chrome.runtime.sendMessage({ type:'weblens:getSessions' });
  if (!tabIds?.length) return [];
  const out = [];
  for (const tabId of tabIds) {
    const s = await chrome.runtime.sendMessage({ type:'weblens:getSession', tabId });
    if (!s || s.error) continue;
    if (s.pageUrl?.startsWith('chrome')) continue;
    // Also skip a session still stuck at "about:blank" — the pre-existing,
    // documented Playwright-only artifact (see CONTEXT.md's "Known testing
    // limitations"): opening the dashboard/popup itself via page.goto()
    // commits an about:blank navigation first, which session.js normally
    // corrects once the real URL lands. A tab that's never had that
    // correction land isn't a real visited page — most commonly the
    // dashboard/popup's own tab (whose only "requests" are its own asset
    // fetches, e.g. the Field Report webfont link, not anything the user
    // browsed to). Filtering it out here keeps the auto-selected "best"
    // session below from ever picking that noise over a real session.
    if (!s.pageUrl || s.pageUrl === 'about:blank') continue;
    out.push({ tabId, session:s });
  }
  return out.sort((a,b) => b.session.startedAt - a.session.startedAt);
}

function populateSessions(sessions) {
  document.getElementById('sessionSelect').innerHTML = sessions.map((s,i) =>
    `<option value="${i}">${hostOf(s.session.pageUrl)} (${s.session.requests?.length??0} reqs)</option>`
  ).join('');
}

// ── Graph ──────────────────────────────────────────────────────────────────────
function buildElements(session) {
  const map = buildDomainMap(session);
  const pageHost = hostOf(session.pageUrl);
  const nodes = [], edges = [];

  nodes.push({ data:{ id:'__page__', label:pageHost, type:'page', color:C_PAGE, size:52,
    domain:pageHost, party:'first-party', category:null, organization:null,
    provenance:'Observed', requests:[] }});

  for (const [key, info] of map) {
    const n = info.requests.length;
    const size = Math.round(20 + Math.log1p(n) * 9);
    const baseColor = info.category ? (CAT_CLR[info.category]??C_THIRD)
      : (info.party==='first-party' ? C_FIRST : C_THIRD);

    // Data Exposure Detector findings, at a glance — previously only visible
    // after opening a node's detail panel; a domain with something detected
    // now also gets a marker on the node itself and in its hover tooltip.
    // Combines request-based findings with (v0.12.0) cookie-value findings,
    // using the module-level sessionCookies populated by loadSession()
    // before buildElements() is called on each session load.
    const exposures = combinedExposuresForEntry(info, sessionCookies);
    const personalTypes = new Set(['email', 'phone', 'geo', 'zip']);
    const hasPersonalExposure = exposures.some(e => personalTypes.has(e.type));
    const exposureSeverity = exposures.length ? (hasPersonalExposure ? 'high' : 'medium') : '';
    const exposureTypes = [...new Set(exposures.map(e => e.type).filter(t => t !== 'page'))]
      .map(t => EXPOSURE_TYPE_LABEL[t] ?? t);

    nodes.push({ data:{ id:key, label:info.domain, type:info.party, color:baseColor, size,
      domain:info.domain, etld1:info.etld1, etld1s:[...info.etld1s], party:info.party,
      category:info.category, organization:info.organization, provenance:info.provenance,
      requests:info.requests, exposureSeverity, exposureTypes }});
    edges.push({ data:{ id:`e-${key}`, source:'__page__', target:key, count:n }});
  }
  return { nodes, edges, domainMap:map };
}

// Reads a resolved theme color off <html> at call time — Cytoscape's style
// engine takes literal color strings, not CSS custom properties, so graph
// colors that need to track the active theme (ink, paper) are read via
// getComputedStyle rather than duplicated as separate hex constants here.
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

let _lastGraphElements = null;

function initGraph({ nodes, edges }) {
  if (cy) { cy.destroy(); cy = null; }
  _lastGraphElements = { nodes, edges };

  const ink    = cssVar('--text') || '#2a2621';
  const paper  = cssVar('--surface1') || '#fffdf9';
  const accent = cssVar('--accent') || '#a8501f';
  const textRgb = cssVar('--text-rgb') || '42,38,33';

  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: { nodes, edges },
    style: [
      // ── Base node — thin ring, category-tinted fill at reduced opacity,
      // label always visible next to the node in the small sans body font
      // (the same --font-sans pairing the rest of the page uses). ────────
      { selector:'node', style:{
        'background-color':          'data(color)',
        'background-opacity':        0.22,
        'label':                     'data(label)',
        'width':                     'data(size)',
        'height':                    'data(size)',
        'font-size':                 '10px',
        'font-family':               'Public Sans,-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif',
        'font-weight':               '600',
        'color':                     ink,
        'text-opacity':              0.85,
        'text-valign':               'bottom',
        'text-halign':               'center',
        'text-margin-y':             '7px',
        'text-max-width':            '90px',
        'text-wrap':                 'ellipsis',
        'text-background-color':     paper,
        'text-background-opacity':   0.75,
        'text-background-padding':   '2px',
        'text-background-shape':     'round-rectangle',
        'border-width':              1.4,
        'border-color':              'data(color)',
        'border-opacity':            0.9,
        'shadow-opacity':            0,
        'transition-property':       'opacity,border-width,border-color,border-opacity,text-opacity,background-opacity',
        'transition-duration':       '180ms',
      }},
      // ── Tracker vs. unclassified — the popup/hero "N trackers" count means
      // "matched a known tracker list" (provenance === 'Classified'), which
      // includes every category, not just Advertising/Fingerprinting. Before
      // this, a classified and an unclassified node looked almost identical
      // (same low fill opacity, color was the only cue) — no way to tell
      // which of the N nodes were the counted trackers without opening each
      // one's detail panel. Classified nodes now render visibly solid;
      // unclassified nodes stay light/hollow, so the count is legible on
      // the graph itself. See also the legend note in dashboard.html. ─────
      { selector:'node[provenance = "Classified"]', style:{
        'background-opacity': 0.55,
        'border-width':       1.8,
      }},
      { selector:'node[provenance = "Observed"]', style:{
        'background-opacity': 0.1,
        'border-opacity':     0.55,
      }},
      // ── Page node (center) — plain paper fill with a bold dark ink ring,
      // not a gradient/glow. ─────────────────────────────────────────────
      { selector:'node[type="page"]', style:{
        'shape':              'round-rectangle',
        'background-color':   paper,
        'background-opacity': 1,
        'font-weight':        '700',
        'font-size':          '11px',
        'color':              ink,
        'text-opacity':       1,
        'text-margin-y':      '9px',
        'text-background-opacity': 0.75,
        'border-width':       2.5,
        'border-color':       ink,
        'border-opacity':     0.85,
        'shadow-opacity':     0,
      }},
      // ── Data exposure marker ──────────────────────────────────────────
      // A domain whose requests tripped the Data Exposure Detector gets a
      // dashed ring so it's visible without opening the detail panel —
      // red for personal-data-shaped matches (email/phone/geo/zip), amber
      // for tracking-identifier-only matches. Selection/hover styles below
      // still take precedence since they're declared after this.
      { selector:'node[exposureSeverity = "high"]', style:{
        'border-width':       3,
        'border-color':       'rgb(248,113,113)',
        'border-opacity':     0.9,
        'border-style':       'dashed',
      }},
      { selector:'node[exposureSeverity = "medium"]', style:{
        'border-width':       2.5,
        'border-color':       'rgb(251,146,60)',
        'border-opacity':     0.85,
        'border-style':       'dashed',
      }},
      // ── Selected ───────────────────────────────────────────────────────
      { selector:'node:selected', style:{
        'border-width':       2.5,
        'border-color':       accent,
        'border-opacity':     1,
        'shadow-opacity':     0,
        'text-opacity':       1,
        'color':              ink,
        'text-background-opacity': 0.85,
        'background-opacity': 0.4,
      }},
      // ── Hover highlight ────────────────────────────────────────────────
      { selector:'node.hl', style:{
        'border-width':       2,
        'border-color':       accent,
        'border-opacity':     0.8,
        'shadow-opacity':     0,
        'text-opacity':       1,
        'color':              ink,
        'text-background-opacity': 0.8,
        'background-opacity': 0.34,
      }},
      // ── Faded ─────────────────────────────────────────────────────────
      { selector:'node.faded', style:{
        'opacity':            0.1,
        'shadow-opacity':     0,
      }},
      // ── Search states ─────────────────────────────────────────────────
      { selector:'node.search-match', style:{
        'border-width':       2.5,
        'border-color':       accent,
        'border-opacity':     1,
        'shadow-opacity':     0,
        'text-opacity':       1,
        'color':              ink,
        'text-background-opacity': 0.85,
        'background-opacity': 0.4,
      }},
      { selector:'node.search-dim', style:{ 'opacity':0.1, 'shadow-opacity':0 }},
      // ── Edges — thin lines, ink-tinted rather than the old blue. Opacity
      // bumped from an earlier 0.16 (functionally invisible against the
      // light theme's warm-paper background — a real bug, not a style
      // choice: 16% ink on #faf7f2 falls under most displays' visible
      // threshold at 0.9px width) to a value readable in both themes. ────
      { selector:'edge', style:{
        'width':              1,
        'line-color':         `rgba(${textRgb},0.38)`,
        'curve-style':        'bezier',
        'line-style':         'solid',
        'target-arrow-shape': 'none',
        'transition-property':'opacity,width,line-color',
        'transition-duration':'180ms',
      }},
      { selector:'edge.faded', style:{ 'opacity':0.02 }},
      { selector:'edge.hl', style:{
        'line-color':         accent,
        'width':              1.3,
        'opacity':            0.7,
      }},
    ],
    layout:{
      name:            'cose',
      animate:         true,
      animationDuration: 1100,
      animationEasing: 'ease-out-cubic',
      // Nodes carry an always-visible label now (Field Report redesign —
      // labels used to only show on hover/select), so they need more room
      // than the old hover-only layout did to avoid overlapping text.
      nodeRepulsion:   () => 90000,
      idealEdgeLength: () => 260,
      edgeElasticity:  () => 60,
      gravity:         0.05,
      numIter:         2500,
      fit:             true,
      padding:         90,
      randomize:       true,
      componentSpacing: 120,
      nodeOverlap:     40,
    },
    userZoomingEnabled:  true,
    userPanningEnabled:  true,
    boxSelectionEnabled: false,
    minZoom: 0.15,
    maxZoom: 5,
  });

  const tooltip = document.getElementById('tooltip');

  cy.on('mouseover', 'node', evt => {
    const d = evt.target.data();
    cy.batch(() => {
      cy.elements().addClass('faded').removeClass('hl');
      evt.target.removeClass('faded').addClass('hl');
      evt.target.connectedEdges().removeClass('faded').addClass('hl');
      cy.$('#__page__').removeClass('faded');
    });
    if (d.id === '__page__') return;
    const ttIcon = CAT_ICON[d.category] ?? '';
    const categoryLabel = d.category || (d.party === 'first-party' ? 'First party' : 'Third party');
    const exposureLine = d.exposureSeverity
      ? `<div class="tt-exposure tt-exposure-${esc(d.exposureSeverity)}">${icon(d.exposureSeverity === 'high' ? 'alert-triangle' : 'search', { size:11 })} ${esc((d.exposureTypes||[]).join(', '))}</div>`
      : '';
    tooltip.innerHTML = `
      <div class="tt-domain">${esc(d.domain)}</div>
      ${d.organization ? `<div class="tt-org">${esc(d.organization)}</div>` : ''}
      <div class="tt-reqs">${d.requests?.length??0} request${(d.requests?.length??0)===1?'':'s'} · ${ttIcon} ${esc(categoryLabel)}</div>
      ${exposureLine}`;
    tooltip.classList.add('show');
  });

  cy.on('mousemove', evt => {
    if (!tooltip.classList.contains('show')) return;
    const wrap = document.getElementById('cy-wrap');
    const pos = evt.renderedPosition;
    let x = pos.x + 16, y = pos.y - 12;
    if (x + 220 > wrap.clientWidth)  x = pos.x - 230;
    if (y + 100 > wrap.clientHeight) y = pos.y - 110;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
  });

  cy.on('mouseout', 'node', () => {
    cy.elements().removeClass('faded hl');
    tooltip.classList.remove('show');
  });

  cy.on('tap', 'node', evt => {
    const d = evt.target.data();
    if (d.id === '__page__') { showEmpty(); return; }
    renderDetail(d);
  });
  cy.on('tap', evt => { if (evt.target === cy) showEmpty(); });
  return cy;
}

// ── Category tally footer strip (v0.13.0) ─────────────────────────────────
// A per-category count built from the exact same domainMap grouping the
// graph/table/legend already use — no separate counting logic invented,
// just a small tally over the same real data. Unclassified third-party and
// first-party domains are folded in too, using the same colors the legend
// already uses for those buckets.
function buildCategoryTally(domainMap) {
  const counts = new Map();
  for (const info of domainMap.values()) {
    const label = info.category || (info.party === 'first-party' ? 'First party' : 'Unclassified');
    const color = info.category ? (CAT_CLR[info.category] ?? C_THIRD)
      : (info.party === 'first-party' ? C_FIRST : C_THIRD);
    if (!counts.has(label)) counts.set(label, { label, color, count: 0 });
    counts.get(label).count++;
  }
  return [...counts.values()].sort((a, b) => b.count - a.count);
}

function renderCategoryTally(domainMap) {
  const el = document.getElementById('categoryTally');
  if (!el) return;
  const tally = buildCategoryTally(domainMap);
  el.innerHTML = tally.map(t =>
    `<span class="ct-item"><span class="ct-sq" style="background:${t.color}"></span>${esc(t.label)} · ${t.count}</span>`
  ).join('');
}

// ── Legend ────────────────────────────────────────────────────────────────────
function buildLegend(domainMap) {
  const cats = new Set(), hasFirst = { v:false }, hasThird = { v:false };
  for (const d of domainMap.values()) {
    if (d.category) cats.add(d.category);
    else if (d.party === 'first-party') hasFirst.v = true;
    else hasThird.v = true;
  }
  // The colored dot already carries the category identity — the legend
  // doesn't need a second emoji glyph doing the same job.
  const items = [...cats].map(c => ({ label:c, color:CAT_CLR[c]??C_THIRD }));
  if (hasFirst.v) items.push({ label:'First party', color:C_FIRST });
  if (hasThird.v) items.push({ label:'Unclassified', color:C_THIRD });
  const CAT_TIPS = {
    Advertising:'Tracks your browsing to build ad profiles', Analytics:'Measures visitor behaviour for the site owner',
    Social:'Social media tracking widgets', Fingerprinting:'Identifies your browser without cookies',
    Cryptomining:'Uses your CPU to mine cryptocurrency', Content:'Fonts, images, and CDN resources',
    'Anti-fraud':'Bot detection and fraud prevention', Consent:'Cookie consent management',
    'First party':'Owned by the site you are visiting', Unclassified:'Third-party domain not matched in tracker list',
  };
  document.getElementById('legend').innerHTML = items.map(i =>
    `<div class="lpill" title="${esc(CAT_TIPS[i.label]??i.label)}"><div class="ldot" style="background:${i.color}"></div>${esc(i.label)}</div>`
  ).join('');
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function renderTimeline(session) {
  const canvas = document.getElementById('tl-canvas');
  const wrap   = document.getElementById('timeline-wrap');
  const W = wrap.clientWidth, H = wrap.clientHeight;
  canvas.width = W * devicePixelRatio; canvas.height = H * devicePixelRatio;
  canvas.style.width = W+'px'; canvas.style.height = H+'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(devicePixelRatio, devicePixelRatio);

  const reqs = session.requests.filter(r => r.timestamp);
  if (!reqs.length) return;
  const t0 = Math.min(...reqs.map(r=>r.timestamp));
  const t1 = Math.max(...reqs.map(r=>r.timestamp));
  const span = Math.max(t1-t0,1);
  const PL=8,PR=8,PT=18,PB=8;
  const dW=W-PL-PR, dH=H-PT-PB;

  const ticks = Math.min(8, Math.floor(dW/70));
  ctx.strokeStyle='rgba(99,120,200,0.12)'; ctx.lineWidth=1;
  ctx.fillStyle='rgba(55,65,81,0.45)'; ctx.font='8px system-ui'; ctx.textAlign='center';
  for (let i=0;i<=ticks;i++) {
    const x = PL + dW*i/ticks;
    ctx.beginPath(); ctx.moveTo(x,PT); ctx.lineTo(x,PT+dH); ctx.stroke();
    ctx.fillText(`${Math.round(span*i/ticks)}ms`, x, PT+dH+8);
  }

  const baseY = PT + dH*0.55;
  ctx.beginPath(); ctx.moveTo(PL,baseY); ctx.lineTo(PL+dW,baseY);
  ctx.strokeStyle='rgba(99,120,200,0.18)'; ctx.lineWidth=1; ctx.stroke();

  const BUCKETS = Math.max(1, Math.min(reqs.length, Math.floor(dW/7)));
  const buckets = new Map();
  for (const req of reqs) {
    const b = Math.round(((req.timestamp-t0)/span)*BUCKETS);
    if (!buckets.has(b)) buckets.set(b,[]);
    buckets.get(b).push(req);
  }
  for (const [b, group] of buckets) {
    const x = PL + (b/BUCKETS)*dW;
    group.forEach((req, i) => {
      const color = req.category ? (CAT_CLR[req.category]??C_THIRD)
        : (req.party==='first-party' ? C_FIRST : C_THIRD);
      const r = req.type==='script'||req.type==='xmlhttprequest' ? 5 : 3.5;
      const y = baseY - i*(r*2+2);
      ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
      ctx.fillStyle=color+'dd'; ctx.fill();
      ctx.strokeStyle='rgba(7,9,15,0.7)'; ctx.lineWidth=0.8; ctx.stroke();
    });
  }
}

// ── Collapsible section helper ────────────────────────────────────────────────
function makeSection(id, title, countBadge, bodyHtml, openByDefault=true) {
  return `<div class="dsec${openByDefault?' open':''}" id="sec-${id}">
    <div class="dsec-hd">
      <span class="dsec-title">
        ${title}
        ${countBadge!=null?`<span class="dsec-title-count">${countBadge}</span>`:''}
      </span>
      <span class="dsec-arrow">▶</span>
    </div>
    <div class="dsec-body">${bodyHtml}</div>
  </div>`;
}

// ── Detail: empty state ───────────────────────────────────────────────────────
function showEmpty() {
  document.getElementById('detail').innerHTML = `
    <div class="detail-empty">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
        <circle cx="12" cy="12" r="3"/>
        <circle cx="4" cy="6" r="2"/><circle cx="20" cy="6" r="2"/>
        <circle cx="4" cy="18" r="2"/><circle cx="20" cy="18" r="2"/>
        <line x1="6" y1="6" x2="10" y2="11"/><line x1="18" y1="6" x2="14" y2="11"/>
        <line x1="6" y1="18" x2="10" y2="13"/><line x1="18" y1="18" x2="14" y2="13"/>
      </svg>
      <span>Click any node to explore</span>
      <div class="detail-empty-hint">
        See what each domain does, what data it collects, and how to protect yourself.
      </div>
    </div>`;
}

// ── Cookie description helper ─────────────────────────────────────────────────
function cookieDescription(name, flags, expiry) {
  const lname = name.toLowerCase();
  let what = '';
  if (lname.includes('_ga') || lname.includes('_gid'))
    what = 'Google Analytics identifier — tracks visits and sessions across this site.';
  else if (lname.includes('_fbp') || lname.includes('_fbc'))
    what = 'Facebook Pixel identifier — used to track conversions and build ad audiences.';
  else if (lname.includes('optimizely'))
    what = 'Optimizely A/B test assignment — records which variant of a page experiment you\'re in.';
  else if (lname.includes('_pcid') || lname.includes('pa_vid'))
    what = 'Piano/Tinypass user identifier — tracks your paywall or subscription status.';
  else if (lname.includes('ckns'))
    what = 'BBC cookie notice state — records what you consented to on this site.';
  else if (lname.includes('session') || lname.includes('sess'))
    what = 'Session cookie — keeps you logged in during your current browser session.';
  else if (lname.includes('consent') || lname.includes('gdpr') || lname.includes('ccpa'))
    what = 'Consent record — stores your privacy preference choices.';
  else if (flags.includes('Long-lived'))
    what = 'Persistent identifier — keeps tracking you across visits for more than 90 days.';
  else
    what = 'Tracking or functional cookie set by this domain.';

  const risks = [];
  if (flags.includes('Long-lived'))      risks.push('Persists for more than 90 days, enabling long-term tracking.');
  if (flags.includes('SameSite=None'))   risks.push('Sent on cross-site requests — enables cross-site tracking.');
  if (!flags.includes('HttpOnly'))       risks.push('Readable by page JavaScript — exposed to any script on this page.');
  if (!flags.includes('Secure'))         risks.push('Not marked Secure — could be transmitted over HTTP.');

  return { what, risks };
}

// ── Request description helper ────────────────────────────────────────────────
function requestDescription(req) {
  const type = req.type || '';
  const typeDescriptions = {
    script:          'JavaScript file — executes code in your browser. Third-party scripts can read page content and track behaviour.',
    xmlhttprequest:  'API call — sends or receives data in the background. Common for tracking beacons and analytics pings.',
    image:           'Image request — often a 1×1 "tracking pixel" used to confirm the page was loaded.',
    sub_frame:       'Embedded frame — loads third-party content in an iframe, often for ads or widgets.',
    stylesheet:      'CSS stylesheet — usually safe, but can occasionally be used for fingerprinting.',
    font:            'Web font — loading fonts from a third-party CDN lets that server log your visit.',
    media:           'Media file — audio or video content loaded from this domain.',
    other:           'Other resource type.',
  };
  return typeDescriptions[type] ?? `Network request (${type}) to this domain.`;
}



// ── Notable findings engine ───────────────────────────────────────────────────
// Surfaces the most privacy-significant observations across the whole session.
// Provenance: Classified (tracker list matches) + Inferred (cookie attribute patterns).
// Never presented as "malware detected" — only as notable findings worth reviewing.

const FINDING_CATEGORIES = new Set(['Fingerprinting', 'Cryptomining']);

// ── Data Exposure Detector (v0.11.0) ─────────────────────────────────────────
// Aggregates classify/exposure.js's per-request matches across a domain
// group's requests, deduplicated by (type, paramName) — a tracking ID sent
// on every request of a session should show up once, not fifty times.
function collectExposures(requests) {
  const seen = new Set();
  const out = [];
  for (const r of requests) {
    for (const e of r.exposures ?? []) {
      const key = `${e.type}:${e.paramName}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(e);
    }
  }
  return out;
}

// Which of the session's cookies belong to a given domain-map entry — the
// same eTLD+1 matching assessFlags() already does for its own cookie list,
// pulled out here so exposure aggregation (below) can reuse it instead of
// re-deriving domCookies a second, slightly-different way.
function cookiesForDomainEntry(entry, cookies) {
  const realDomains = entry.etld1s ? [...entry.etld1s] : [entry.etld1 || entry.domain];
  return (cookies ?? []).filter(c =>
    realDomains.some(d => c.domain === `.${d}` || c.domain === d || c.domain.endsWith(`.${d}`)));
}

// (v0.12.0) A domain group's exposure findings, combining what its requests
// carried (collectExposures above) with what its cookies' values matched
// (classify/exposure.js's detectValueExposure, computed in cookies.js) —
// so a domain flagged only because of a cookie value (not a request) still
// shows up in the graph/table markers and the session-wide Notable Finding,
// not just in that one cookie's own expanded detail.
function combinedExposuresForEntry(entry, cookies) {
  const reqExp = collectExposures(entry.requests ?? []);
  const cookieExp = [];
  for (const c of cookiesForDomainEntry(entry, cookies)) {
    for (const e of c.exposures ?? []) cookieExp.push(e);
  }
  const seen = new Set();
  const out = [];
  for (const e of [...reqExp, ...cookieExp]) {
    const key = `${e.source}:${e.type}:${e.paramName}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

// Session-wide: which domains leaked what, for the Findings panel and the
// Insights badge — attributed per domain so the wording can name a source.
function buildSessionExposures(domainMap, cookies) {
  const rows = [];
  for (const [, info] of domainMap) {
    const exp = combinedExposuresForEntry(info, cookies);
    if (exp.length) rows.push({ domain: info.domain, exposures: exp });
  }
  return rows;
}

const EXPOSURE_TYPE_LABEL = {
  email: 'email address', phone: 'phone number', geo: 'approximate location',
  zip: 'ZIP/postal code', id: 'tracking identifier', campaign: 'campaign parameter', page: 'page path',
};

function buildSessionFindings(domainMap, cookies) {
  const findings = [];

  // Data exposure — what classify/exposure.js found leaving the page in
  // request URLs/bodies, and (v0.12.0) in cookie values. Personal-data-shaped
  // matches (email/phone/geo/zip) are High; tracking-identifier-only matches
  // are Medium.
  const exposureRows = buildSessionExposures(domainMap, cookies);
  if (exposureRows.length) {
    const personalTypes = new Set(['email', 'phone', 'geo', 'zip']);
    const hasPersonal = exposureRows.some(r => r.exposures.some(e => personalTypes.has(e.type)));
    const distinctTypes = [...new Set(exposureRows.flatMap(r => r.exposures.map(e => e.type)).filter(t => t !== 'page'))];
    const domainCount = exposureRows.length;
    findings.push({
      icon: icon(hasPersonal ? 'alert-triangle' : 'search', { size:16 }),
      severity: hasPersonal ? 'high' : 'medium',
      title: hasPersonal
        ? `Personal information detected leaving the page`
        : `Tracking identifiers detected leaving the page`,
      detail: `${distinctTypes.map(t => EXPOSURE_TYPE_LABEL[t] ?? t).join(', ')} found in requests to ${domainCount} domain${domainCount===1?'':'s'}. Values are redacted — see each domain's detail panel for specifics. This reflects what was observed in the request itself, not confirmation it is accurate or belongs to you.`,
      provenance: 'Observed',
    });
  }

  // Fingerprinters and cryptominers — most invasive classified categories
  for (const [, info] of domainMap) {
    if (info.party !== 'third-party') continue;
    if (info.category === 'Fingerprinting') {
      findings.push({
        icon: icon('search',{size:16}),
        severity: 'high',
        title: `Browser fingerprinter: ${info.domain}`,
        detail: info.organization
          ? `Operated by ${info.organization}. Fingerprinting can identify you across sites even after clearing cookies.`
          : 'Can identify you across sites even after clearing cookies and private browsing.',
        provenance: 'Classified',
      });
    }
    if (info.category === 'Cryptomining') {
      findings.push({
        icon: icon('zap',{size:16}),
        severity: 'high',
        title: `Cryptocurrency miner: ${info.domain}`,
        detail: 'This script uses your CPU to mine cryptocurrency without your explicit consent.',
        provenance: 'Classified',
      });
    }
  }

  // Long-lived cross-site cookies — inferred risk
  const crossSiteLongLived = cookies.filter(c => c.longLived && c.sameSite === 'no_restriction');
  if (crossSiteLongLived.length > 0) {
    findings.push({
      icon: icon('globe',{size:16}),
      severity: 'medium',
      title: `${crossSiteLongLived.length} long-lived cross-site cookie${crossSiteLongLived.length > 1 ? 's' : ''}`,
      detail: 'These cookies persist for over 90 days and can be sent on requests to other sites, enabling cross-site tracking.',
      provenance: 'Inferred',
    });
  }

  // High advertiser concentration
  const adDomains = [...domainMap.values()].filter(d => d.category === 'Advertising' && d.party === 'third-party');
  if (adDomains.length >= 5) {
    findings.push({
      icon: icon('megaphone',{size:16}),
      severity: 'medium',
      title: `${adDomains.length} advertising trackers active`,
      detail: 'A high concentration of ad trackers increases the chance your browsing is being profiled across multiple data brokers.',
      provenance: 'Classified',
    });
  }

  // Third-party scripts count — inferred from script type requests
  const thirdPartyScripts = [...domainMap.values()].filter(d =>
    d.party === 'third-party' && d.requests.some(r => r.type === 'script')
  );
  if (thirdPartyScripts.length >= 4) {
    findings.push({
      icon: icon('file-text',{size:16}),
      severity: 'low',
      title: `${thirdPartyScripts.length} third-party scripts executing`,
      detail: 'Each third-party script runs with full access to your browser tab and can read what you type, click, and see on the page.',
      provenance: 'Observed',
    });
  }

  if (!findings.length) {
    findings.push({
      icon: icon('check-circle',{size:16}),
      severity: 'none',
      title: 'No notable findings for this session',
      detail: 'No fingerprinters, cryptominers, or unusually risky cookies were detected. This does not mean no tracking is occurring.',
      provenance: 'Observed',
    });
  }

  return findings;
}

// Findings-panel severity -> token-based color (see ui/theme.css). Kept as
// a lookup of CSS custom-property references, not literal hex, so it stays
// correct in both themes automatically.
const SEV_COLOR_VAR = {
  high:   'rgb(var(--danger-rgb))',
  medium: 'rgb(var(--warning-rgb))',
  low:    'rgb(var(--slate-rgb))',
  none:   'rgb(var(--success-rgb))',
};
const SEV_LABEL = { high:'High', medium:'Medium', low:'Low', none:'Clear' };

function renderFindings(domainMap, cookies) {
  const findings = buildSessionFindings(domainMap, cookies);
  return findings.map(f => `
    <div style="display:flex;align-items:flex-start;gap:10px;padding:11px 13px;border-radius:9px;background:var(--surface2);border:1px solid var(--border);margin-bottom:8px">
      <span style="flex-shrink:0;line-height:1.2;color:${SEV_COLOR_VAR[f.severity]}">${f.icon}</span>
      <div style="min-width:0">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:4px">
          <span style="font-size:12px;font-weight:700;color:var(--text)">${esc(f.title)}</span>
          <span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:8px;background:var(--surface3);color:${SEV_COLOR_VAR[f.severity]};flex-shrink:0">${SEV_LABEL[f.severity]}</span>
        </div>
        <div style="font-size:11px;color:var(--muted2);line-height:1.6">${esc(f.detail)}</div>
        <div style="font-size:9px;color:var(--muted);margin-top:4px;font-style:italic">Provenance: ${f.provenance}</div>
      </div>
    </div>`).join('');
}

// Updates the Insights button's badge state (folds in what #btnFindings
// used to show on its own before Story/Findings/Protect were merged).
function updateInsightsBadge(domainMap, cookies) {
  const findings = buildSessionFindings(domainMap, cookies);
  const highCount = findings.filter(f => f.severity === 'high').length;
  const btn = document.getElementById('btnInsights');
  if (!btn) return;
  btn.classList.toggle('btn-warn', highCount > 0);
  btn.innerHTML = `${icon('alert-triangle',{size:13})} Insights${highCount ? ` (${highCount})` : ''}`;
}

// ── Protect yourself panel ────────────────────────────────────────────────────
// Static, session-aware tips. Provenance: Explained.
function buildProtectPanel(domainMap, cookies) {
  const hasAds   = [...domainMap.values()].some(d => d.category === 'Advertising' && d.party === 'third-party');
  const hasFP    = [...domainMap.values()].some(d => d.category === 'Fingerprinting');
  const hasCM    = [...domainMap.values()].some(d => d.category === 'Cryptomining');
  const hasSocial= [...domainMap.values()].some(d => d.category === 'Social');
  const hasLongCookies = cookies.some(c => c.longLived);
  const hasCrossSite   = cookies.some(c => c.sameSite === 'no_restriction');

  const tools = [];
  const habits = [];

  tools.push({
    icon: '🧱',
    title: 'uBlock Origin',
    desc: 'The most effective free ad and tracker blocker. Blocks the majority of what WebLens detected on this page before it even loads.',
    link: 'https://ublockorigin.com',
    linkLabel: 'Get uBlock Origin →',
    relevant: hasAds || hasFP || hasCM,
  });

  tools.push({
    icon: '🦆',
    title: 'DuckDuckGo Privacy Browser / Extension',
    desc: 'Automatically blocks trackers, forces HTTPS, and gives each site a privacy grade. Available as a browser and extension.',
    link: 'https://duckduckgo.com/app',
    linkLabel: 'Get DuckDuckGo →',
    relevant: hasAds,
  });

  if (hasFP) {
    tools.push({
      icon: '🦁',
      title: 'Brave Browser',
      desc: 'Brave blocks fingerprinting at the browser level — something extensions alone cannot fully prevent.',
      link: 'https://brave.com',
      linkLabel: 'Get Brave →',
      relevant: true,
    });
  }

  if (hasSocial) {
    tools.push({
      icon: '📦',
      title: 'Firefox Multi-Account Containers',
      desc: 'Isolates social media trackers like Facebook and Twitter into separate containers, preventing cross-site tracking.',
      link: 'https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/',
      linkLabel: 'Get Containers →',
      relevant: true,
    });
  }

  if (hasLongCookies || hasCrossSite) {
    habits.push({
      icon: '🧹',
      title: 'Clear cookies regularly',
      desc: 'Long-lived cookies were found on this page. Go to Settings → Privacy → Clear browsing data → Cookies. Do this monthly.',
      relevant: true,
    });
  }

  habits.push({
    icon: '🔒',
    title: 'Use a private DNS resolver',
    desc: 'Services like Cloudflare 1.1.1.1 for Families or NextDNS block tracking domains at the network level, across all your apps.',
    link: 'https://nextdns.io',
    linkLabel: 'Try NextDNS →',
    relevant: hasAds,
  });

  habits.push({
    icon: '🌐',
    title: 'Enable Global Privacy Control',
    desc: 'GPC is a browser signal that legally requires some companies to stop selling your data. Firefox and Brave support it natively.',
    link: 'https://globalprivacycontrol.org',
    linkLabel: 'Learn about GPC →',
    relevant: hasAds,
  });

  const makeTip = (t, i) => `
    <div class="protect-tip" style="animation-delay:${i*0.04}s">
      <div class="protect-tip-icon">${t.icon}</div>
      <div class="protect-tip-body">
        <div class="protect-tip-title">${esc(t.title)}</div>
        <div class="protect-tip-desc">${esc(t.desc)}</div>
        ${t.link ? `<a href="${t.link}" target="_blank" class="protect-tip-link">${esc(t.linkLabel ?? 'Learn more →')}</a>` : ''}
      </div>
    </div>`;

  const relevantTools  = tools.filter(t => t.relevant);
  const relevantHabits = habits.filter(h => h.relevant);

  return `
    <div class="protect-section">
      <div class="protect-section-head">
        <div class="protect-section-icon">🧰</div>
        <div>
          <div class="protect-section-title">Recommended tools for this page</div>
          <div class="protect-section-sub">Based on what WebLens detected during your session</div>
        </div>
      </div>
      <div class="protect-tips-list">${relevantTools.map(makeTip).join('')}</div>
    </div>
    <div class="protect-section">
      <div class="protect-section-head">
        <div class="protect-section-icon">💡</div>
        <div>
          <div class="protect-section-title">Privacy habits</div>
          <div class="protect-section-sub">Simple steps that make a real difference</div>
        </div>
      </div>
      <div class="protect-tips-list">${relevantHabits.map(makeTip).join('')}</div>
    </div>
    <div style="padding:12px 16px;font-size:10px;color:var(--muted);line-height:1.65;border-radius:10px;background:var(--s2);border:1px solid var(--border)">
      <strong style="color:var(--muted2)">Provenance: Explained</strong> — these recommendations are based on what WebLens classified during your session. 
      WebLens does not earn money from any tool or service listed here. No affiliate links.
    </div>`;
}

// ── Organization grouping (Step 2) ───────────────────────────────────────────
// Groups all third-party domains and cookies by owning organization.
// Provenance: Observed (request counts), Classified (org/category), Inferred (cookie association).

function buildOrgGroups(domainMap, cookies) {
  const orgMap = new Map();
  for (const [, info] of domainMap) {
    if (info.party === 'first-party') continue;
    // M5: domainMap is now itself grouped by organization when known, so
    // info.domain may already be an org label rather than a real hostname.
    // Use the full etld1s set (real hostnames) for domain listing and
    // cookie matching — never the display label.
    const orgKey = info.organization || info.domain;
    if (!orgMap.has(orgKey)) {
      orgMap.set(orgKey, { name: info.organization || info.domain,
        category: info.category, domains: [], rawDomains: [], requests: [], cookies: [] });
    }
    const g = orgMap.get(orgKey);
    const realDomains = info.etld1s ? [...info.etld1s] : [info.etld1 || info.domain];
    g.domains.push(...realDomains);
    g.rawDomains.push(...realDomains);
    g.requests.push(...info.requests);
    if (!g.category && info.category) g.category = info.category;
  }
  for (const [, g] of orgMap) {
    g.domains = [...new Set(g.domains)];
    g.rawDomains = [...new Set(g.rawDomains)];
    g.cookies = cookies.filter(c =>
      g.rawDomains.some(d =>
        c.domain === `.${d}` || c.domain === d || c.domain.endsWith(`.${d}`)
      )
    );
  }
  return [...orgMap.values()].sort((a, b) => {
    if (!!a.category !== !!b.category) return a.category ? -1 : 1;
    return b.requests.length - a.requests.length;
  });
}

function renderOrgGroups(domainMap, cookies) {
  const groups = buildOrgGroups(domainMap, cookies);
  const panel  = document.getElementById('orgs-panel');
  if (!panel) return;

  if (!groups.length) {
    panel.innerHTML = '<p style="color:var(--muted);padding:24px;text-align:center;font-size:13px">No third-party services detected for this session.</p>';
    return;
  }

  panel.innerHTML = groups.map((g, gi) => {
    const orgIcon = CAT_ICON[g.category] ?? '';
    const catBadge = g.category
      ? `<span class="badge badge-${esc(g.category)}" style="font-size:10px">${orgIcon} ${esc(g.category)}</span>`
      : `<span class="badge badge-third-party" style="font-size:10px">⚪ Third party</span>`;
    const color = g.category ? (CAT_CLR[g.category] ?? C_THIRD) : C_THIRD;
    const chips = [
      `<span class="org-chip">${g.domains.length} domain${g.domains.length===1?"":"s"}</span>`,
      `<span class="org-chip">${g.requests.length} request${g.requests.length===1?"":"s"}</span>`,
      g.cookies.length ? `<span class="org-chip org-chip-warn">${g.cookies.length} cookie${g.cookies.length===1?"":"s"}</span>` : "",
    ].filter(Boolean).join("");

    const domainRows = g.domains.map(d => {
      // M5: domainMap is keyed by group (org-or-domain), not by raw eTLD+1,
      // so count directly from this group's own request list.
      const reqCount = g.requests.filter(r => (r.etld1 || r.domain) === d).length;
      return `<div class="org-domain-row"><span class="org-domain-name">${esc(d)}</span><span class="org-domain-reqs">${reqCount} req</span></div>`;
    }).join("");

    const cookieRows = g.cookies.length ? `
      <div class="org-section-label" style="margin-top:10px">Cookies (${g.cookies.length})</div>
      ${g.cookies.map(c => {
        const fl = [];
        if (c.longLived) fl.push(`<span class="flag fw">Long-lived</span>`);
        if (c.session)   fl.push(`<span class="flag fi">Session</span>`);
        if (c.sameSite === "no_restriction") fl.push(`<span class="flag fw">SameSite=None</span>`);
        if (c.secure)    fl.push(`<span class="flag fg">Secure</span>`);
        if (c.httpOnly)  fl.push(`<span class="flag fg">HttpOnly</span>`);
        return `<div class="org-cookie-row"><span class="ck-name" style="font-size:11px">${esc(c.name)}</span><div class="ck-flags" style="margin-top:2px">${fl.join("")}</div></div>`;
      }).join("")}` : "";

    const orgResTypes = [...new Set(g.requests.map(r=>r.type))];
    const explanation = getExplanation(g.category, g.name, "third-party", orgResTypes);

    return `<div class="org-card">
      <div class="org-card-hd">
        <div class="org-color-bar" style="background:${color}"></div>
        <div class="org-card-main">
          <div class="org-card-top">
            <span class="org-name">${esc(g.name)}</span>
            ${catBadge}
          </div>
          <div class="org-chips">${chips}</div>
        </div>
        <span class="dsec-arrow" style="flex-shrink:0;color:var(--muted);font-size:10px">▶</span>
      </div>
      <div class="org-card-body">
        <div class="org-explain">${explanation}</div>
        <div class="org-section-label">Domains</div>
        ${domainRows}
        ${cookieRows}
      </div>
    </div>`;
  }).join("");

}

// One-time event delegation for org cards — set up after DOM is ready.
// Inline onclick doesn't work reliably in type="module" scripts.
document.getElementById('orgs-panel')?.addEventListener('click', e => {
  const hd = e.target.closest('.org-card-hd');
  if (!hd) return;
  const card = hd.closest('.org-card');
  if (card) card.classList.toggle('open');
});

// ── Detail: node selected ─────────────────────────────────────────────────────
// Renders the per-domain "Data leaving the page" section — what classify/
// exposure.js found in this domain's requests. Redacted by default; each
// finding has a "Show" toggle (v0.12.0, requested directly) that swaps in
// the exact matched value — never the whole request, just that one match.
const EXPOSURE_ICON = { email:'search', phone:'search', geo:'globe', zip:'globe', id:'search', campaign:'megaphone', page:'file-text' };
// The reveal toggle below carries no inline onclick — MV3's default page CSP
// (script-src 'self', no 'unsafe-inline') silently blocks inline event-handler
// attributes entirely, so an inline onclick here would just do nothing (this
// was caught by testing, not assumed). It's handled instead by the delegated
// click listener on #detail near the bottom of this file (search for
// '.exp-reveal-btn'), the same delegation pattern already used for the
// org-card and dsec-hd toggles elsewhere in this file.
function exposureRowHtml(e) {
  return `
    <div style="display:flex;align-items:flex-start;gap:9px;padding:9px 10px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);margin-bottom:6px">
      <span style="flex-shrink:0;color:var(--text2)">${icon(EXPOSURE_ICON[e.type] ?? 'search',{size:13})}</span>
      <div style="min-width:0;flex:1">
        <div style="font-size:12px;font-weight:700;color:var(--text)">${esc(e.label)}</div>
        <div style="display:flex;align-items:center;gap:8px;margin-top:2px">
          <span class="exp-value" data-redacted="${esc(e.redacted)}" data-raw="${esc(e.raw ?? e.redacted)}" style="font-size:11px;color:var(--muted2);font-family:monospace;word-break:break-all">${esc(e.redacted)}</span>
          ${e.raw && e.raw !== e.redacted ? `<button type="button" class="exp-reveal-btn" style="flex-shrink:0;font-size:9px;padding:2px 7px;border-radius:6px;border:1px solid var(--border2);background:none;color:var(--muted);cursor:pointer">Show</button>` : ''}
        </div>
        <div style="font-size:9px;color:var(--muted);margin-top:3px">Param: <code>${esc(e.paramName)}</code> · ${e.source === 'body' ? 'request body' : e.source === 'cookie' ? 'cookie value' : 'URL query string'} · ${esc(e.provenance)}</div>
      </div>
    </div>`;
}
function buildExposureBody(exposures) {
  const rows = exposures.filter(e => e.type !== 'page');
  const pageCtx = exposures.find(e => e.type === 'page');
  return `
    <div style="margin-bottom:10px;font-size:11px;color:var(--muted2);line-height:1.6">
      Patterns found in this domain's request URLs/bodies — Observed, not confirmed accurate or tied to you.
      Redacted by default; click "Show" on any finding to see the exact matched value. Separately, like
      every website, your browser sends basic device/browser info (User-Agent — browser, OS, device class)
      to every domain automatically as part of standard HTTP — that's not a detection, just how requests work.
    </div>
    <div class="exposure-list">
      ${rows.map(exposureRowHtml).join('')}
      ${pageCtx ? `<div style="font-size:10px;color:var(--muted);margin-top:4px">Page context: <code>${esc(pageCtx.redacted)}</code></div>` : ''}
    </div>`;
}

// Total classified trackers currently in the session — same "trackers" count
// the hero line and top-bar stat already use (domains with a category),
// reused here for the "See all N trackers" link rather than recomputed.
function _sessionTrackerCount() {
  return [..._currentDomainMap.values()].filter(v => v.category).length;
}

function renderDetail(d) {
  _detailNodeData = d;
  const { flags, tips, domCookies } = assessFlags(d, sessionCookies);

  const catIcon = CAT_ICON[d.category] ?? '';
  const badge = d.category
    ? `<span class="badge badge-${esc(d.category)}">${catIcon} ${esc(d.category)}</span>`
    : `<span class="badge badge-${d.party==='first-party'?'first-party':'third-party'}">${d.party==='first-party'?icon('check-circle',{size:10}):icon('globe',{size:10})} ${d.party==='first-party'?'First party':'Third party'}</span>`;

  const exposures = collectExposures(d.requests ?? []);

  // Static explanation — provenance: Explained
  const resourceTypes = [...new Set((d.requests??[]).map(r=>r.type))];
  const explanationText = getExplanation(d.category, d.organization, d.party, resourceTypes);

  // ── "In focus" head — italic serif title, a two-stat row in serif
  // numerals (requests made / owning org), then sentence-style prose
  // combining the classification explanation with the first exposure
  // finding (if any), inline, via the SAME redacted/reveal markup and
  // delegated-listener mechanism the full "Data leaving the page" accordion
  // below uses (exposureRowHtml + the #detail click listener's
  // .exp-reveal-btn branch) — not a re-implementation.
  const reqCount = d.requests?.length ?? 0;
  const ownerLabel = d.organization || (d.party === 'first-party' ? 'This site' : 'Unclassified');
  const firstExposure = exposures.find(e => e.type !== 'page');
  const moreExposures = exposures.filter(e => e.type !== 'page').length - (firstExposure ? 1 : 0);

  const proseHtml = `
    <div class="if-prose">
      <p style="margin:0 0 10px">${esc(explanationText)}</p>
      ${firstExposure ? `
      <p style="margin:0">
        Its requests appear to include a <strong>${esc(firstExposure.label.toLowerCase())}</strong> —
        <span class="exp-value" data-redacted="${esc(firstExposure.redacted)}" data-raw="${esc(firstExposure.raw ?? firstExposure.redacted)}">${esc(firstExposure.redacted)}</span>.
        ${firstExposure.raw && firstExposure.raw !== firstExposure.redacted ? `<button type="button" class="exp-reveal-btn if-reveal">Reveal the value →</button>` : ''}
        ${moreExposures > 0 ? ` (${moreExposures} more finding${moreExposures===1?'':'s'} below.)` : ''}
      </p>` : ''}
    </div>`;

  // ── Verify & Protect — a quoted callout for the block/breakage caveat,
  // an outlined block/unblock button (still the real .verify-action-btn,
  // still dispatched through the #detail delegated listener below), and a
  // "See all N trackers" link into the Organizations view.
  let verifyHtml = '';
  if (d.party === 'third-party') {
    const realDomains = d.etld1s ?? [d.etld1 ?? d.domain];
    const blockedCount = realDomains.filter(dom => blockedForSite.has(dom)).length;
    const allBlocked = blockedCount > 0 && blockedCount === realDomains.length;
    const btnAction = allBlocked ? 'unblock' : 'block';
    const btnLabel = allBlocked
      ? `${icon('undo',{size:13})} Unblock &amp; reload`
      : `${icon('shield',{size:13})} Block this tracker`;
    const trackerTotal = _sessionTrackerCount();
    verifyHtml = `
      <div class="if-quote">Blocking ${realDomains.length>1?'these domains':'this domain'} only affects this site — WebLens then reloads the page and shows a before/after receipt. That is a count of what changed, not a promise the site still works.</div>
      <div class="if-actions">
        <button class="verify-action-btn if-outline-btn${allBlocked?' if-blocked':''}" data-action="${btnAction}">${btnLabel}</button>
        <button type="button" class="if-see-all" id="btnSeeAllTrackers">See all ${trackerTotal} tracker${trackerTotal===1?'':'s'} →</button>
      </div>`;
  }

  const headHtml = `
    <div class="detail-head">
      <div class="if-title">In focus: <b class="d-domain">${esc(d.domain)}</b></div>
      ${d.organization ? `<div class="d-org" style="margin-top:2px">${esc(d.organization)}</div>` : ''}
      ${(d.etld1s?.length ?? 1) > 1
        ? `<div class="d-org" style="opacity:.7">Includes ${d.etld1s.length} domains: ${d.etld1s.map(esc).join(', ')}</div>`
        : ''}
      <div class="d-badges" style="margin-top:9px">${badge}</div>
      <div class="if-stats">
        <div><div class="if-stat-n">${reqCount}</div><div class="if-stat-l">Requests made</div></div>
        <div><div class="if-stat-n" style="font-size:15px">${esc(ownerLabel)}</div><div class="if-stat-l">Owning org</div></div>
      </div>
    </div>
    ${proseHtml}
    ${verifyHtml}`;

  // Flags section
  const flagsBody = `
    <div class="risk-card">
      <div class="risk-flags">
        ${flags.length
          ? flags.map(f=>`<div class="risk-flag"><em class="risk-flag-icon">${f.icon}</em>${esc(f.text)}</div>`).join('')
          : '<div class="risk-flag" style="color:var(--muted)">No specific flags for this domain.</div>'}
      </div>
    </div>
    ${tips.length ? `
    <div class="mitigate-card">
      <div class="mitigate-title">${icon('shield',{size:13})} How to protect yourself</div>
      <div class="mitigate-tips">
        ${tips.map(t=>`<div class="mitigate-tip"><em class="mitigate-tip-icon">→</em>${esc(t)}</div>`).join('')}
      </div>
    </div>` : ''}`;

  // Cookies section
  const cookiesBody = domCookies.length ? `
    <div class="ck-list">
      ${domCookies.map(c => {
        const fl=[];
        if(c.secure)   fl.push(`<span class="flag fg">Secure</span>`);
        if(c.httpOnly) fl.push(`<span class="flag fg">HttpOnly</span>`);
        if(c.longLived) fl.push(`<span class="flag fw">Long-lived</span>`);
        if(c.session)  fl.push(`<span class="flag fi">Session</span>`);
        if(c.sameSite==='no_restriction') fl.push(`<span class="flag fw">SameSite=None</span>`);
        const flagNames = [];
        if(c.longLived) flagNames.push('Long-lived');
        if(c.sameSite==='no_restriction') flagNames.push('SameSite=None');
        if(!c.httpOnly) flagNames.push('No HttpOnly');
        if(!c.secure)   flagNames.push('No Secure');
        const { what, risks } = cookieDescription(c.name, flagNames, c.daysUntilExpiry);
        const expiry = c.session ? 'Clears when browser closes'
          : c.daysUntilExpiry != null ? `Expires in ${c.daysUntilExpiry} days` : '';
        // Cookie value exposure (v0.12.0) — same detector, same redact/reveal
        // treatment as request findings above. Absent unless the cookie's
        // value itself matched a pattern; a cookie's declared category
        // (from the Open Cookie Database lookup in `what`/`risks` above)
        // is a separate, already-existing signal and isn't affected by this.
        const cExposures = c.exposures ?? [];
        if (cExposures.length) fl.push(`<span class="flag fw" title="This cookie's value looks like it contains ${esc(cExposures.map(e=>e.label.toLowerCase()).join(', '))}">${icon('search',{size:10})} Value match</span>`);
        return `<div class="ck-item">
          <div class="ck-item-hd">
            <span class="ck-name">${esc(c.name)}</span>
            <div class="ck-flags">${fl.join('')}</div>
          </div>
          <div class="ck-item-body">
            <div style="margin-bottom:6px">${esc(what)}</div>
            ${risks.length ? `<div style="margin-bottom:4px"><strong>What to know:</strong></div>${risks.map(r=>`<div style="margin-bottom:3px">· ${esc(r)}</div>`).join('')}` : ''}
            ${expiry ? `<div style="margin-top:6px;opacity:.6">${esc(expiry)}</div>` : ''}
            ${cExposures.length ? `
            <div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border)">
              <div style="font-size:10px;font-weight:700;color:var(--text);margin-bottom:5px">This cookie's value appears to contain:</div>
              ${cExposures.map(exposureRowHtml).join('')}
            </div>` : ''}
          </div>
        </div>`;
      }).join('')}
    </div>` : '<div style="color:var(--muted);font-size:11px">No cookies set by this domain.</div>';

  // Requests section
  const reqs = (d.requests??[]).slice(0, 10);
  const reqsBody = `
    <div class="req-list">
      ${reqs.map(r=>{
        let p=r.url; try{p=new URL(r.url).pathname}catch{}
        if(p.length>36) p=p.slice(0,36)+'…';
        const desc = requestDescription(r);
        // Chrome's own net-error, not an assumption — tells the request
        // apart from a normal completed one. See shared/schema.js isBlockedError().
        const blocked = isBlockedError(r);
        return `<div class="req-item">
          <div class="req-item-hd">
            <span class="rtype">${esc(r.type)}</span>
            <span style="overflow:hidden;text-overflow:ellipsis">${esc(p)}</span>
            ${blocked ? `<span style="color:rgb(var(--danger-rgb));font-size:10px;font-weight:700;flex-shrink:0;display:inline-flex;align-items:center;gap:3px" title="Cancelled by an extension's block rule (net::ERR_BLOCKED_BY_CLIENT)">${icon('ban',{size:11})} blocked</span>` : ''}
          </div>
          <div class="req-item-body">
            <div style="margin-bottom:5px">${esc(desc)}</div>
            ${blocked ? `<div style="margin-bottom:5px;color:rgb(var(--danger-rgb));display:flex;align-items:center;gap:5px">${icon('ban',{size:12})} This request was cancelled — Chrome reported net::ERR_BLOCKED_BY_CLIENT.</div>` : ''}
            <div style="word-break:break-all;opacity:.5;font-size:10px">${esc(r.url)}</div>
          </div>
        </div>`;
      }).join('')}
      ${d.requests.length>10 ? `<div style="font-size:11px;color:var(--muted);padding:4px 8px">+${d.requests.length-10} more requests</div>`:''}
    </div>`;

  document.getElementById('detail').innerHTML = `
    ${headHtml}
    <div class="detail-scroll">
      ${makeSection('flags','Flags', flags.length||null, flagsBody, false)}
      ${makeSection('cookies','Cookies', domCookies.length, cookiesBody, domCookies.length>0)}
      ${exposures.length ? makeSection('exposure','Data leaving the page', exposures.length, buildExposureBody(exposures), false) : ''}
      ${makeSection('requests','Requests', d.requests?.length, reqsBody, false)}
      <div class="prov-note" style="margin-top:8px">
        <strong>Provenance: ${esc(d.provenance??'Observed')}</strong><br>
        ${d.provenance==='Classified'
          ? 'Matched against the Disconnect tracker list. A match is evidence of classification, not proof of harmful activity.'
          : 'Reported directly by Chrome\'s network API.'}
      </div>
    </div>`;

  // "See all N trackers" — a plain, properly-attached listener (not
  // delegated, since it's simplest to bind fresh right after this exact
  // element is created, same pattern already used for #btnVerifyUndo below).
  document.getElementById('btnSeeAllTrackers')?.addEventListener('click', () => switchView('orgs'));
}

// ── Verify & Protect (M6) ────────────────────────────────────────────────────
// WebLens's first active intervention. Every action here is triggered by an
// explicit click — never automatic, never based on classification alone.
// Blocking is scoped to (site, domain) via background/blocking.js and is a
// toggle: there is no separate "restore" flow, unblocking IS the undo.
// (The block/unblock control itself — status line, outlined button, caveat
// quote — is now built directly in renderDetail()'s "In focus" head, as
// part of the v0.13.0 Field Report redesign, instead of its own accordion
// section here; the workflow functions below are unchanged.)

function showVerifyOverlay(d, title, bodyHtml) {
  const overlay  = document.getElementById('verify-overlay');
  const titleEl  = document.getElementById('verify-title');
  const body     = document.getElementById('verify-body');
  if (titleEl) titleEl.innerHTML = `${icon('search',{size:14})} Verify: ${esc(d.domain)}${title ? ' — ' + esc(title) : ''}`;
  if (body) body.innerHTML = bodyHtml;
  if (overlay) overlay.style.display = 'flex';
}

// Counts only — the same Observed data already captured, sliced down to
// what changed. No new capture mechanism.
function _snapshotStats(domainMap, cookies, realDomains) {
  const entries = [...domainMap.values()];
  const thirdParties = entries.filter(i => i.party === 'third-party');
  const thirdPartyDomainCount = new Set(thirdParties.flatMap(i => [...i.etld1s])).size;
  const trackerCount = thirdParties.filter(i => i.provenance === 'Classified').length;

  const allRequests = entries.flatMap(i => i.requests);
  const targetRequests = allRequests.filter(r => realDomains.includes(r.etld1 || r.domain));
  const targetCompleted = targetRequests.filter(r => r.status === 'completed').length;

  const firstPartyRequests = entries.filter(i => i.party === 'first-party').flatMap(i => i.requests);
  const firstPartyCompleted = firstPartyRequests.filter(r => r.status === 'completed').length;
  const firstPartyErrored   = firstPartyRequests.filter(r => r.status === 'error').length;

  const targetCookies = cookies.filter(c =>
    realDomains.some(dom => c.domain === `.${dom}` || c.domain === dom || c.domain.endsWith(`.${dom}`)));

  return {
    thirdPartyDomainCount, trackerCount,
    targetCompleted, firstPartyCompleted, firstPartyErrored,
    targetCookieCount: targetCookies.length,
    totalCookieCount: cookies.length,
  };
}

// Polls the reloaded tab's new session until its request count stops
// growing (settled for SETTLE_MS) or MAX_WAIT_MS elapses, then snapshots.
async function _waitAndSnapshot(tabId, realDomains) {
  const MAX_WAIT_MS = 8000, SETTLE_MS = 1200, POLL_MS = 400;
  let lastCount = -1, stableStart = null, session = null;
  const start = Date.now();

  while (Date.now() - start < MAX_WAIT_MS) {
    try { session = await chrome.runtime.sendMessage({ type: 'weblens:getSession', tabId }); }
    catch { session = null; }
    const count = session?.requests?.length ?? 0;
    if (count === lastCount && count > 0) {
      if (!stableStart) stableStart = Date.now();
      if (Date.now() - stableStart >= SETTLE_MS) break;
    } else {
      stableStart = null;
      lastCount = count;
    }
    await new Promise(r => setTimeout(r, POLL_MS));
  }

  if (!session || session.error) return null;

  let cookies = [];
  try {
    const cr = await chrome.runtime.sendMessage({ type: 'weblens:getCookies', url: session.pageUrl });
    cookies = cr?.cookies ?? [];
  } catch { /* best effort */ }

  const { domainMap } = buildElements(session);
  return _snapshotStats(domainMap, cookies, realDomains);
}

async function runVerifyWorkflow(d, action) {
  if (!_currentSession || !_currentSiteEtld1) return;
  const realDomains = d.etld1s ?? [d.etld1 ?? d.domain];
  const tabId = _currentSession.tabId;
  const before = _snapshotStats(_currentDomainMap, sessionCookies, realDomains);

  showVerifyOverlay(d, action === 'block' ? 'blocking…' : 'unblocking…',
    `<div style="padding:24px;text-align:center;color:var(--muted)">${action === 'block' ? 'Blocking and reloading…' : 'Unblocking and reloading…'}</div>`);

  try {
    for (const dom of realDomains) {
      await chrome.runtime.sendMessage({
        type: action === 'block' ? 'weblens:blockDomain' : 'weblens:unblockDomain',
        siteEtld1: _currentSiteEtld1, domain: dom,
      });
    }
  } catch (e) {
    showVerifyOverlay(d, 'error', `<div style="padding:24px;color:tomato">Could not update blocking rules: ${esc(String(e))}</div>`);
    return;
  }

  if (action === 'block') realDomains.forEach(dom => blockedForSite.add(dom));
  else realDomains.forEach(dom => blockedForSite.delete(dom));
  // Refresh the detail panel now so its Block/Unblock button reflects the
  // new state underneath the overlay, even before the user closes it.
  if (_detailNodeData) renderDetail(_detailNodeData);

  try {
    await chrome.tabs.reload(tabId);
  } catch {
    showVerifyOverlay(d, action === 'block' ? 'blocked' : 'unblocked', `
      <div style="padding:16px;color:var(--muted2);font-size:13px">
        ${action === 'block' ? 'Blocked' : 'Unblocked'} on this site, but WebLens couldn't reload the tab automatically (it may have closed). Reload the page yourself to see the effect.
      </div>`);
    return;
  }

  const after = await _waitAndSnapshot(tabId, realDomains);
  renderVerifyReceipt(d, action, before, after);
}

function renderVerifyReceipt(d, action, before, after) {
  if (!after) {
    showVerifyOverlay(d, 'incomplete', `<div style="padding:20px;color:var(--muted2);font-size:13px">
      The page reloaded, but WebLens couldn't capture new data in time (the tab may have closed or navigated away). Try again from the dashboard.
    </div>`);
    return;
  }

  const row = (label, b, a) => {
    const delta = a - b;
    const improved = delta < 0; // for these metrics, lower after blocking is the expected "good" direction
    const deltaColor = delta === 0 ? 'var(--muted)' : (improved ? 'rgb(var(--success-rgb))' : 'rgb(var(--danger-rgb))');
    const deltaStr = delta === 0 ? '±0' : (delta > 0 ? `+${delta}` : `${delta}`);
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:12px;color:var(--muted2)">${esc(label)}</span>
      <span style="font-size:12px"><strong>${b}</strong> → <strong>${a}</strong> <span style="color:${deltaColor}">(${deltaStr})</span></span>
    </div>`;
  };

  // Breakage caveat — a soft, honestly-limited signal only. WebLens has no
  // way to see whether a page visually or functionally broke; the closest
  // thing it CAN observe is whether first-party (same-site) requests
  // completed less often or errored more after the block.
  const fpDropped   = before.firstPartyCompleted - after.firstPartyCompleted;
  const fpErrorsUp  = after.firstPartyErrored > before.firstPartyErrored;
  const possibleBreakage = action === 'block' &&
    (fpDropped > Math.max(2, before.firstPartyCompleted * 0.15) || fpErrorsUp);

  const caveat = possibleBreakage ? `
    <div style="margin-top:14px;padding:12px 16px;border-radius:10px;background:rgba(var(--warning-rgb),.12);border:1px solid rgba(var(--warning-rgb),.35)">
      <strong style="color:rgb(var(--warning-rgb));font-size:12px;display:flex;align-items:center;gap:6px">${icon('alert-triangle',{size:14})} Worth checking the page</strong>
      <div style="font-size:11px;color:var(--muted2);margin-top:4px;line-height:1.5">
        First-party requests that completed ${fpDropped > 0 ? `dropped by ${fpDropped}` : ''}${fpDropped>0 && fpErrorsUp ? ' and ' : ''}${fpErrorsUp ? 'errors increased' : ''} after blocking. That can mean the site needed this resource — or it can be unrelated. <strong>WebLens cannot see whether the page looks or works correctly.</strong> Only looking at it can confirm that.
      </div>
    </div>` : `
    <div style="margin-top:14px;padding:12px 16px;border-radius:10px;background:var(--s2);border:1px solid var(--border)">
      <div style="font-size:11px;color:var(--muted);line-height:1.5">No drop in first-party requests was observed — a weak signal the page loaded normally, not proof nothing changed visually.</div>
    </div>`;

  const targetLine = `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);background:rgba(var(--success-rgb),.06)">
    <span style="font-size:12px;color:var(--muted2)">${esc(d.domain)} requests completed</span>
    <span style="font-size:12px"><strong>${before.targetCompleted}</strong> → <strong>${after.targetCompleted}</strong></span>
  </div>`;

  showVerifyOverlay(d, 'receipt', `
    <div style="margin-bottom:12px;font-size:12px;color:var(--muted2)">
      Privacy receipt — before vs. after ${action === 'block' ? 'blocking' : 'unblocking'} <strong>${esc(d.domain)}</strong> on this site.
    </div>
    ${targetLine}
    ${row('Third-party domains on page', before.thirdPartyDomainCount, after.thirdPartyDomainCount)}
    ${row('Classified trackers on page', before.trackerCount, after.trackerCount)}
    ${row('Cookies from this domain', before.targetCookieCount, after.targetCookieCount)}
    ${row('Total cookies on page', before.totalCookieCount, after.totalCookieCount)}
    ${caveat}
    <div style="margin-top:14px">
      <button id="btnVerifyUndo" style="padding:8px 14px;border-radius:8px;border:1px solid var(--border2);background:var(--s2);color:var(--text2);font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:7px">
        ${action === 'block' ? icon('undo',{size:13})+' Unblock &amp; reload again' : icon('shield',{size:13})+' Block &amp; reload again'}
      </button>
    </div>
    <div style="margin-top:10px;font-size:9px;opacity:.5;font-style:italic">Provenance: Observed (request/cookie counts), Inferred (the breakage caveat). Not a functional test of the page.</div>`);

  document.getElementById('btnVerifyUndo')?.addEventListener('click', () => {
    runVerifyWorkflow(d, action === 'block' ? 'unblock' : 'block');
  });
}

// ── Search ────────────────────────────────────────────────────────────────────
function applySearch(q) {
  if (!cy) return;
  q = q.trim().toLowerCase();
  cy.batch(() => {
    cy.elements().removeClass('search-match search-dim');
    if (!q) return;
    cy.nodes().forEach(n => {
      if (n.id()==='__page__') return;
      const d = n.data();
      const match = (d.label||'').toLowerCase().includes(q)
        || (d.organization||'').toLowerCase().includes(q)
        || (d.category||'').toLowerCase().includes(q);
      n.addClass(match ? 'search-match' : 'search-dim');
    });
  });
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats(session, map) {
  const domains = [...map.values()];
  const vals = {
    sReqs: session.requests.length,
    sDoms: map.size,
    s3rd:  domains.filter(d=>d.party==='third-party').length,
    sTrk:  domains.filter(d=>d.category).length,
  };
  for (const [id, val] of Object.entries(vals)) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.textContent = val;
    // Retrigger animation on every session switch
    el.style.animation = 'none';
    void el.offsetWidth;
    el.style.animation = '';
    el.classList.remove('stat-pop');
    void el.offsetWidth;
    el.classList.add('stat-pop');
  }
}

// ── Table ──────────────────────────────────────────────────────────────────────
// v0.11.1 — one row per domain/organization, not one row per raw request. A
// site that loads the same script from bbci.co.uk nine times used to produce
// nine visually-identical rows; grouping via the same domainMap the graph
// already builds (buildDomainMap()) collapses that into one row with a
// request count, and makes rows clickable into the same detail panel a
// graph node opens — closing the "graph is clickable, table isn't"
// inconsistency in the same change.
function renderTable(session, domainMap) {
  const entries = [...(domainMap ?? new Map()).values()];
  const loading = document.getElementById('tl-loading');
  const table   = document.getElementById('req-table');
  if (!entries.length) {
    if (loading) { loading.textContent = 'No requests captured. Reload the page with WebLens active.'; loading.style.display = ''; }
    if (table) table.style.display = 'none';
    return;
  }
  // Busiest domains first by default — the ones worth a second look surface
  // without having to click "sort".
  const sorted = [...entries].sort((a, b) => b.requests.length - a.requests.length);

  document.getElementById('tbl-body').innerHTML = sorted.map(r => {
    const blockedCount = r.requests.filter(isBlockedError).length;
    const errorCount = r.requests.filter(x => x.status === 'error' && !isBlockedError(x)).length;
    const statusLabel = blockedCount ? `${blockedCount} blocked` : errorCount ? `${errorCount} errored` : 'completed';
    // Data Exposure Detector marker — same at-a-glance treatment as the
    // graph nodes (see buildElements), so the table doesn't require opening
    // every row's detail panel to see which domains have something flagged.
    const exposures = combinedExposuresForEntry(r, sessionCookies);
    const personalTypes = new Set(['email', 'phone', 'geo', 'zip']);
    const hasPersonalExposure = exposures.some(e => personalTypes.has(e.type));
    const exposureBadge = exposures.length
      ? `<span class="tbl-exposure-badge tbl-exposure-${hasPersonalExposure ? 'high' : 'medium'}" title="Data exposure: ${esc([...new Set(exposures.map(e => e.type).filter(t => t !== 'page'))].map(t => EXPOSURE_TYPE_LABEL[t] ?? t).join(', '))}">${icon(hasPersonalExposure ? 'alert-triangle' : 'search', { size:11 })}</span>`
      : '';
    // Explicit tracker marker — the "N trackers" count means "matched a
    // known tracker list" (provenance === 'Classified'), which spans every
    // category, not just Advertising/Fingerprinting. The category badge
    // alone implied this (a dash meant unclassified) but never said so —
    // this makes the same fact readable directly, matching the graph's new
    // solid/faint node treatment.
    const trackerBadge = r.provenance === 'Classified'
      ? `<span class="tbl-tracker-badge" title="Matched a known tracker list">${icon('shield', { size:11 })}</span>`
      : '';
    return `<tr>
        <td>${exposureBadge}${trackerBadge}${esc(r.domain)}</td>
        <td class="nm">${esc(r.organization??'—')}</td>
        <td class="nm">${r.category
          ?`<span class="badge badge-${esc(r.category)}" style="font-size:10px;padding:2px 8px">${esc(r.category)}</span>`
          :'<span style="color:var(--muted)">—</span>'}</td>
        <td class="nm">${esc(r.party)}</td>
        <td class="tbl-reqcount">${r.requests.length}</td>
        <td>${esc(statusLabel)}</td>
      </tr>`;
  }).join('');
  if (loading) loading.style.display = 'none';
  if (table) table.style.display = '';

  // Row click -> the same detail panel a graph node opens. etld1s needs to
  // be an array here (buildDomainMap keeps it as a Set for cheap dedup while
  // building); renderDetail()/assessFlags() expect the array shape the
  // graph's node data already provides via buildElements().
  [...document.getElementById('tbl-body').children].forEach((tr, i) => {
    const entry = sorted[i];
    tr.addEventListener('click', () => {
      document.querySelectorAll('#tbl-body tr.tbl-row-selected').forEach(el => el.classList.remove('tbl-row-selected'));
      tr.classList.add('tbl-row-selected');
      renderDetail({ ...entry, etld1s: [...entry.etld1s] });
    });
  });

  // Wire sortable column headers (rebinds each render, matching the
  // pre-grouping behavior; the table is small enough that duplicate
  // listeners from repeated session switches are not worth guarding here).
  document.querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      const asc = !th.classList.contains('sort-asc');
      document.querySelectorAll('th').forEach(t => t.classList.remove('sort-asc','sort-desc'));
      th.classList.add(asc ? 'sort-asc' : 'sort-desc');
      const tbody = document.getElementById('tbl-body');
      if (!tbody) return;
      const rows = [...tbody.querySelectorAll('tr')].sort((a, b) => {
        const ai = ['domain','organization','category','party','requests','status'].indexOf(col);
        const av = a.cells[ai]?.textContent ?? '';
        const bv = b.cells[ai]?.textContent ?? '';
        if (col === 'requests') return asc ? (+av - +bv) : (+bv - +av);
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(r => tbody.appendChild(r));
    });
  });
}

// ── Timeline resize observer ─────────────────────────────────────────────────
let _lastSession = null;
const _tlObserver = new ResizeObserver(() => { if (_lastSession) renderTimeline(_lastSession); });
const _tlWrap = document.getElementById('timeline-wrap');
if (_tlWrap) _tlObserver.observe(_tlWrap);

// ── Insights overlay — Story + Findings + Protect, merged into one place ──────
// Previously three separate topbar buttons/destinations; now one, with each
// as a collapsible section (same accordion pattern as the detail panel).
function showInsights(session) {
  if (!session) return;
  const storyHtml    = buildStory(session, sessionCookies);
  const findingsHtml = `
    <div style="margin-bottom:8px;font-size:12px;color:var(--muted2)">
      Notable observations from this session. These are not proof of malicious activity —
      they are patterns that privacy researchers consider worthy of attention. Separately,
      like every website, your browser sends basic device/browser info (User-Agent — browser,
      OS, device class) to every domain automatically as part of standard HTTP — that's not
      listed as a finding below since it's universally true, not something specific to this site.
    </div>
    ${renderFindings(_currentDomainMap, sessionCookies)}`;
  const protectHtml = buildProtectPanel(_currentDomainMap, sessionCookies);

  const body = document.getElementById('story-body');
  if (body) {
    body.innerHTML =
      makeSection('insight-story', 'Story', null, storyHtml, true) +
      makeSection('insight-findings', 'Findings', null, findingsHtml, false) +
      makeSection('insight-protect', 'Protect & fix', null, protectHtml, false);
  }
  document.querySelector('.story-title').textContent = 'Insights';
  const overlay = document.getElementById('story-overlay');
  if (overlay) overlay.style.display = 'flex';
}
function hideInsights() {
  const overlay = document.getElementById('story-overlay');
  if (overlay) overlay.style.display = 'none';
}

// ── Load session ──────────────────────────────────────────────────────────────
let _currentSession = null;

async function loadSession(session) {
  _currentSession = session;
  hideInsights();

  sessionCookies = [];
  try {
    const cr = await chrome.runtime.sendMessage({ type:'weblens:getCookies', url:session.pageUrl });
    sessionCookies = cr?.cookies ?? [];
  } catch {}

  const { nodes, edges, domainMap } = buildElements(session);
  _currentDomainMap = domainMap;

  // M6 — which real domains are currently blocked on this site, so the
  // graph/detail panel can show it.
  _currentSiteEtld1 = null;
  blockedForSite = new Set();
  try {
    _currentSiteEtld1 = getEtld1(new URL(session.pageUrl).hostname);
    const res = await chrome.runtime.sendMessage({ type: 'weblens:getBlockedForSite', siteEtld1: _currentSiteEtld1 });
    blockedForSite = new Set(res?.domains ?? []);
  } catch { /* no page URL yet, or message failed */ }

  updateStats(session, domainMap);
  initGraph({ nodes, edges });
  buildLegend(domainMap);
  _lastSession = session; renderTimeline(session);
  renderTable(session, domainMap);
  renderOrgGroups(domainMap, sessionCookies);
  renderCategoryTally(domainMap);
  renderHeroLine(session, domainMap);
  updateInsightsBadge(domainMap, sessionCookies);
  renderTrend(session); // prepends the "what changed" diff + history into orgs-view

  showEmpty();
  applySearch(document.getElementById('searchInput').value);
}

// ── Hero — a real headline block (v0.13.0 Field Report redesign), not a
// compact one-line strip: a large serif sentence stating the finding, with
// the emphasized clause in italic accent color, then a smaller sub-sentence
// with more detail. Every number here comes from the same domainMap the
// graph/table/stats strip already build — nothing hardcoded. The timing
// clause is only shown when buildJourney() (built from real request
// timestamps, same function the Data Journey replay uses) actually has a
// third-party arrival to report; it's omitted rather than guessed when a
// session has no third-party requests yet. ─────────────────────────────────
function renderHeroLine(session, domainMap) {
  const el = document.getElementById('heroLine');
  if (!el) return;
  const domains = [...domainMap.values()];
  const thirdParty = domains.filter(d => d.party === 'third-party');
  const trackers = domains.filter(d => d.category);
  const pageHost = hostOf(session.pageUrl);
  if (!session.requests?.length) {
    el.innerHTML = `<div class="hero-headline">No requests captured yet for <em>${esc(pageHost)}</em>.</div>
      <div class="hero-sub">Reload the page with WebLens active, then reopen the dashboard.</div>`;
    return;
  }

  const companyCount = thirdParty.length;
  const trackerCount = trackers.length;

  let headline;
  if (companyCount === 0) {
    headline = `Everything <strong>${esc(pageHost)}</strong> loaded came from <em>${esc(pageHost)} itself</em> — no third-party companies were introduced.`;
  } else if (trackerCount > 0) {
    headline = `This page quietly introduced you to <em>${companyCount} compan${companyCount===1?'y':'ies'}</em> — <em>${trackerCount}</em> of them tracker${trackerCount===1?'':'s'}.`;
  } else {
    headline = `This page quietly introduced you to <em>${companyCount} compan${companyCount===1?'y':'ies'}</em> — none matched a known tracker list.`;
  }

  const journey = buildJourney(session, domainMap);
  const timingClause = journey && journey.steps.length && journey.totalDurationMs > 0
    ? ` The first of them was contacted within ${journey.totalDurationMs < 1000 ? Math.round(journey.totalDurationMs) + 'ms' : (journey.totalDurationMs/1000).toFixed(1) + 's'} of the page opening.`
    : '';
  // Keeps the plain "N domains, M third-party" phrasing in the sub-sentence
  // (in addition to the italic headline above) — this is also the exact
  // substring several existing e2e suites poll for as their "third-party
  // capture has landed" readiness signal, so preserving the literal wording
  // keeps those tests fast/deterministic rather than falling back to their
  // retry loop every run.
  const subText = `${domains.length} domain${domains.length===1?'':'s'} contacted, ${companyCount} third-party.${timingClause}`;

  el.innerHTML = `<div class="hero-headline">${headline}</div><div class="hero-sub">${esc(subText)}</div>`;
}

// ── Data Journey — replay this session's requests in the order they
// actually happened (v0.11.0). Built entirely from `request.timestamp`,
// already captured for every request since M2 — no new data, no new
// permissions. Provenance: Observed (real timestamps); playback timing is
// visually scaled to fit a short overlay, but relative order and the
// summary sentence's stated duration are the real captured numbers. ───────
let _journeyTimers = [];

function buildJourney(session, domainMap) {
  const reqs = session.requests ?? [];
  if (!reqs.length) return null;

  const t0 = Math.min(...reqs.map(r => r.timestamp));
  const pageHost = hostOf(session.pageUrl);

  // Only third-party arrivals are "journey" milestones — first-party
  // requests to the page's own domain are expected, not a discovery.
  const thirdPartySteps = [...domainMap.values()]
    .filter(d => d.party === 'third-party')
    .map(d => ({
      label: d.domain,
      category: d.category,
      requestCount: d.requests.length,
      deltaMs: Math.min(...d.requests.map(r => r.timestamp)) - t0,
    }))
    .sort((a, b) => a.deltaMs - b.deltaMs);

  const totalDurationMs = thirdPartySteps.length
    ? Math.max(...thirdPartySteps.map(s => s.deltaMs))
    : 0;

  return { pageHost, t0, totalDurationMs, steps: thirdPartySteps, totalRequests: reqs.length };
}

function fmtDelta(ms) {
  return ms < 1000 ? `+${Math.round(ms)}ms` : `+${(ms / 1000).toFixed(2)}s`;
}

function renderJourneyStep(step, isOrigin) {
  const iconName = isOrigin ? 'globe' : (CATEGORY_ICON_NAME[step.category] ?? 'network');
  const dotClass = isOrigin ? 'journey-step-dot origin' : 'journey-step-dot';
  const title = isOrigin ? `You opened ${esc(step.label)}` : esc(step.label);
  const meta = isOrigin
    ? 'Page load — everything below is a third-party domain contacted afterward.'
    : `${step.requestCount} request${step.requestCount===1?'':'s'}${step.category ? ` · ${esc(step.category)}` : ''}`;
  return `
    <div class="journey-step" data-delta="${step.deltaMs}">
      <div class="journey-step-rail">
        <div class="${dotClass}"></div>
        <div class="journey-step-line"></div>
      </div>
      <div class="journey-step-body">
        <div class="journey-step-delta">${isOrigin ? 'You opened' : fmtDelta(step.deltaMs)}</div>
        <div class="journey-step-name">${icon(iconName,{size:13})} ${title}</div>
        <div class="journey-step-meta">${meta}</div>
      </div>
    </div>`;
}

function showJourney(session, domainMap) {
  const journey = buildJourney(session, domainMap);
  const body = document.getElementById('journey-body');
  const overlay = document.getElementById('journey-overlay');
  if (!body || !overlay) return;

  if (!journey || !journey.steps.length) {
    body.innerHTML = `<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px">
      No third-party requests captured for this session yet — nothing to replay.
    </div>`;
    overlay.style.display = 'flex';
    return;
  }

  const originStep = { label: journey.pageHost, deltaMs: 0 };
  body.innerHTML = `
    <div class="journey-timeline" id="journeyTimeline">
      ${renderJourneyStep(originStep, true)}
      ${journey.steps.map(s => renderJourneyStep(s, false)).join('')}
    </div>
    <div class="journey-summary" id="journeySummary">
      Within <strong>${(journey.totalDurationMs/1000).toFixed(1)}s</strong> of opening this page, your browser contacted
      <strong>${journey.steps.length} external domain${journey.steps.length===1?'':'s'}</strong>
      through <strong>${journey.totalRequests} request${journey.totalRequests===1?'':'s'}</strong>.
    </div>`;
  overlay.style.display = 'flex';
  playJourney();
}

function playJourney() {
  _journeyTimers.forEach(clearTimeout);
  _journeyTimers = [];

  const stepEls = [...document.querySelectorAll('#journeyTimeline .journey-step')];
  const summaryEl = document.getElementById('journeySummary');
  if (!stepEls.length) return;

  // Scale total playback to a comfortable max, but never compress below the
  // real relative order — only the wall-clock speed of the reveal changes,
  // never which domain appears first. Enforce a small minimum gap so fast
  // sessions (everything within a few ms) don't just flash all at once.
  const MAX_PLAYBACK_MS = 5000;
  const MIN_STEP_GAP_MS = 160;
  const realDeltas = stepEls.map(el => Number(el.dataset.delta));
  const maxReal = Math.max(1, ...realDeltas);
  const scale = maxReal > MAX_PLAYBACK_MS ? MAX_PLAYBACK_MS / maxReal : 1;

  let lastScheduled = -Infinity;
  const scheduled = realDeltas.map(d => {
    const t = Math.max(d * scale, lastScheduled + MIN_STEP_GAP_MS);
    lastScheduled = t;
    return t;
  });

  stepEls.forEach((el, i) => {
    el.classList.remove('shown');
    _journeyTimers.push(setTimeout(() => el.classList.add('shown'), scheduled[i]));
  });
  if (summaryEl) {
    summaryEl.classList.remove('shown');
    _journeyTimers.push(setTimeout(() => summaryEl.classList.add('shown'), lastScheduled + 400));
  }
}

function hideJourney() {
  const overlay = document.getElementById('journey-overlay');
  if (overlay) overlay.style.display = 'none';
  _journeyTimers.forEach(clearTimeout);
  _journeyTimers = [];
}

// ── Graph mode toggle (map / table) — folds the old separate Table vtab
// into the Graph view itself, per the design pass. ────────────────────────────
function setGraphMode(mode) {
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  document.getElementById('cy-wrap')?.classList.toggle('wl-hidden', mode !== 'map');
  document.getElementById('table-view')?.classList.toggle('wl-hidden', mode !== 'table');
  document.getElementById('timeline-wrap').style.display = mode === 'map' ? '' : 'none';
}
document.querySelectorAll('.mode-btn').forEach(btn => {
  btn.innerHTML = icon(btn.dataset.mode === 'table' ? 'table' : 'network', { size:13 });
  btn.addEventListener('click', () => setGraphMode(btn.dataset.mode));
});

// ── View tabs ─────────────────────────────────────────────────────────────────
// Only Graph and Organizations remain as top-level destinations — Table
// folded into Graph's mode toggle above, Trend folded into Organizations
// (renderTrend), and Story/Findings/Protect folded into the Insights overlay.
function switchView(v) {
  document.querySelectorAll('.vtab').forEach(t=>t.classList.remove('active'));
  const btn = document.querySelector(`.vtab[data-view="${v}"]`);
  if (btn) btn.classList.add('active');
  document.getElementById('graph-view').style.display = v === 'graph' ? 'flex' : 'none';
  document.getElementById('orgs-view').classList.toggle('active', v === 'orgs');
  document.getElementById('detail').style.display = v === 'graph' ? '' : 'none';
}
document.querySelectorAll('.vtab').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

document.getElementById('searchInput').addEventListener('input', e => applySearch(e.target.value));

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
  const key = e.key.toLowerCase();
  if (key === 'g') switchView('graph');
  else if (key === 'o') switchView('orgs');
  else if (key === 'i') document.getElementById('btnInsights')?.click();
  else if (key === 'escape') {
    hideInsights();
    const settingsOverlay = document.getElementById('settings-overlay');
    if (settingsOverlay?.style.display === 'flex') settingsOverlay.style.display = 'none';
    const verifyOverlay = document.getElementById('verify-overlay');
    if (verifyOverlay?.style.display === 'flex') verifyOverlay.style.display = 'none';
  }
  else if (key === '/') { e.preventDefault(); document.getElementById('searchInput')?.focus(); }
  else if (key === '?') {
    const bar = document.getElementById('shortcutBar');
    if (bar) bar.classList.toggle('show');
  }
});
document.getElementById('sessionSelect').addEventListener('change', async e => {
  const s = allSessions[parseInt(e.target.value,10)];
  if (s) await loadSession(s.session);
});
document.getElementById('btnInsights').addEventListener('click', () => showInsights(_currentSession));
document.getElementById('btnStoryClose')?.addEventListener('click', hideInsights);

// ── Data Journey replay button ───────────────────────────────────────────────
document.getElementById('btnReplay')?.addEventListener('click', () => {
  if (_currentSession) showJourney(_currentSession, _currentDomainMap);
});
document.getElementById('btnJourneyClose')?.addEventListener('click', hideJourney);

// ── Trend (M5) ────────────────────────────────────────────────────────────────
// Reads background/history.js's opt-in per-day summaries for the current
// page's site. Off by default — shows an explanatory empty state instead.
async function renderTrend(session) {
  const el = document.getElementById('trend-inner');
  if (!el) return;

  if (!weblensSettings.historyEnabled) {
    el.innerHTML = `<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px;max-width:420px;margin:0 auto">
      Session history is off by default. Turn it on in ⚙ Settings to see how this site's tracking activity changes day to day —
      counts only, never URLs or cookie names, and fully clearable.
    </div>`;
    return;
  }

  let pageEtld1 = null;
  try { pageEtld1 = getEtld1(new URL(session.pageUrl).hostname); } catch { /* fall through */ }
  if (!pageEtld1) { el.innerHTML = '<div style="padding:24px;color:var(--muted)">No page URL for this session.</div>'; return; }

  let days = [];
  try {
    const res = await chrome.runtime.sendMessage({ type: 'weblens:getHistory', etld1: pageEtld1 });
    days = res?.days ?? [];
  } catch { /* best effort */ }

  if (!days.length) {
    el.innerHTML = `<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px">
      No history yet for ${esc(pageEtld1)}. A day's summary is recorded the next time a session here ends.
    </div>`;
    return;
  }

  const maxVal = Math.max(1, ...days.map(d => d.thirdPartyCount));
  const rows = days.map(d => {
    const barPct = Math.round((d.thirdPartyCount / maxVal) * 100);
    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <div style="width:88px;font-size:11px;color:var(--muted)">${esc(d.date)}</div>
      <div style="flex:1;background:var(--s2);border-radius:4px;overflow:hidden;height:16px">
        <div style="width:${barPct}%;height:100%;background:${C_THIRD}"></div>
      </div>
      <div style="width:260px;font-size:11px;color:var(--muted2);text-align:right;flex-shrink:0">
        ${d.thirdPartyCount} 3rd-party · ${d.trackerCount} tracker${d.trackerCount===1?'':'s'} · ${d.cookieCount} cookie${d.cookieCount===1?'':'s'}
      </div>
    </div>`;
  }).join('');

  el.innerHTML = `
    ${buildTrendDiff(days)}
    <div style="margin-bottom:14px;font-size:13px;color:var(--muted2)">Daily summary for <strong>${esc(pageEtld1)}</strong> — oldest first.</div>
    <div>${rows}</div>
    <div style="margin-top:14px;padding:12px 16px;font-size:10px;color:var(--muted);line-height:1.65;border-radius:10px;background:var(--s2);border:1px solid var(--border)">
      <strong style="color:var(--muted2)">Counts only.</strong> No URLs, cookie names, or raw requests are stored — only the numbers shown above, for up to 30 days per site. Clear anytime in ⚙ Settings.
    </div>`;
}

// "What changed since last visit" — a plain-English diff between the two
// most recent recorded days for this site. Pure function over the same
// per-day counts renderTrend() already fetches from history.js; no schema
// change, no new storage. Days are oldest-first, so the last two entries
// are "today" (or most recent) and the visit before that.
function buildTrendDiff(days) {
  if (days.length < 2) return '';
  const curr = days[days.length - 1];
  const prev = days[days.length - 2];

  const fmtDay = (dateStr) => {
    // dateStr is 'YYYY-MM-DD'. Show a weekday name when recent enough to be
    // meaningful ("since Tuesday"), otherwise fall back to the date itself.
    const d = new Date(dateStr + 'T00:00:00');
    if (Number.isNaN(d.getTime())) return dateStr;
    const daysAgo = Math.round((Date.now() - d.getTime()) / 86400000);
    if (daysAgo >= 0 && daysAgo <= 6) return d.toLocaleDateString(undefined, { weekday: 'long' });
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  };

  const deltas = [
    { key: 'trackerCount',         label: 'tracker' },
    { key: 'thirdPartyCount',      label: 'third-party domain' },
    { key: 'cookieCount',          label: 'cookie' },
    { key: 'longLivedCookieCount', label: 'long-lived cookie' },
  ].map(({ key, label }) => ({ label, diff: (curr[key] ?? 0) - (prev[key] ?? 0) }))
   .filter(d => d.diff !== 0);

  const sinceWhen = fmtDay(prev.date);

  if (!deltas.length) {
    return `<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:12px 14px;border-radius:10px;background:rgba(var(--success-rgb),.08);border:1px solid rgba(var(--success-rgb),.25)">
      ${icon('check-circle', { size:16 })}
      <div style="font-size:13px;color:var(--text2)">No change in tracking activity on this site since <strong>${esc(sinceWhen)}</strong>.</div>
    </div>`;
  }

  const parts = deltas.map(d => {
    const up = d.diff > 0;
    const n = Math.abs(d.diff);
    const verb = up ? 'added' : 'removed';
    return `${verb} <strong>${n} ${esc(d.label)}${n===1?'':'s'}</strong>`;
  });
  const anyIncrease = deltas.some(d => d.diff > 0);

  const bg = anyIncrease ? 'rgba(var(--warning-rgb),.08)' : 'rgba(var(--success-rgb),.08)';
  const border = anyIncrease ? 'rgba(var(--warning-rgb),.25)' : 'rgba(var(--success-rgb),.25)';
  const iconName = anyIncrease ? 'alert-triangle' : 'trending-up';

  return `<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:16px;padding:12px 14px;border-radius:10px;background:${bg};border:1px solid ${border}">
    ${icon(iconName, { size:16 })}
    <div style="font-size:13px;color:var(--text2);line-height:1.55">This site ${parts.join(', ')} since <strong>${esc(sinceWhen)}</strong>.</div>
  </div>`;
}

// ── Settings panel (M5) ──────────────────────────────────────────────────────
function fmtListsUpdated(meta) {
  if (!meta?.lastSuccess) return 'Never updated — using the bundled snapshot.';
  const d = new Date(meta.lastSuccess);
  const dateStr = d.toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
  return `Last updated ${dateStr} — ${meta.trackerCount.toLocaleString()} tracker domains, ${(meta.cookieExactCount+meta.cookieWildcardCount).toLocaleString()} cookie entries.`;
}

async function renderSettingsPanel() {
  const el = document.getElementById('settings-body');
  if (!el) return;

  const { meta } = await chrome.runtime.sendMessage({ type: 'weblens:getListsMeta' }).catch(() => ({ meta: null }));

  const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'system';
  const themeOption = (value, name, label) => `
    <button class="theme-opt${currentTheme===value?' active':''}" data-theme-value="${value}" title="${label}" style="display:flex;align-items:center;gap:6px;padding:7px 12px;border-radius:8px;border:1px solid var(--border2);background:${currentTheme===value?'var(--accent)':'var(--s2)'};color:${currentTheme===value?'#fff':'var(--text2)'};font-size:12px;cursor:pointer">
      ${icon(name,{size:13})} ${label}
    </button>`;

  el.innerHTML = `
    <div style="margin-bottom:14px;font-size:12px;color:var(--muted2);line-height:1.6">
      Off by default. Everything it stores stays in your browser — WebLens has no server and sends nothing externally — and can be wiped at any time.
    </div>

    <div style="padding:12px 0;border-bottom:1px solid var(--border)">
      <div style="font-weight:600;font-size:13px;margin-bottom:8px">Appearance</div>
      <div style="display:flex;gap:8px" id="themeOptions">
        ${themeOption('system','monitor','System')}
        ${themeOption('light','sun','Light')}
        ${themeOption('dark','moon','Dark')}
      </div>
    </div>

    <div style="display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)">
      <input type="checkbox" id="chkHistory" ${weblensSettings.historyEnabled ? 'checked' : ''} style="margin-top:3px"/>
      <label for="chkHistory" style="cursor:pointer">
        <div style="font-weight:600;font-size:13px">Session history / trend</div>
        <div style="font-size:11px;color:var(--muted);margin-top:3px;line-height:1.5">Keeps one count summary per site per day (up to 30 days) so the Trend tab can show whether tracking activity is increasing. Counts only — never URLs, cookie names, or raw requests.</div>
      </label>
    </div>
    <button id="btnClearDurable" style="margin-top:16px;padding:8px 14px;border-radius:8px;border:1px solid var(--border2);background:var(--s2);color:var(--text2);font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px">${icon('trash',{size:13})} Clear history data</button>
    <div id="clearDurableStatus" style="margin-top:8px;font-size:11px;color:var(--muted)"></div>

    <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border);display:flex;align-items:flex-start;gap:12px">
      <input type="checkbox" id="chkListRefresh" ${weblensSettings.listRefreshEnabled ? 'checked' : ''} style="margin-top:3px"/>
      <label for="chkListRefresh" style="cursor:pointer;flex:1">
        <div style="font-weight:600;font-size:13px">Tracker &amp; cookie list updates</div>
        <div style="font-size:11px;color:var(--muted);margin-top:3px;line-height:1.5">
          The bundled tracker list and cookie database are dated snapshots and go stale over time, so WebLens re-fetches
          the same two public sources they were built from (Disconnect's tracker list, the Open Cookie Database) about once a
          day, on by default. This is the only outbound request WebLens itself ever makes — no browsing data is sent, only a plain fetch of
          two fixed public files. Turn it off here at any time to go back to the bundled snapshot only.
        </div>
      </label>
    </div>
    <div style="margin-top:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <button id="btnRefreshListsNow" style="padding:7px 12px;border-radius:8px;border:1px solid var(--border2);background:var(--s2);color:var(--text2);font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px">${icon('refresh-cw',{size:12})} Check for updates now</button>
      <span id="listsStatus" style="font-size:11px;color:var(--muted)">${esc(fmtListsUpdated(meta))}</span>
    </div>
    ${meta?.lastSuccess ? `<button id="btnRevertLists" style="margin-top:8px;padding:6px 10px;border-radius:8px;border:1px solid var(--border2);background:none;color:var(--muted);font-size:11px;cursor:pointer">Revert to bundled snapshot</button>` : ''}

    <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border)">
      <div style="font-weight:600;font-size:13px;margin-bottom:6px">Verify &amp; Protect blocks</div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:10px;line-height:1.5">Every domain you've blocked from the dashboard, on every site — not opt-in, since each one only exists because you clicked "Block" yourself.</div>
      <button id="btnClearBlocks" style="padding:8px 14px;border-radius:8px;border:1px solid var(--border2);background:var(--s2);color:var(--text2);font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px">${icon('trash',{size:13})} Remove all blocks</button>
      <div id="clearBlocksStatus" style="margin-top:8px;font-size:11px;color:var(--muted)"></div>
    </div>`;

  document.getElementById('themeOptions').addEventListener('click', async e => {
    const btn = e.target.closest('.theme-opt');
    if (!btn) return;
    await setTheme(btn.dataset.themeValue);
    updateThemeButtonIcon();
    renderSettingsPanel();
    // Cytoscape reads theme colors as literal strings at init time (see
    // initGraph's cssVar() comment) — without rebuilding here, switching
    // theme from this settings panel left the graph's node/edge colors
    // stuck on whichever theme was active on last render (the small topbar
    // toggle already did this; this second theme-change entry point didn't).
    if (_lastGraphElements) initGraph(_lastGraphElements);
  });

  document.getElementById('chkHistory').addEventListener('change', async e => {
    const checked = e.target.checked;
    await chrome.runtime.sendMessage({ type: 'weblens:setSetting', key: 'historyEnabled', value: checked });
    weblensSettings.historyEnabled = checked;
  });
  document.getElementById('chkListRefresh').addEventListener('change', async e => {
    const checked = e.target.checked;
    await chrome.runtime.sendMessage({ type: 'weblens:setSetting', key: 'listRefreshEnabled', value: checked });
    weblensSettings.listRefreshEnabled = checked;
    if (checked) {
      const status = document.getElementById('listsStatus');
      if (status) status.textContent = 'Enabled — checking now…';
      const result = await chrome.runtime.sendMessage({ type: 'weblens:refreshListsNow' });
      if (result?.ok) {
        renderSettingsPanel(); // re-render to surface the "Revert" button, same as the manual check
        return;
      }
      if (status) status.textContent = `Update failed (${result?.error ?? 'unknown error'}) — still using the bundled snapshot.`;
    }
  });
  document.getElementById('btnRefreshListsNow').addEventListener('click', async () => {
    const btn = document.getElementById('btnRefreshListsNow');
    const status = document.getElementById('listsStatus');
    if (btn) btn.disabled = true;
    if (status) status.textContent = 'Checking…';
    const result = await chrome.runtime.sendMessage({ type: 'weblens:refreshListsNow' });
    if (btn) btn.disabled = false;
    if (status) status.textContent = result?.ok
      ? fmtListsUpdated({ lastSuccess: result.checkedAt, trackerCount: result.trackerCount, cookieExactCount: result.cookieExactCount, cookieWildcardCount: result.cookieWildcardCount })
      : `Update failed (${result?.error ?? 'unknown error'}) — still using the bundled snapshot.`;
    if (result?.ok) renderSettingsPanel(); // re-render to surface the "Revert" button
  });
  document.getElementById('btnRevertLists')?.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'weblens:clearLiveLists' });
    renderSettingsPanel();
  });
  document.getElementById('btnClearDurable').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'weblens:clearDurableData' });
    const status = document.getElementById('clearDurableStatus');
    if (status) status.textContent = 'Cleared. New data will only accumulate again for features left enabled above.';
  });
  document.getElementById('btnClearBlocks').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'weblens:clearAllBlocks' });
    blockedForSite = new Set();
    const status = document.getElementById('clearBlocksStatus');
    if (status) status.textContent = 'All blocks removed. Reload any affected pages to restore normal loading.';
  });
}

// ── Theme toggle button ──────────────────────────────────────────────────────
const THEME_ICON = { system: 'monitor', light: 'sun', dark: 'moon' };
function updateThemeButtonIcon() {
  const btn = document.getElementById('btnTheme');
  if (!btn) return;
  const theme = document.documentElement.getAttribute('data-theme') ?? 'system';
  btn.innerHTML = icon(THEME_ICON[theme] ?? 'monitor', { size:13 });
  btn.title = `Theme: ${theme[0].toUpperCase()}${theme.slice(1)} (click to change)`;
}
document.getElementById('btnTheme')?.addEventListener('click', async () => {
  await cycleTheme();
  updateThemeButtonIcon();
  // Cytoscape reads theme colors as literal strings at init time (see
  // cssVar() above), so they don't track a live CSS variable change the way
  // the rest of the page does — rebuild the graph with the same elements
  // so node/edge colors pick up the new theme immediately, not on next
  // session switch.
  if (_lastGraphElements) initGraph(_lastGraphElements);
});

document.getElementById('btnSettings')?.addEventListener('click', () => {
  const titleEl = document.getElementById('settings-title');
  if (titleEl) titleEl.innerHTML = `${icon('settings',{size:14})} Settings`;
  renderSettingsPanel();
  const overlay = document.getElementById('settings-overlay');
  if (overlay) overlay.style.display = 'flex';
});
document.getElementById('btnSettingsClose')?.addEventListener('click', () => {
  const overlay = document.getElementById('settings-overlay');
  if (overlay) overlay.style.display = 'none';
});

// Delegated click handling for everything inside #detail. #detail's innerHTML
// is regenerated on every node selection, and MV3's default page CSP blocks
// inline onclick attributes outright (confirmed by testing: Chrome logs
// "Refused to execute inline event handler ... script-src 'self'" and the
// handler never runs) — so every interactive element rendered into #detail
// (section headers, cookie/request accordion rows, the exposure reveal
// toggle, and the M6 verify/block button) is handled here via
// event.target.closest(), the same delegation pattern the orgs-panel toggle
// above already uses.
document.getElementById('detail')?.addEventListener('click', e => {
  // Reveal/hide a redacted exposure finding. Checked first and returns early
  // so the click doesn't also fall through and toggle an ancestor
  // .ck-item/.req-item open — the equivalent of the old inline handler's
  // event.stopPropagation().
  const revealBtn = e.target.closest('.exp-reveal-btn');
  if (revealBtn) {
    const v = revealBtn.previousElementSibling;
    if (v) {
      const revealed = v.textContent === v.dataset.raw;
      v.textContent = revealed ? v.dataset.redacted : v.dataset.raw;
      revealBtn.textContent = revealed ? 'Show' : 'Hide';
    }
    return;
  }

  const dsecHd = e.target.closest('.dsec-hd');
  if (dsecHd) { dsecHd.parentElement.classList.toggle('open'); return; }

  const ckItem = e.target.closest('.ck-item');
  if (ckItem) { ckItem.classList.toggle('open'); return; }

  const reqItem = e.target.closest('.req-item');
  if (reqItem) { reqItem.classList.toggle('open'); return; }

  const btn = e.target.closest('.verify-action-btn');
  if (!btn || !_detailNodeData) return;
  runVerifyWorkflow(_detailNodeData, btn.dataset.action);
});
// The Insights overlay (#story-body) also renders makeSection() dsec-hd
// headers (Story/Findings/Protect & fix), separately from #detail, so it
// needs its own delegated toggle.
document.getElementById('story-body')?.addEventListener('click', e => {
  const dsecHd = e.target.closest('.dsec-hd');
  if (dsecHd) dsecHd.parentElement.classList.toggle('open');
});
document.getElementById('btnVerifyClose')?.addEventListener('click', () => {
  const overlay = document.getElementById('verify-overlay');
  if (overlay) overlay.style.display = 'none';
  // The block/unblock button's label lives in the detail panel underneath
  // the overlay, not the overlay itself — re-render so it reflects the
  // block state that runVerifyWorkflow() already updated.
  if (_detailNodeData) renderDetail(_detailNodeData);
});

// ── Main ──────────────────────────────────────────────────────────────────────
await applyStoredTheme();
updateThemeButtonIcon();
document.getElementById('btnInsights').innerHTML = `${icon('alert-triangle',{size:13})} Insights`;
document.getElementById('btnReplay').innerHTML = `${icon('zap',{size:12})} Replay`;
document.getElementById('btnSettings').innerHTML = icon('settings',{size:13});
try {
  weblensSettings = await chrome.runtime.sendMessage({ type: 'weblens:getSettings' }) ?? weblensSettings;
} catch { /* defaults already off */ }
allSessions = await loadAllSessions();
if (!allSessions.length) {
  document.getElementById('sessionSelect').innerHTML = '<option>No sessions — visit a page first</option>';
  document.getElementById('cy').innerHTML = '<p class="empty-msg">No data. Visit a page then reopen.</p>';
} else {
  populateSessions(allSessions);
  const best = allSessions.find(s=>s.session.requests?.length>0) ?? allSessions[0];
  document.getElementById('sessionSelect').value = allSessions.indexOf(best);
  await loadSession(best.session);
}
