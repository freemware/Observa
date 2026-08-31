// WebLens popup — M3 refinement.
import { lookupCookie } from '../../classify/cookie-db.js';
import { getEtld1 } from '../../classify/classify.js';
import { isBlockedError } from '../../shared/schema.js';
import { icon } from '../icons.js';
import { applyStoredTheme, cycleTheme } from '../theme.js';

// Tabs, clear button, improved cookie layout, capture timing notice.

// ---------------------------------------------------------------------------
// Theme + structural icons (design pass — see dashboard.js for the shared system)
// ---------------------------------------------------------------------------
const THEME_ICON = { system: 'monitor', light: 'sun', dark: 'moon' };
function updateThemeButtonIcon() {
  const btn = document.getElementById('btnTheme');
  if (!btn) return;
  const theme = document.documentElement.getAttribute('data-theme') ?? 'system';
  btn.innerHTML = icon(THEME_ICON[theme] ?? 'monitor', { size:13 });
  btn.title = `Theme: ${theme[0].toUpperCase()}${theme.slice(1)} (click to change)`;
}
await applyStoredTheme();
updateThemeButtonIcon();
document.getElementById('btnTheme')?.addEventListener('click', async () => {
  await cycleTheme();
  updateThemeButtonIcon();
});
document.getElementById('btnDashboard').innerHTML = `Full dashboard ${icon('chevron-right',{size:12})}`;
document.getElementById('tabStory').innerHTML = `${icon('book-open',{size:12})} Story`;
document.getElementById('tabProtect').innerHTML = `${icon('shield',{size:12})} Protect`;

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab, .panel').forEach(el => el.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`panel-${btn.dataset.panel}`).classList.add('active');
    // Clear button only meaningful on requests tab
    const clearBtn = document.getElementById('btnClear');
    if (clearBtn) clearBtn.style.visibility = btn.dataset.panel === 'requests' ? 'visible' : 'hidden';
  });
});

// ---------------------------------------------------------------------------
// Dashboard button
// ---------------------------------------------------------------------------
document.getElementById('btnDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('ui/dashboard/dashboard.html') });
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
const esc = str => str
  ? str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
  : '';

// M6 — Verify & Protect: the current tab's site, and which real domains are
// currently blocked on it. Populated once in Main, updated after each
// block/unblock click.
let popupSiteEtld1 = null;
let popupBlockedSet = new Set();
let currentSession = null; // kept so the block/unblock handler can re-render after a change

function setStats(ids, val) {
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    el.classList.remove('skel');
  });
}

// ---------------------------------------------------------------------------
// Requests tab
// ---------------------------------------------------------------------------
function buildDomainSummary(requests) {
  const map = new Map();
  for (const req of requests) {
    const key = req.etld1 || req.domain;
    if (!map.has(key)) {
      map.set(key, { domain: key, count: 0, blockedCount: 0, party: req.party,
        category: req.category, organization: req.organization });
    }
    const d = map.get(key);
    d.count++;
    // Distinguishes "attempted but cancelled by an extension's block rule"
    // from a completed request — WebLens's own onBeforeRequest observer
    // still logs an attempt even when M6 (or another blocker) cancels it,
    // so the raw count alone can't answer "did the block actually work?".
    if (isBlockedError(req)) d.blockedCount++;
  }
  return [...map.values()].sort((a, b) => {
    // Trackers first, then third-party, then by count
    const score = d => (d.category ? 2 : 0) + (d.party === 'third-party' ? 1 : 0);
    return score(b) - score(a) || b.count - a.count;
  });
}

function renderRequests(session) {
  document.getElementById('pageUrl').textContent = session.pageUrl ?? '—';
  setStats(['totalRequests'], session.requests.length);

  const domains = buildDomainSummary(session.requests);
  setStats(['totalDomains'], domains.length);
  setStats(['thirdPartyCount'], domains.filter(d => d.party === 'third-party').length);
  setStats(['trackerCount'], domains.filter(d => d.category).length);

  const list = document.getElementById('domainList');
  if (!domains.length) {
    list.innerHTML = '<li style="opacity:.4;grid-column:1/-1;display:block;padding:6px 0">No requests captured. Reload the page with WebLens active.</li>';
    return;
  }

  list.innerHTML = domains.map(d => {
    const partyKey = d.party === 'first-party' ? 'first' : d.party === 'third-party' ? 'third' : 'unknown';
    const badge = d.category
      ? `<span class="badge badge-${esc(d.category)}">${esc(d.category)}</span>`
      : `<span class="badge badge-${partyKey}">${partyKey === 'first' ? '1st' : partyKey === 'third' ? '3rd' : '?'}</span>`;
    const org = d.organization ? `<span class="org"> ${esc(d.organization)}</span>` : '';

    // Real confirmation of whether a block actually took effect: Chrome's
    // own net-error, not an assumption, for the unambiguous "every request
    // to this domain was cancelled" case — the count itself turns red with
    // a ban icon, no extra element needed.
    //
    // v0.12.3: dropped the partial-block sub-count ("9 (3)", later a small
    // pill) from this compact popup list — flagged twice by the user as
    // visual clutter, and the popup's job is a 10-second glance, not a full
    // breakdown. That per-request detail (which specific requests were
    // blocked vs. completed) is still fully available in the dashboard's
    // detail panel, so nothing is actually lost, just not duplicated here.
    const countLabel = (d.blockedCount > 0 && d.blockedCount === d.count)
      ? `<span class="count" style="color:rgb(var(--danger-rgb))" title="All ${d.count} attempts were cancelled by an extension's block rule">${icon('ban',{size:10})} ${d.count}</span>`
      : `<span class="count">${d.count}</span>`;

    const isBlockedHere = popupBlockedSet.has(d.domain);
    // Not-yet-blocked is a neutral, available action — not a warning, so it
    // stays transparent rather than red (red reads as "something's wrong").
    // Once blocked, the button reflects that protection is active (green).
    const blockRow = d.party === 'third-party' ? `
      <div class="pop-block-row" style="display:flex;align-items:center;gap:8px;margin-top:3px;width:100%">
        <button class="pop-block-btn" data-domain="${esc(d.domain)}" data-action="${isBlockedHere ? 'unblock' : 'block'}"
          style="font-size:10px;padding:2px 8px;border-radius:var(--radius-sm);cursor:pointer;display:inline-flex;align-items:center;gap:4px;${isBlockedHere
            ? 'border:1px solid rgba(var(--success-rgb),.35);background:rgba(var(--success-rgb),.1);color:rgb(var(--success-rgb))'
            : 'border:1px solid var(--border2);background:transparent;color:var(--accent2)'}">
          ${isBlockedHere ? `${icon('check-circle',{size:11})} Blocked — Unblock` : `${icon('shield',{size:11})} Block on this site`}
        </button>
      </div>` : '';

    return `<li>
      <span class="domain">${esc(d.domain)}${org}</span>
      ${badge}
      ${countLabel}
      ${blockRow}
    </li>`;
  }).join('');
}

// ---------------------------------------------------------------------------
// Block / unblock (M6 — Verify & Protect, popup-level controls)
// ---------------------------------------------------------------------------
function showBlockHint(action) {
  const el = document.getElementById('blockHint');
  if (!el) return;
  el.style.display = 'block';
  el.innerHTML = (action === 'block'
    ? `${icon('refresh-cw',{size:11})} Reload this page to apply the block. Requests already loaded before you blocked it won’t disappear from this list until you reload.`
    : `${icon('refresh-cw',{size:11})} Reload this page for the unblock to take effect.`);
}

async function handleBlockClick(domain, action) {
  if (!popupSiteEtld1 || !domain) return;
  const btn = document.querySelector(`.pop-block-btn[data-domain="${CSS.escape(domain)}"]`);
  const prevLabel = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = action === 'block' ? 'Blocking…' : 'Unblocking…'; }

  try {
    const type = action === 'block' ? 'weblens:blockDomain' : 'weblens:unblockDomain';
    const result = await chrome.runtime.sendMessage({ type, siteEtld1: popupSiteEtld1, domain });
    if (result?.error) throw new Error(result.error);

    if (action === 'block') popupBlockedSet.add(domain);
    else popupBlockedSet.delete(domain);

    if (currentSession) renderRequests(currentSession);
    showBlockHint(action);
  } catch (err) {
    console.error('[WebLens] block/unblock failed:', err);
    if (btn) { btn.disabled = false; btn.textContent = prevLabel; }
  }
}

document.getElementById('domainList')?.addEventListener('click', e => {
  const btn = e.target.closest('.pop-block-btn');
  if (!btn) return;
  handleBlockClick(btn.dataset.domain, btn.dataset.action);
});

// ---------------------------------------------------------------------------
// Cookies tab
// ---------------------------------------------------------------------------
function renderCookies({ cookies, summary }) {
  // Summary grid — 6 cells in 3 columns
  document.getElementById('cookieStats').innerHTML = [
    ['Total', summary.total],
    ['Persistent', summary.persistent],
    ['Long-lived', summary.longLived],
    ['HttpOnly', summary.httpOnly],
    ['Secure', summary.secure],
    ['SameSite=None', summary.sameSiteNone],
  ].map(([l, v]) => `<div class="cstat"><div class="cv">${v}</div><div class="cl">${l}</div></div>`).join('');

  const list = document.getElementById('cookieList');
  if (!cookies.length) {
    list.innerHTML = '<p style="opacity:.4;font-size:12px;margin:0">No cookies found for this page.</p>';
    return;
  }

  // Sort: persistent first (they're more interesting), then alphabetical
  const sorted = [...cookies].sort((a, b) => {
    if (a.session !== b.session) return a.session ? 1 : -1;
    return a.name.localeCompare(b.name);
  });

  list.innerHTML = sorted.map(c => {
    const flags = [];
    if (c.secure)   flags.push(`<span class="flag flag-good">Secure</span>`);
    if (c.httpOnly) flags.push(`<span class="flag flag-good">HttpOnly</span>`);
    const ssMap = { strict:'SameSite=Strict', lax:'SameSite=Lax',
                    no_restriction:'SameSite=None', unspecified:'SameSite=?' };
    // SameSite=None is a neutral observed property (blue), not dangerous by itself
    // Long-lived is an orange concern, not red
    // Session is gray — temporary, not concerning
    const ssClass = c.sameSite === 'no_restriction' ? 'flag-neutral'
                  : c.sameSite === 'strict' ? 'flag-good' : 'flag';
    flags.push(`<span class="flag ${ssClass}">${ssMap[c.sameSite] ?? c.sameSite}</span>`);
    if (c.longLived) flags.push(`<span class="flag flag-concern">Long-lived</span>`);
    if (c.session)   flags.push(`<span class="flag flag-session">Session</span>`);

    let expiry = c.session ? 'Clears when browser closes'
      : c.daysUntilExpiry != null ? `Expires in ${c.daysUntilExpiry} day${c.daysUntilExpiry===1?'':'s'}` : '';

    // ── Cookie purpose lookup ─────────────────────────────────────────────
    // Primary source: Open Cookie Database (CC0, jkwakman/Open-Cookie-Database)
    // Provenance: CLASSIFIED when matched, INFERRED for attribute-based flags.
    const dbEntry = lookupCookie(c.name);

    let purposeHtml = '';
    let provenanceNote = '';

    if (dbEntry) {
      // Database match — use documented description
      const catLabel = dbEntry.c || 'Unknown';
      const controller = dbEntry.dc || 'Unknown';
      const desc = dbEntry.d || '';
      const retention = dbEntry.r || '';

      purposeHtml = `
        <div style="margin-bottom:5px">
          <span style="color:var(--text);font-weight:700">${esc(dbEntry.p || catLabel)}</span>
          <span style="color:var(--muted);font-size:10px"> · ${esc(catLabel)} · ${esc(controller)}</span>
        </div>
        <div style="margin-bottom:5px">${esc(desc)}</div>
        ${retention ? `<div style="opacity:.55;font-size:10px">Documented retention: ${esc(retention)}</div>` : ''}`;
      provenanceNote = 'Classified — matched against Open Cookie Database (CC0). Source: cookiedatabase.org';
    } else {
      // No database match — infer from attributes only, be honest about uncertainty
      let inferredDesc = '';
      if (c.session) {
        inferredDesc = 'Session cookie — exists only while your browser tab is open. Likely used for login state or temporary preferences. Clears when you close the browser.';
      } else if (c.longLived) {
        inferredDesc = 'Persistent cookie lasting ' + (c.daysUntilExpiry != null ? c.daysUntilExpiry + ' days' : 'an extended period') + '. Purpose could not be matched in the cookie database. Check the site privacy policy for details.';
      } else {
        inferredDesc = 'Cookie set by ' + esc(c.domain) + '. Purpose unknown — not found in the cookie database. Check the site privacy policy for details.';
      }
      purposeHtml = `<div>${inferredDesc}</div>`;
      provenanceNote = 'Inferred from attributes only — name not found in cookie database. Not enough information to classify purpose.';
    }

    // ── Attribute flags ────────────────────────────────────────────────────
    // Provenance: OBSERVED (attributes reported by chrome.cookies API)
    // Language is calibrated: SameSite=None means cross-site eligible, not "sent everywhere"
    const attrFlags = [];
    if (c.longLived && c.sameSite === 'no_restriction')
      attrFlags.push('Persistent and cross-site eligible — can accompany requests to this domain from other sites, and will persist for ' + (c.daysUntilExpiry != null ? c.daysUntilExpiry + ' more days' : 'an extended period') + '. This increases tracking potential but WebLens has not directly observed it being used across multiple websites.');
    else if (c.longLived)
      attrFlags.push('Persists for ' + (c.daysUntilExpiry != null ? c.daysUntilExpiry + ' days' : 'an extended period') + ' — allows the site to recognise you across many visits.');
    if (c.sameSite === 'no_restriction' && !c.longLived)
      attrFlags.push('SameSite=None — eligible to accompany cross-site requests to ' + esc(c.domain) + '. This does not mean the cookie is sent to unrelated websites.');
    if (!c.httpOnly && !c.session)
      attrFlags.push('HttpOnly not set — page scripts on applicable ' + esc(c.domain) + ' pages can read this cookie.');
    if (!c.secure && !c.session)
      attrFlags.push('Secure flag not set — could be transmitted over unencrypted HTTP connections.');

    // ── Attribute grid rows ─────────────────────────────────────────────────
    // Each row: observed value + calibrated plain-English meaning
    // Provenance: OBSERVED (chrome.cookies API)
    const attrRows = [];

    // Expiry
    if (c.session) {
      attrRows.push({ k:'Expires', v:'Session only', m:'Clears when browser closes — temporary.' });
    } else if (c.daysUntilExpiry != null) {
      const tone = c.daysUntilExpiry > 90 ? 'concern' : 'neutral';
      attrRows.push({ k:'Expires', v:`${c.daysUntilExpiry} days`, m: c.daysUntilExpiry > 90 ? 'Persistent — allows recognition across many visits.' : 'Short-lived.', tone });
    }

    // Retention conflict note
    if (dbEntry?.r && c.daysUntilExpiry != null) {
      const dbDays = dbEntry.r.toLowerCase();
      const showConflict = (dbDays.includes('month') || dbDays.includes('year')) &&
        !dbDays.includes(String(c.daysUntilExpiry));
      if (showConflict) {
        attrRows.push({ k:'Reference', v:dbEntry.r, m:`Documented reference duration. Observed expiry differs — cookie duration can vary by implementation or be refreshed on later visits.`, tone:'neutral' });
      }
    }

    // SameSite
    const ssLabels = { strict:'Strict', lax:'Lax', no_restriction:'None', unspecified:'Unspecified' };
    if (c.sameSite === 'no_restriction') {
      attrRows.push({ k:'SameSite', v:'None', m:`Browser may attach this cookie to eligible requests sent to ${c.domain} from a cross-site context. Browser blocking and partitioning settings may still prevent this.`, tone:'neutral' });
    } else if (c.sameSite === 'strict') {
      attrRows.push({ k:'SameSite', v:'Strict', m:'Only sent in same-site requests — strong cross-site protection.', tone:'good' });
    } else {
      attrRows.push({ k:'SameSite', v:ssLabels[c.sameSite]??c.sameSite, m:'Partial cross-site protection.', tone:'neutral' });
    }

    // Secure
    attrRows.push({ k:'Secure', v: c.secure ? 'Yes' : 'No',
      m: c.secure ? 'HTTPS only — transmission is encrypted.' : 'Not restricted to HTTPS — could be transmitted over unencrypted connections.',
      tone: c.secure ? 'good' : 'concern' });

    // HttpOnly
    attrRows.push({ k:'HttpOnly', v: c.httpOnly ? 'Yes' : 'No',
      m: c.httpOnly ? 'Not readable by page scripts — protected.' : `Scripts running in an applicable ${c.domain} page context may be able to read this cookie.`,
      tone: c.httpOnly ? 'good' : 'concern' });

    // Domain scope
    attrRows.push({ k:'Domain', v: esc(c.domain), m: c.domain.startsWith('.') ? `Available across all subdomains of ${c.domain.replace(/^\./,'')}` : `Scoped to ${c.domain} only.`, tone:'neutral' });

    const toneColor = { good:'rgb(var(--success-rgb))', neutral:'var(--muted2)', concern:'rgb(var(--warning-rgb))', advert:'rgb(var(--social-rgb))' };

    const attrGridHtml = attrRows.map(r => `
      <div class="attr-key">${esc(r.k)}</div>
      <div class="attr-val">
        <span style="color:${toneColor[r.tone??'neutral']};font-weight:600">${r.v}</span>
        <span style="color:var(--muted);margin-left:5px;font-size:9px">— ${esc(r.m)}</span>
      </div>`).join('');

    // ── Evidence section ─────────────────────────────────────────────────────
    const purposeProvenance = dbEntry ? 'Classified' : 'Unknown';
    const purposeSource     = dbEntry ? `Open Cookie Database · ${dbEntry.dc||''}` : 'Not found in database';
    const crossSiteNote     = c.sameSite === 'no_restriction'
      ? 'Inferred from SameSite=None — WebLens has not observed this cookie used across multiple websites.'
      : 'N/A — SameSite policy restricts cross-site use.';

    const evidenceHtml = `
      <div class="evidence-row"><span class="evidence-key">Purpose</span><span class="evidence-val ${dbEntry?'classified':''}">${esc(purposeSource)}</span></div>
      <div class="evidence-row"><span class="evidence-key">Attributes</span><span class="evidence-val observed">Observed via Chrome</span></div>
      <div class="evidence-row"><span class="evidence-key">Cross-site use</span><span class="evidence-val inferred">${esc(crossSiteNote)}</span></div>`;

    // Status label
    let statusLabel = '', statusColor = '';
    if (dbEntry?.c === 'Security' || dbEntry?.c === 'Functional') {
      statusLabel = `${dbEntry.c} cookie`; statusColor = 'rgb(var(--slate-rgb))';
    } else if (dbEntry?.c === 'Marketing' || dbEntry?.c === 'Advertising') {
      statusLabel = 'Privacy concern · Persistent advertising identifier'; statusColor = 'rgb(var(--social-rgb))';
    } else if (dbEntry?.c === 'Analytics') {
      statusLabel = 'Analytics · Behavioural data collected'; statusColor = 'rgb(var(--info-rgb))';
    } else if (c.longLived && c.sameSite === 'no_restriction') {
      statusLabel = 'Privacy consideration · Persistent and cross-site eligible'; statusColor = 'rgb(var(--warning-rgb))';
    } else {
      statusLabel = 'Purpose unclassified'; statusColor = 'var(--muted)';
    }

    return `<div class="cookie-row" data-ci="${sorted.indexOf(c)}">
      <div class="cookie-top">
        <span class="cookie-name" title="${esc(c.name)}">${esc(c.name)}</span>
        <span class="cookie-domain-label">${esc(c.domain)}</span>
      </div>
      <div class="cookie-flags">${flags.join('')}</div>
      ${expiry ? `<div class="expiry">${esc(expiry)}</div>` : ''}
      <div class="cookie-see-more">▸ See what this cookie does</div>
      <div class="cookie-detail">

        <div class="cookie-detail-section">
          <div class="cookie-detail-label">What it does</div>
          ${purposeHtml}
        </div>

        <div class="cookie-detail-section">
          <div class="cookie-detail-label">Observed properties</div>
          <div class="attr-grid">${attrGridHtml}</div>
        </div>

        <div class="cookie-detail-section">
          <div class="cookie-detail-label">Evidence</div>
          ${evidenceHtml}
        </div>

        <div style="margin-top:8px;padding:6px 8px;border-radius:var(--radius-sm);background:var(--surface3);border:1px solid var(--border);font-size:9px;color:${statusColor};font-weight:600">
          ${esc(statusLabel)}
        </div>

      </div>
    </div>`;
  }).join('');

  // Event delegation — fixes type="module" inline onclick limitation
  list.addEventListener('click', e => {
    const row = e.target.closest('.cookie-row');
    if (row) row.classList.toggle('open');
  });
}


// ── Story tab ─────────────────────────────────────────────────────────────────
const CAT_LABELS_POPUP = {
  Advertising:'advertising networks', Analytics:'analytics services',
  Social:'social media platforms', Fingerprinting:'browser fingerprinters',
  Cryptomining:'cryptocurrency miners', Content:'content delivery networks',
  'Anti-fraud':'anti-fraud services', Consent:'consent management platforms',
};

function buildPopupStory(session, cookies) {
  const reqs = session.requests ?? [];
  if (!reqs.length) return '<p>No requests captured yet. Reload the page with WebLens active.</p>';

  const pageHost = (() => { try { return new URL(session.pageUrl).hostname; } catch { return session.pageUrl; } })();
  const totalMs = reqs.length > 1
    ? Math.round(Math.max(...reqs.map(r=>r.timestamp)) - Math.min(...reqs.map(r=>r.timestamp))) : 0;

  const domMap = new Map();
  for (const r of reqs) {
    const key = r.etld1 || r.domain;
    if (!domMap.has(key)) domMap.set(key, { ...r, requests:[] });
    domMap.get(key).requests.push(r);
  }
  const domains    = [...domMap.values()];
  const thirdParty = domains.filter(d => d.party === 'third-party');
  const catMap     = new Map();
  for (const d of thirdParty) {
    if (!d.category) continue;
    if (!catMap.has(d.category)) catMap.set(d.category, []);
    catMap.get(d.category).push(d);
  }

  const sentences = [];
  if (totalMs > 0) {
    sentences.push(`When you opened <strong>${esc(pageHost)}</strong>, your browser made <strong>${reqs.length} requests</strong> over <strong>${totalMs.toLocaleString()}ms</strong>.`);
  } else {
    sentences.push(`When you opened <strong>${esc(pageHost)}</strong>, your browser made <strong>${reqs.length} requests</strong>.`);
  }

  if (thirdParty.length === 0) {
    sentences.push(`All domains contacted belong to ${esc(pageHost)} — no third-party services detected.`);
  } else {
    sentences.push(`<strong>${thirdParty.length}</strong> of ${domains.length} domains are third-party — companies other than ${esc(pageHost)}.`);
  }

  if (catMap.size > 0) {
    const parts = [...catMap.entries()]
      .sort((a,b)=>b[1].length-a[1].length)
      .map(([cat,ds]) => `<strong>${ds.length}</strong> ${CAT_LABELS_POPUP[cat]??cat.toLowerCase()}`);
    sentences.push(`Third parties include: ${parts.join(', ')}.`);
  }

  const fp = catMap.get('Fingerprinting')??[];
  const cm = catMap.get('Cryptomining')??[];
  if (fp.length) sentences.push(`⚠️ <strong>${fp.length} fingerprinter${fp.length>1?'s':''}</strong> detected — can identify you even after clearing cookies.`);
  if (cm.length) sentences.push(`⚠️ <strong>${cm.length} cryptominer${cm.length>1?'s':''}</strong> detected — using your CPU without permission.`);

  const longCross = cookies.filter(c=>c.longLived&&c.sameSite==='no_restriction');
  if (cookies.length > 0) {
    let line = `<strong>${cookies.length} cookie${cookies.length===1?'':'s'}</strong> set`;
    const parts = [];
    if (longCross.length) parts.push(`${longCross.length} cross-site long-lived`);
    if (parts.length) line += ` — including ${parts.join(', ')}`;
    sentences.push(line + '.');
  }

  sentences.push(`<em>Open the full dashboard for the complete graph and organization breakdown.</em>`);
  return sentences.map(s=>`<p>${s}</p>`).join('');
}

function renderStoryTab(session, cookies) {
  const el = document.getElementById('storyContent');
  if (!el) return;
  el.innerHTML = session ? buildPopupStory(session, cookies) : '<p style="opacity:.4">No session data yet.</p>';
}

// ---------------------------------------------------------------------------
// Clear button
// ---------------------------------------------------------------------------
async function clearAndReload(tabId, tabUrl) {
  await chrome.runtime.sendMessage({ type: 'weblens:clearSession', tabId });
  const [session, cookieResult] = await Promise.all([
    chrome.runtime.sendMessage({ type: 'weblens:getSession', tabId }),
    chrome.runtime.sendMessage({ type: 'weblens:getCookies', url: tabUrl }),
  ]);
  if (session && !session.error) { currentSession = session; renderRequests(session); }
  if (cookieResult && !cookieResult.error) {
    renderCookies(cookieResult);
    // Also refresh findings banner and story tab after clear
    renderFindingsBanner(session, cookieResult.cookies ?? []);
    renderStoryTab(session, cookieResult.cookies ?? []);
  }
}


// ── Protect tab ───────────────────────────────────────────────────────────────
function renderProtectTab(session, cookieResult) {
  const cookies = cookieResult?.cookies ?? [];
  const requests = session?.requests ?? [];
  const list = document.getElementById('protectList');
  if (!list) return;

  // session.requests have category populated at capture time via classify()
  const hasAds    = requests.some(r => r.category === 'Advertising' && r.party === 'third-party');
  const hasFP     = requests.some(r => r.category === 'Fingerprinting');
  const hasSocial = requests.some(r => r.category === 'Social');
  const hasLong   = cookies.some(c => c.longLived);

  const tips = [];

  tips.push({ icon:'🧱', title:'Install uBlock Origin', desc:'Blocks most trackers on this page before they load. Free and highly effective.' });
  if (hasFP)     tips.push({ icon:'🦁', title:'Try Brave Browser', desc:'Blocks fingerprinting at the browser level — more effective than extensions alone.' });
  if (hasSocial) tips.push({ icon:'📦', title:'Use Firefox Containers', desc:'Isolate social media trackers so they cannot follow you across sites.' });
  if (hasLong)   tips.push({ icon:'🧹', title:'Clear cookies monthly', desc:'Long-lived cookies were found. Settings → Privacy → Clear browsing data → Cookies.' });
  tips.push({ icon:'🌐', title:'Enable Global Privacy Control', desc:'A legal signal that requires some companies to stop selling your data. Supported in Firefox and Brave.' });

  list.innerHTML = tips.map(t => `
    <div class="protect-item">
      <div class="protect-icon">${t.icon}</div>
      <div>
        <div class="protect-title">${t.title}</div>
        <div class="protect-desc">${t.desc}</div>
      </div>
    </div>`).join('');
}

// ── Findings banner ───────────────────────────────────────────────────────────
function renderFindingsBanner(session, cookies) {
  const el = document.getElementById('findingsBanner');
  if (!el) return;
  const requests = session?.requests ?? [];
  const hasFP = requests.some(r => r.category === 'Fingerprinting');
  const hasCM = requests.some(r => r.category === 'Cryptomining');
  const hasLongCross = cookies.filter(c => c.longLived && c.sameSite === 'no_restriction').length;

  // Only show banner for high-severity classified categories.
  // Cross-site eligible cookies are explained in each cookie card — no banner needed.
  if (hasFP || hasCM) {
    const what = hasCM
      ? `${icon('zap',{size:12})} Cryptominer classified`
      : `${icon('search',{size:12})} Fingerprinter classified`;
    el.innerHTML = `<div class="findings-banner sev-red">
      <div class="findings-banner-title">${what}</div>
      <div class="findings-banner-sub">Open the full dashboard for details and context.</div>
    </div>`;
  } else {
    el.innerHTML = ''; // No banner for normal sessions — don't alarm users unnecessarily
  }
}

// ---------------------------------------------------------------------------
// Skeleton loading — shown while the first round-trip to the service worker
// is in flight, so the popup feels instant rather than blank/broken.
// ---------------------------------------------------------------------------
function renderSkeleton() {
  const skelRow = (w1, w2) => `<div class="skel-row"><div class="skel skel-line" style="width:${w1}"></div><div class="skel skel-line" style="width:${w2};margin-left:auto"></div></div>`;
  const domainList = document.getElementById('domainList');
  if (domainList) domainList.innerHTML = `<li style="display:block;padding:0">${skelRow('55%','16%')}${skelRow('40%','16%')}${skelRow('60%','16%')}${skelRow('35%','16%')}</li>`;
  const cookieList = document.getElementById('cookieList');
  if (cookieList) cookieList.innerHTML = skelRow('45%','20%') + skelRow('35%','20%') + skelRow('50%','20%');
}
renderSkeleton();

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const tabId  = tab?.id  ?? null;
const tabUrl = tab?.url ?? null;

if (!tabId) {
  document.getElementById('error').textContent = 'Could not determine active tab.';
} else {
  document.getElementById('btnClear').addEventListener('click', () => clearAndReload(tabId, tabUrl));

  try { if (tabUrl) popupSiteEtld1 = getEtld1(new URL(tabUrl).hostname); } catch { /* no page URL yet */ }

  const [session, cookieResult, blockedResult] = await Promise.all([
    chrome.runtime.sendMessage({ type: 'weblens:getSession', tabId }),
    chrome.runtime.sendMessage({ type: 'weblens:getCookies', url: tabUrl }),
    popupSiteEtld1
      ? chrome.runtime.sendMessage({ type: 'weblens:getBlockedForSite', siteEtld1: popupSiteEtld1 })
      : Promise.resolve(null),
  ]);
  popupBlockedSet = new Set(blockedResult?.domains ?? []);

  if (!session) {
    document.getElementById('pageUrl').textContent = tabUrl ?? '—';
    document.getElementById('error').textContent = 'No session yet — reload the page with WebLens active.';
  } else if (session.error) {
    document.getElementById('error').textContent = session.error;
  } else {
    currentSession = session;
    renderRequests(session);
  }

  if (cookieResult && !cookieResult.error) {
    renderCookies(cookieResult);
    renderFindingsBanner(session, cookieResult.cookies ?? []);
    renderProtectTab(session, cookieResult);
    renderStoryTab(session, cookieResult.cookies ?? []);
  } else {
    document.getElementById('cookieList').innerHTML =
      `<p style="color:rgb(var(--danger-rgb));font-size:12px;margin:0">${esc(cookieResult?.error ?? 'Failed to load cookies.')}</p>`;
  }
}
