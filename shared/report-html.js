// Observa — shared/report-html.js
//
// Renders a report object (shared/report.js) as ONE complete, self-contained
// HTML document.
//
// ── Why one string ─────────────────────────────────────────────────────────
// The preview iframe, the downloaded .html and the printed PDF are all this
// same string. Not "generated the same way" — literally the same bytes. That
// is the only way to guarantee the requirement that downloads and shared
// reports match what the user previewed, and it makes the redaction toggle
// impossible to apply to one surface and miss on another.
//
// No JavaScript, no external requests, no fonts to fetch: the document must
// render identically offline, inside the extension's CSP (script-src 'self'),
// and when emailed to someone else. Colours are literal values rather than the
// dashboard's CSS custom properties for the same reason — a report opened
// outside the extension has no theme.js to define them.
//
// Pure function over plain data — no chrome.* APIs, no DOM.

const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function fmtWhen(iso) {
  if (!iso) return 'unknown';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
  } catch { return iso; }
}

const BAND_COLOR = {
  reasonable: '#1f7a45',
  caution:    '#9a6400',
  concern:    '#a3291f',
};

function section(title, bodyHtml, note) {
  return `<section class="s">
    <h2>${esc(title)}</h2>
    ${note ? `<p class="note">${esc(note)}</p>` : ''}
    ${bodyHtml}
  </section>`;
}

function emptyNote(text) {
  return `<p class="empty">${esc(text)}</p>`;
}

function table(headers, rows) {
  if (!rows.length) return '';
  return `<table>
    <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
  </table>`;
}

/**
 * @param {object} report - from buildReport()
 * @returns {string} a complete HTML document
 */
export function renderReportHtml(report) {
  const m = report.meta ?? {};
  const v = report.overview?.verdict ?? null;
  const c = report.overview?.counts ?? {};
  const bandColor = BAND_COLOR[v?.band] ?? '#444';

  // ── Header ───────────────────────────────────────────────────────────────
  const header = `
    <header class="hd">
      <div class="brand">Observa</div>
      <h1>Privacy scan report</h1>
      <dl class="meta">
        <div><dt>Page</dt><dd class="mono">${esc(m.siteUrl ?? m.host ?? 'unknown')}</dd></div>
        <div><dt>Scanned</dt><dd>${esc(fmtWhen(m.scannedAt))}</dd></div>
        <div><dt>Report generated</dt><dd>${esc(fmtWhen(m.generatedAt))}</dd></div>
        ${m.version ? `<div><dt>Observa version</dt><dd>${esc(m.version)}</dd></div>` : ''}
      </dl>
      ${m.redacted
        ? `<p class="redbar">Sensitive information is redacted in this report. Observed values, identifiers and sensitive URL parameters are replaced with <span class="mono">[redacted]</span>. The findings themselves are unchanged.</p>`
        : `<p class="warnbar">This report is <strong>not redacted</strong>. It may contain personal information, identifiers and URL parameters observed during the scan. Take care where you send it.</p>`}
    </header>`;

  // ── Assessment ───────────────────────────────────────────────────────────
  const assessment = v ? `
    <div class="verdict" style="border-left-color:${bandColor}">
      <div class="vlabel" style="color:${bandColor}">${esc(v.label)}</div>
      <div class="vhead">${esc(v.headline)}</div>
      ${v.reasons?.length ? `<ul class="reasons">${v.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      <p class="conf"><strong>Confidence: ${esc(v.confidence ?? 'unknown')}</strong> — ${esc(v.confidenceWhy ?? '')}</p>
      <p class="note">This is a plain-language summary of what Observa could observe. It is not a score, a rating, or a judgement of the company.</p>
    </div>` : emptyNote('No assessment was produced for this scan.');

  const countsTable = table(
    ['Measure', 'Count'],
    [
      ['Network requests observed', String(c.requests ?? 0)],
      ['Third-party companies contacted', String(c.thirdPartyCompanies ?? 0)],
      ['Of those, matching known trackers', String(c.trackers ?? 0)],
      ['Cookies readable for this site', String(c.cookies ?? 0)],
      ['Data types seen leaving the page', String(c.dataTypes ?? 0)],
      ['Policy documents read', String(c.policyDocumentsRead ?? 0)],
    ].map(([a, b]) => [esc(a), `<span class="num">${esc(b)}</span>`])
  );

  // ── Findings ─────────────────────────────────────────────────────────────
  const findings = report.findings?.length
    ? `<ul class="findings">${report.findings.map(f => `
        <li class="sev-${esc(f.severity)}">
          <div class="ftitle">${esc(f.title)}</div>
          ${f.detail ? `<div class="fdetail">${esc(f.detail)}</div>` : ''}
        </li>`).join('')}</ul>`
    : emptyNote('Nothing on this page matched a known tracker or a personal-data pattern.');

  // ── Requests ─────────────────────────────────────────────────────────────
  const byType = Object.entries(report.requests?.byType ?? {})
    .sort((a, b) => b[1] - a[1]);
  const requests = report.requests?.total
    ? `<p>${report.requests.total} requests observed — ${report.requests.firstParty} to this site, ${report.requests.thirdParty} to other companies.</p>
       ${table(['Request type', 'Count'], byType.map(([t, n]) => [esc(t), `<span class="num">${n}</span>`]))}`
    : emptyNote('No network requests were captured for this page.');

  // ── Third parties ────────────────────────────────────────────────────────
  const thirdParties = report.thirdParties?.length
    ? table(
        ['Company', 'Domains', 'Category', 'Requests'],
        report.thirdParties.map(t => [
          esc(t.company) + (t.organizationKnown ? '' : ' <span class="muted">(owner unknown)</span>'),
          `<span class="mono small">${t.domains.map(esc).join('<br/>')}</span>`,
          t.category ? esc(t.category) + (t.isTracker ? '' : ' <span class="muted">(not a tracker)</span>') : '<span class="muted">unclassified</span>',
          `<span class="num">${t.requestCount}</span>`,
        ])
      )
    : emptyNote('This page did not contact any other companies.');

  // ── Data exposures ───────────────────────────────────────────────────────
  const exposures = report.exposures?.length
    ? table(
        ['Data type', 'Value', 'Parameter', 'Sent to', 'When', 'In the policy?'],
        report.exposures.map(e => [
          esc(e.label) + (e.sensitive ? ' <span class="tag tag-warn">sensitive</span>' : ''),
          e.value == null ? '<span class="muted">not captured</span>' : `<span class="mono small">${esc(e.value)}</span>`,
          e.parameter ? `<span class="mono small">${esc(e.parameter)}</span>` : '<span class="muted">—</span>',
          esc((e.sharedWith ?? []).join(', ') || '—'),
          esc(e.timing ?? '—'),
          e.disclosed === null ? '<span class="muted">no policy read</span>'
            : e.disclosed ? 'Mentioned' : '<span class="tag tag-warn">Not mentioned</span>',
        ])
      )
    : emptyNote('Nothing matching a personal-data or tracking-identifier pattern was seen leaving this page.');

  // ── Cookies ──────────────────────────────────────────────────────────────
  const cookies = report.cookies?.length
    ? `${table(
        ['Name', 'Domain', 'Expires', 'SameSite', 'Flags', 'Matched in value'],
        report.cookies.map(k => [
          `<span class="mono small">${esc(k.name)}</span>`,
          `<span class="mono small">${esc(k.domain ?? '—')}</span>`,
          k.session ? 'session' : esc(k.expiresAt ? fmtWhen(k.expiresAt) : '—'),
          esc(k.sameSite ?? '—'),
          [k.longLived ? 'long-lived' : null, k.secure ? 'secure' : null, k.httpOnly ? 'httpOnly' : null]
            .filter(Boolean).map(esc).join(', ') || '—',
          k.matches?.length
            ? k.matches.map(x => `${esc(x.label)}: <span class="mono small">${esc(x.value ?? '—')}</span>`).join('<br/>')
            : '<span class="muted">—</span>',
        ])
      )}
      <p class="note">Observa reads cookie metadata through Chrome's cookie API. Cookie <em>values</em> are never captured, so none appear here; the last column shows only patterns matched inside a value.</p>`
    : emptyNote('No cookies were readable for this site at scan time.');

  // ── Policy ───────────────────────────────────────────────────────────────
  const docs = report.policy?.documents ?? [];
  const policyDocs = docs.length
    ? `<ul class="docs">${docs.map(d => `<li>${esc(d.title)} — <span class="mono small">${esc(d.url ?? '')}</span>${
        d.ok ? '' : ` <span class="tag tag-warn">${esc(d.error ?? 'could not be read')}</span>`}${
        d.discoveredVia === 'site-root' ? ' <span class="muted">(found via the site’s root page)</span>' : ''}</li>`).join('')}</ul>`
    : '';

  const policyFindings = report.policy?.findings?.length
    ? table(
        ['Clause', 'Reads as', 'Document', 'Section', 'Quoted wording'],
        report.policy.findings.map(f => [
          esc(f.title),
          esc(f.tone === 'concern' ? `concern (${f.importance ?? 'unrated'})` : f.tone ?? ''),
          esc(f.sourceDocument ?? '—'),
          esc(f.section ?? '—'),
          f.evidence ? `<span class="quote">“${esc(f.evidence)}”</span>` : '<span class="muted">—</span>',
        ])
      )
    : emptyNote(docs.length
        ? 'No clauses in the documents Observa read matched its patterns.'
        : 'No policy document was read for this page, so there are no policy findings.');

  const comparisons = report.policy?.comparisons?.length
    ? `<ul class="cmp">${report.policy.comparisons.map(x => `
        <li>
          <div class="ftitle">${esc(x.title)}</div>
          ${x.declaredQuote ? `<div class="quote">Policy says: “${esc(x.declaredQuote)}”${
            x.declaredSource ? ` <span class="muted">(${esc(x.declaredSource)}${x.declaredSection ? ' · ' + esc(x.declaredSection) : ''})</span>` : ''}</div>` : ''}
          ${x.observedText ? `<div class="fdetail">Observed: ${esc(x.observedText)}</div>` : ''}
          ${x.caveat ? `<div class="note">${esc(x.caveat)}</div>` : ''}
        </li>`).join('')}</ul>`
    : '';

  const notFound = report.policy?.notFound?.length
    ? `<p class="note"><strong>Topics Observa looked for and did not find:</strong> ${
        report.policy.notFound.map(esc).join(', ')}. This is a limit of the scanner's patterns, not a statement that the policy is silent on them.</p>`
    : '';

  // ── Limitations ──────────────────────────────────────────────────────────
  const limitations = `<ul class="lims">${(report.limitations ?? []).map(l => `<li>${esc(l)}</li>`).join('')}</ul>`;

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Observa report — ${esc(m.host ?? 'scan')}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 28px 56px;
    font: 14px/1.6 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #15181d; background: #fff; max-width: 900px; margin-inline: auto;
  }
  .brand { font-weight: 800; letter-spacing: -.02em; font-size: 15px; color: #6d4aff; }
  h1 { font-size: 25px; line-height: 1.2; margin: 6px 0 16px; letter-spacing: -.02em; }
  h2 { font-size: 16px; margin: 0 0 10px; letter-spacing: -.01em; }
  .hd { border-bottom: 2px solid #15181d; padding-bottom: 18px; margin-bottom: 4px; }
  dl.meta { display: grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); gap: 8px 20px; margin: 0 0 14px; }
  dl.meta div { min-width: 0; }
  dl.meta dt { font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; font-weight: 700; }
  dl.meta dd { margin: 2px 0 0; overflow-wrap: anywhere; }
  .redbar, .warnbar { font-size: 12.5px; padding: 9px 12px; border-radius: 6px; margin: 0; }
  .redbar  { background: #eef2ff; border: 1px solid #c7d2fe; color: #3730a3; }
  .warnbar { background: #fff7ed; border: 1px solid #fed7aa; color: #9a3412; }
  .s { padding: 22px 0 4px; border-bottom: 1px solid #e5e7eb; }
  .s:last-of-type { border-bottom: 0; }
  .note { font-size: 12px; color: #6b7280; margin: 8px 0 0; }
  .empty { font-size: 13px; color: #6b7280; font-style: italic; margin: 6px 0 0; }
  .muted { color: #9ca3af; }
  .small { font-size: 12px; }
  .num { font-variant-numeric: tabular-nums; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0 0; font-size: 12.5px; }
  th { text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: .07em;
       color: #6b7280; border-bottom: 1.5px solid #d1d5db; padding: 7px 8px; }
  /* Break long URLs and tokens, but never split an ordinary word: a narrow
     column was rendering "Advertising" as "Advertisin / g". */
  td { padding: 8px; border-bottom: 1px solid #eef0f3; vertical-align: top;
       word-break: normal; overflow-wrap: break-word; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          overflow-wrap: anywhere; }
  .verdict { border-left: 4px solid #444; padding: 12px 0 12px 14px; margin: 4px 0 16px; }
  .vlabel { font-size: 10px; text-transform: uppercase; letter-spacing: .09em; font-weight: 800; }
  .vhead { font-size: 17px; font-weight: 650; margin: 4px 0 8px; line-height: 1.35; }
  ul.reasons { margin: 0 0 8px; padding-left: 18px; }
  ul.reasons li { margin: 3px 0; }
  .conf { font-size: 12.5px; margin: 8px 0 0; color: #374151; }
  ul.findings, ul.cmp, ul.docs, ul.lims { list-style: none; margin: 8px 0 0; padding: 0; }
  ul.findings li, ul.cmp li { padding: 9px 0 9px 12px; border-left: 3px solid #d1d5db; margin-bottom: 8px; }
  ul.findings li.sev-high { border-left-color: #a3291f; }
  ul.findings li.sev-medium { border-left-color: #9a6400; }
  ul.lims li { padding: 5px 0 5px 16px; position: relative; font-size: 12.5px; color: #374151; }
  ul.lims li::before { content: '\\2014'; position: absolute; left: 0; color: #9ca3af; }
  ul.docs li { font-size: 12.5px; padding: 3px 0; overflow-wrap: anywhere; }
  .ftitle { font-weight: 650; }
  .fdetail { font-size: 12.5px; color: #374151; margin-top: 3px; }
  .quote { font-style: italic; color: #374151; font-size: 12.5px; }
  .tag { display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px;
         border-radius: 4px; white-space: nowrap; }
  .tag-warn { background: #fff7ed; color: #9a3412; }
  footer { margin-top: 28px; padding-top: 14px; border-top: 1px solid #e5e7eb;
           font-size: 11.5px; color: #6b7280; }
  @media print {
    body { padding: 0; max-width: none; font-size: 11pt; }
    .s { page-break-inside: auto; border-bottom: 1px solid #ccc; }
    h2 { page-break-after: avoid; }
    tr, ul.findings li, ul.cmp li { page-break-inside: avoid; }
    thead { display: table-header-group; }
    .redbar, .warnbar { border-width: 1px; }
    a { text-decoration: none; color: inherit; }
  }
</style>
</head><body>
${header}
${section('Assessment', assessment + countsTable)}
${section('Findings', findings, 'Everything below was observed during this page visit or read from the site’s own published documents.')}
${section('Data seen leaving the page', exposures)}
${section('Other companies contacted', thirdParties)}
${section('Cookies', cookies)}
${section('Network requests', requests)}
${section('Policy analysis', policyDocs + policyFindings + comparisons + notFound)}
${section('What this report does not cover', limitations)}
<footer>
  Generated by Observa from a single page visit. Informational analysis of observed network
  activity and published policy text — not legal advice, and not a compliance assessment.
</footer>
</body></html>`;
}
