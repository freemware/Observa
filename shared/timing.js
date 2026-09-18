// Observa — shared/timing.js
//
// Separates requests that happened while the page was loading from requests
// that happened *later* — after the page went quiet.
//
// ── Why this is the most differentiating signal Observa has ────────────────
// Every automated privacy scanner (Blacklight and friends) drives a headless
// browser that loads a URL and leaves. It never logs in, never focuses a form,
// never reaches a checkout step. Observa watches a real person's real session,
// so it sees the requests that fire *because of what the person did* — and
// those are frequently the ones carrying actual personal data, because that is
// when the person actually typed something.
//
// Nothing here needs a new permission. Every request already carries a
// `timestamp`; this module only does arithmetic on timestamps that were
// captured anyway.
//
// ── What this can and cannot claim ─────────────────────────────────────────
// Observa has no content script, so it CANNOT see clicks, focus, typing, or
// form submission. It sees only *when* a request happened. So:
//
//   - "During page load" is close to Observed — it is simply early.
//   - "After the page settled" is **Inferred**, and the honest wording is that
//     late requests are *often* caused by something the person did, while a
//     timer, a poll, a lazy-loaded widget, or a background refresh can produce
//     exactly the same shape. The UI must say so, and must never assert "you
//     clicked X" or "this was triggered by your form entry".
//
// Getting this wrong would be a textbook CLAUDE.md Rule 3 violation — claiming
// visibility Observa does not have — so the label is deliberately about the
// page ("after the page settled"), not about the person ("after you typed").
//
// Pure functions over plain data — no chrome.* APIs, no DOM.

const DEFAULT_FLOOR_MS = 3000;    // never call anything inside 3s "later"
const DEFAULT_QUIET_GAP_MS = 2000; // a 2s lull means the load burst is over

/**
 * Finds the moment the initial load burst ended, relative to the first request.
 *
 * A fixed threshold alone is wrong: a slow page can still be loading at 6s, and
 * flagging its own assets as "later" would be a false positive. So the burst
 * end is found adaptively — walk the sorted request times and stop at the first
 * quiet gap — and then floored, so a fast page doesn't produce a 200ms cutoff
 * that flags ordinary deferred analytics.
 *
 * @param {number[]} timestamps - raw request timestamps (epoch ms)
 * @param {{floorMs?:number, quietGapMs?:number}} [opts]
 * @returns {{t0:number|null, settleMs:number}} settleMs is relative to t0
 */
export function computeSettlePoint(timestamps, opts = {}) {
  const floorMs = opts.floorMs ?? DEFAULT_FLOOR_MS;
  const quietGapMs = opts.quietGapMs ?? DEFAULT_QUIET_GAP_MS;

  const times = (timestamps ?? []).filter(t => typeof t === 'number' && isFinite(t)).sort((a, b) => a - b);
  if (!times.length) return { t0: null, settleMs: floorMs };

  const t0 = times[0];
  let burstEnd = 0;
  for (let i = 1; i < times.length; i++) {
    if (times[i] - times[i - 1] >= quietGapMs) break;
    burstEnd = times[i] - t0;
  }
  return { t0, settleMs: Math.max(floorMs, burstEnd) };
}

/**
 * @param {number|null|undefined} ts - the request's timestamp (epoch ms)
 * @param {number|null} t0 - the session's first request timestamp
 * @param {number} settleMs
 * @returns {{phase:'load'|'later'|'unknown', elapsedMs:number|null,
 *            label:string, provenance:'Observed'|'Inferred'}}
 */
export function classifyTiming(ts, t0, settleMs) {
  if (typeof ts !== 'number' || typeof t0 !== 'number' || !isFinite(ts) || !isFinite(t0)) {
    return { phase: 'unknown', elapsedMs: null, label: 'Timing unknown', provenance: 'Inferred' };
  }
  const elapsedMs = Math.max(0, ts - t0);
  if (elapsedMs < settleMs) {
    return { phase: 'load', elapsedMs, label: 'During page load', provenance: 'Observed' };
  }
  return {
    phase: 'later',
    elapsedMs,
    label: `After the page settled · ${formatElapsed(elapsedMs)} in`,
    provenance: 'Inferred',
  };
}

export function formatElapsed(ms) {
  if (typeof ms !== 'number' || !isFinite(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60000)}m`;
}

// The single caveat every surface that shows a 'later' phase must carry.
export const LATER_CAVEAT =
  'Observa can’t see clicks or typing — only when a request happened. Requests after the page settles are often caused by something you did, but a timer, a lazy-loaded widget, or a background refresh looks identical.';
