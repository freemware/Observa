// Observa Data Exposure Detector — classify/exposure.js (v0.11.0)
//
// Parses each request's URL query string and (when present) its POST body
// for locally-recognizable patterns of information leaving the page —
// emails, phone-shaped strings, coordinates, ZIP codes, and known
// tracking/campaign identifier parameter names. Everything here runs
// entirely inside the extension, synchronously, on data Observa already
// observes via the existing `webRequest` permission (adding the
// `requestBody` extra-info option to the existing listener does not
// require a new manifest permission).
//
// Provenance: OBSERVED — a match means this literal string was seen in an
// outgoing request. It is not proof the value is real, accurate, or tied
// to the visiting user (a page can send junk, defaults, or someone else's
// data), and Observa has no way to confirm that — see the caveat surfaced
// in the UI.
//
// Each finding carries both `redacted` (what's shown by default) and `raw`
// (the exact matched substring — e.g. just the email address, never the
// whole URL/body/cookie it was found in). The UI shows `redacted` unless
// the user explicitly clicks "Show" on that one finding (v0.12.0) — this is
// a deliberate, user-directed exception to "redact by default," not a
// removal of it: `raw` is still only ever the narrow matched pattern, never
// the full request/cookie payload, and it never appears in a console.log or
// error report (CLAUDE.md Rule 2 — "never write cookie values or full URLs
// with query strings to logs" — applies to logs, not to a value the user
// explicitly asks Observa to display).
//
// v0.12.0 also added detectValueExposure() below, which runs these same
// detectors against a single name/value pair — used by cookies.js to check
// whether a cookie's *value* (not just its metadata) looks like it carries
// an email, phone number, or similar pattern. See cookies.js for what that
// does and does not change about cookie handling.

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
// Conservative: requires separators, so it doesn't fire on arbitrary
// numeric IDs. Still pattern-based, so false positives (e.g. order/tracking
// numbers formatted like phone numbers) are possible — labelled Inferred.
const PHONE_RE = /(?:\+?\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/;
const ZIP_RE = /\b\d{5}(?:-\d{4})?\b/;
const LATLONG_PAIR_RE = /(-?\d{1,3}\.\d{3,})\s*,\s*(-?\d{1,3}\.\d{3,})/;

const LAT_PARAM_NAMES = new Set(['lat', 'latitude']);
const LNG_PARAM_NAMES = new Set(['lng', 'lon', 'long', 'longitude']);
const ZIP_PARAM_NAMES = new Set(['zip', 'zipcode', 'zip_code', 'postal', 'postalcode', 'postal_code']);
const EMAIL_PARAM_HINTS = ['email', 'mail', 'e_mail'];
const PHONE_PARAM_HINTS = ['phone', 'tel', 'mobile', 'msisdn'];

// Known tracking/identifier parameter names — shown verbatim if they look
// like low-sensitivity labels (campaign names), redacted if they look like
// an opaque identifier (long alphanumeric token).
const ID_PARAMS = new Map([
  ['uid', 'Persistent identifier'], ['user_id', 'Persistent identifier'], ['userid', 'Persistent identifier'],
  ['client_id', 'Analytics client ID'], ['clientid', 'Analytics client ID'], ['_ga', 'Google Analytics ID'],
  ['ga_id', 'Google Analytics ID'], ['gaid', 'Advertising ID'], ['idfa', 'Advertising ID (iOS)'],
  ['aaid', 'Advertising ID (Android)'], ['advertising_id', 'Advertising ID'], ['adid', 'Advertising ID'],
  ['fbclid', 'Facebook click ID'], ['fbp', 'Facebook browser ID'], ['gclid', 'Google click ID'],
  ['dclid', 'Google Display click ID'], ['msclkid', 'Microsoft click ID'], ['ttclid', 'TikTok click ID'],
  ['session_id', 'Session identifier'], ['sessionid', 'Session identifier'], ['sid', 'Session identifier'],
]);
const CAMPAIGN_PARAMS = new Map([
  ['campaign', 'Campaign'], ['utm_campaign', 'Campaign'], ['utm_source', 'Traffic source'],
  ['utm_medium', 'Traffic medium'], ['utm_term', 'Search term (campaign)'], ['utm_content', 'Ad content variant'],
]);
const PAGE_PARAMS = new Set(['page', 'url', 'loc', 'location', 'referrer', 'ref']);

function redactEmail(v) {
  const at = v.indexOf('@');
  if (at < 1) return '•••';
  return `${v[0]}***${v.slice(at)}`;
}
function redactPhone(v) {
  const digits = v.replace(/\D/g, '');
  return digits.length >= 4 ? `***-***-${digits.slice(-4)}` : '***';
}
function redactZip(v) {
  return v.length >= 3 ? `${v.slice(0, 3)}**` : '*****';
}
function redactCoord(lat, lng) {
  // City-level precision only (~11km at 1 decimal place) — never the exact point.
  const round1 = n => Math.round(parseFloat(n) * 10) / 10;
  return `~${round1(lat)}, ${round1(lng)} (approx., rounded)`;
}
function redactId(v) {
  if (v.length <= 4) return '•'.repeat(v.length);
  return `${'•'.repeat(Math.min(6, v.length - 4))}${v.slice(-4)}`;
}

function looksLikeOpaqueToken(v) {
  return /^[a-zA-Z0-9._-]{6,}$/.test(v) && /\d/.test(v);
}

/**
 * @param {[string,string][]} entries - key/value pairs from a query string or form body
 * @param {'query'|'body'} source
 * @returns {Array<{type:string,label:string,redacted:string,paramName:string,source:string,provenance:string}>}
 */
function scanEntries(entries, source) {
  const found = [];
  let sawIdSignal = false;

  for (const [rawKey, rawVal] of entries) {
    if (!rawVal) continue;
    const key = rawKey.toLowerCase();
    const val = String(rawVal);

    if (EMAIL_PARAM_HINTS.some(h => key.includes(h)) && EMAIL_RE.test(val)) {
      const m = val.match(EMAIL_RE)[0];
      found.push({ type: 'email', label: 'Email address', redacted: redactEmail(m), raw: m, paramName: rawKey, source, provenance: 'Observed' });
      sawIdSignal = true;
      continue;
    }
    if (EMAIL_RE.test(val)) {
      const m = val.match(EMAIL_RE)[0];
      found.push({ type: 'email', label: 'Email address', redacted: redactEmail(m), raw: m, paramName: rawKey, source, provenance: 'Observed' });
      sawIdSignal = true;
      continue;
    }
    if (PHONE_PARAM_HINTS.some(h => key.includes(h)) && PHONE_RE.test(val)) {
      found.push({ type: 'phone', label: 'Phone number', redacted: redactPhone(val), raw: val, paramName: rawKey, source, provenance: 'Inferred' });
      sawIdSignal = true;
      continue;
    }
    if (ZIP_PARAM_NAMES.has(key) && ZIP_RE.test(val)) {
      found.push({ type: 'zip', label: 'ZIP / postal code', redacted: redactZip(val), raw: val, paramName: rawKey, source, provenance: 'Observed' });
      sawIdSignal = true;
      continue;
    }
    if (ID_PARAMS.has(key)) {
      const label = ID_PARAMS.get(key);
      found.push({ type: 'id', label, redacted: looksLikeOpaqueToken(val) ? redactId(val) : val, raw: val, paramName: rawKey, source, provenance: 'Observed' });
      sawIdSignal = true;
      continue;
    }
    if (CAMPAIGN_PARAMS.has(key)) {
      found.push({ type: 'campaign', label: CAMPAIGN_PARAMS.get(key), redacted: val.length > 60 ? val.slice(0, 60) + '…' : val, raw: val, paramName: rawKey, source, provenance: 'Observed' });
      continue;
    }
  }

  // Lat/long as a pair of named params (lat=..&lng=..)
  const byKey = new Map(entries.map(([k, v]) => [k.toLowerCase(), v]));
  let latVal = null, lngVal = null;
  for (const k of LAT_PARAM_NAMES) if (byKey.has(k)) latVal = byKey.get(k);
  for (const k of LNG_PARAM_NAMES) if (byKey.has(k)) lngVal = byKey.get(k);
  if (latVal != null && lngVal != null) {
    found.push({ type: 'geo', label: 'Coordinates', redacted: redactCoord(latVal, lngVal), raw: `${latVal}, ${lngVal}`, paramName: 'lat/lng', source, provenance: 'Observed' });
    sawIdSignal = true;
  }

  // Page context — only surfaced alongside a genuine tracking signal, not
  // as a standalone finding on every request (that would just be noise).
  if (sawIdSignal) {
    for (const [k, v] of entries) {
      if (PAGE_PARAMS.has(k.toLowerCase()) && v && String(v).length < 200) {
        found.push({ type: 'page', label: 'Page viewed', redacted: String(v), raw: String(v), paramName: k, source, provenance: 'Observed' });
        break; // one is enough for context
      }
    }
  }

  return found;
}

function parseQuery(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()];
  } catch { return []; }
}

/**
 * @param {chrome.webRequest.WebRequestBodyDetails['requestBody']} requestBody
 * @returns {[string,string][]}
 */
function parseBody(requestBody) {
  if (!requestBody) return [];
  const entries = [];
  if (requestBody.formData) {
    for (const [k, vals] of Object.entries(requestBody.formData)) {
      for (const v of vals) entries.push([k, v]);
    }
    return entries;
  }
  if (requestBody.raw?.length) {
    try {
      const bytes = requestBody.raw.map(chunk => chunk.bytes).filter(Boolean);
      if (!bytes.length) return [];
      const totalLen = bytes.reduce((n, b) => n + b.byteLength, 0);
      if (totalLen > 20000) return []; // cap — avoid decoding huge uploads/binary blobs
      const merged = new Uint8Array(totalLen);
      let offset = 0;
      for (const b of bytes) { merged.set(new Uint8Array(b), offset); offset += b.byteLength; }
      const text = new TextDecoder('utf-8', { fatal: false }).decode(merged);
      // Try JSON first (flatten one level of keys)
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') {
          for (const [k, v] of Object.entries(parsed)) {
            if (v == null) continue;
            if (typeof v === 'object') continue; // skip nested objects — one level only
            entries.push([k, String(v)]);
          }
          return entries;
        }
      } catch { /* not JSON */ }
      // Try form-urlencoded
      if (/^[\w.%+-]+=.*/.test(text)) {
        try {
          for (const [k, v] of new URLSearchParams(text).entries()) entries.push([k, v]);
          if (entries.length) return entries;
        } catch { /* fall through */ }
      }
      // Last resort: scan raw text for an email/phone pattern with no known key name
      const emailMatch = text.match(EMAIL_RE);
      if (emailMatch) entries.push(['(raw body)', emailMatch[0]]);
    } catch { /* decoding failed — skip */ }
  }
  return entries;
}

/**
 * @param {string} url
 * @param {object|undefined} requestBody - chrome.webRequest's requestBody, when captured
 * @returns {Array<{type:string,label:string,redacted:string,raw:string,paramName:string,source:string,provenance:string}>} exposures, deduplicated by type+paramName
 */
export function detectExposures(url, requestBody) {
  const queryEntries = parseQuery(url);
  const bodyEntries = parseBody(requestBody);

  const all = [
    ...scanEntries(queryEntries, 'query'),
    ...scanEntries(bodyEntries, 'body'),
  ];

  const seen = new Set();
  return all.filter(e => {
    const key = `${e.type}:${e.paramName}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * v0.12.0 — same pattern detectors as detectExposures(), applied to a single
 * cookie's name/value pair instead of a URL/body. Used by cookies.js to
 * check whether a cookie's *value* looks like it carries an email, phone
 * number, ZIP, or similar pattern — cookies.js still never returns or
 * stores the cookie's full raw value itself, only whatever this returns
 * (the matched substring, if any, plus its type/label).
 * @param {string} name - the cookie's name
 * @param {string} value - the cookie's value
 * @returns {Array<{type:string,label:string,redacted:string,raw:string,paramName:string,source:string,provenance:string}>}
 */
export function detectValueExposure(name, value) {
  if (!value) return [];
  const direct = scanEntries([[name, value]], 'cookie').filter(e => e.type !== 'page' && e.type !== 'campaign');
  if (direct.length) return direct;
  // chrome.cookies.getAll() returns a cookie's value exactly as stored on
  // the wire — unlike URL query params (already decoded by URLSearchParams
  // before scanEntries sees them), a cookie value that's itself URL-encoded
  // (common in practice — e.g. session=user%40example.com) would otherwise
  // never match EMAIL_RE/etc. Try once more against the decoded form so
  // this doesn't silently miss a common real-world shape. decodeURIComponent
  // throws on malformed %-sequences, so this is best-effort only.
  let decoded;
  try { decoded = decodeURIComponent(value); } catch { return []; }
  if (decoded === value) return [];
  return scanEntries([[name, decoded]], 'cookie').filter(e => e.type !== 'page' && e.type !== 'campaign');
}
