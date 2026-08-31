// Unit test for background/list-refresh.js's parsers — validated against
// REAL sample data fetched from the actual upstream sources (saved to /tmp
// by the same curl commands used during development), not synthetic
// fixtures, so this proves the parser matches the real current schema.
//
// list-refresh.js references chrome.alarms at module top level (to register
// its onAlarm listener), so a minimal chrome stub is installed before import
// — this test exercises the pure parsing functions only, not the chrome.*
// plumbing (which needs a real extension context; see new-features-verify.js
// for that).
import fs from 'fs';

globalThis.chrome = {
  alarms: { onAlarm: { addListener() {} } },
  storage: { onChanged: { addListener() {} }, local: { get: async () => ({}), set: async () => {} } },
};

const { parseDisconnectList, parseCookieCsv, splitCsvLine } =
  await import('../background/list-refresh.js');

let failures = 0;
function assert(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}${detail !== undefined ? ' :: ' + detail : ''}`);
  if (!cond) failures++;
}

// ── splitCsvLine ─────────────────────────────────────────────────────────
{
  const fields = splitCsvLine('a,b,"c, with comma",d');
  assert('CSV: quoted field with embedded comma stays one field', fields.length === 4 && fields[2] === 'c, with comma', JSON.stringify(fields));
}
{
  const fields = splitCsvLine('a,"she said ""hi""",c');
  assert('CSV: doubled-quote escaping decodes to a literal quote', fields[1] === 'she said "hi"', JSON.stringify(fields));
}
{
  const fields = splitCsvLine('a,,c');
  assert('CSV: empty field between commas preserved', fields.length === 3 && fields[1] === '', JSON.stringify(fields));
}

// ── parseDisconnectList — against a small fixture matching the real schema ─
{
  const fixture = {
    license: 'test',
    categories: {
      Advertising: [{ AcmeAds: { 'https://acmeads.example/': ['acmeads.example', 'cdn.acmeads.example'] } }],
      FingerprintingInvasive: [{ SpyCo: { 'https://spy.example/': ['spy.example'] } }],
      FingerprintingGeneral: [{ SpyCo2: { 'https://spy2.example/': ['spy2.example'] } }],
      Email: [{ MailCo: { 'https://mail.example/': ['mail.example'] } }], // should be excluded
    },
  };
  const out = parseDisconnectList(fixture);
  assert('Advertising domain mapped with correct org/category', JSON.stringify(out['acmeads.example']) === JSON.stringify(['AcmeAds', 'Advertising']));
  assert('Second domain under same org also mapped', JSON.stringify(out['cdn.acmeads.example']) === JSON.stringify(['AcmeAds', 'Advertising']));
  assert('FingerprintingInvasive folds into "Fingerprinting"', out['spy.example']?.[1] === 'Fingerprinting');
  assert('FingerprintingGeneral folds into "Fingerprinting"', out['spy2.example']?.[1] === 'Fingerprinting');
  assert('Email category is excluded (not in WebLens\'s 8-category taxonomy)', out['mail.example'] === undefined);
}

// ── parseDisconnectList — against the REAL current upstream file ──────────
{
  const raw = JSON.parse(fs.readFileSync(new URL('./fixtures/disconnect-sample.json', import.meta.url), 'utf8'));
  const out = parseDisconnectList(raw);
  const count = Object.keys(out).length;
  assert('real Disconnect list parses to a substantial domain count', count > 2000, count);
  assert('known domain "doubleclick.net" classified as Advertising', out['doubleclick.net']?.[1] === 'Advertising', JSON.stringify(out['doubleclick.net']));
  assert('known domain "google-analytics.com" present', !!out['google-analytics.com'], JSON.stringify(out['google-analytics.com']));
  const categoriesUsed = new Set(Object.values(out).map(v => v[1]));
  const allowed = new Set(['Advertising','Analytics','Social','Fingerprinting','Cryptomining','Content','Anti-fraud','Consent']);
  const bad = [...categoriesUsed].filter(c => !allowed.has(c));
  assert('every parsed category is one of WebLens\'s 8 known categories', bad.length === 0, JSON.stringify(bad));
}

// ── parseCookieCsv — against the REAL current upstream file ───────────────
{
  const csvText = fs.readFileSync(new URL('./fixtures/cookiedb-sample.csv', import.meta.url), 'utf8');
  const db = parseCookieCsv(csvText);
  const exactCount = Object.keys(db.exact).length;
  assert('real cookie CSV parses to a substantial exact-match count', exactCount > 1000, exactCount);
  assert('real cookie CSV parses wildcard entries', db.wildcard.length > 50, db.wildcard.length);
  assert('exact entry has the short-key shape {p,c,d,r,dc} matching the bundled format', 'p' in Object.values(db.exact)[0] && 'dc' in Object.values(db.exact)[0], Object.keys(Object.values(db.exact)[0]));
  const ga = db.wildcard.find(w => w.n === '_ga_') || db.wildcard.find(w => w.n === '_ga');
  assert('a Google Analytics wildcard entry is present', !!ga, JSON.stringify(db.wildcard.slice(0,3)));
  // Field values should never be truncated garbage — spot check a known row survives with a real description.
  const cookiePrefs = db.exact['cookiePreferences'];
  assert('a known cookie (cookiePreferences) parses with a non-empty description', !!cookiePrefs && cookiePrefs.d.length > 5, JSON.stringify(cookiePrefs));
}

console.log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
