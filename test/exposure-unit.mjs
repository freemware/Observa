// Unit test for classify/exposure.js's detectExposures() — the Data
// Exposure Detector (v0.11.0). Pure module, no chrome.* dependency, so this
// runs directly under Node against the exact shipped file.
import { detectExposures } from '../classify/exposure.js';

let failures = 0;
function assert(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}${detail !== undefined ? ' :: ' + JSON.stringify(detail) : ''}`);
  if (!cond) failures++;
}
const find = (exposures, type, paramName) => exposures.find(e => e.type === type && (!paramName || e.paramName === paramName));

// 1. Email in a hinted query param
{
  const exp = detectExposures('https://analytics.example/collect?email=jane.doe@gmail.com&page=/checkout');
  const e = find(exp, 'email');
  assert('email detected in query param', !!e, exp);
  assert('email redacted (not full value)', e && e.redacted === 'j***@gmail.com', e?.redacted);
  assert('email never contains full local part', e && !e.redacted.includes('jane.doe'));
}

// 2. Phone number with separators in a phone-hinted param
{
  const exp = detectExposures('https://crm.example/track?phone=415-555-1234&uid=abc123');
  const e = find(exp, 'phone');
  assert('phone detected with separators', !!e, exp);
  assert('phone redacted to last 4 digits only', e && e.redacted === '***-***-1234', e?.redacted);
  assert('phone provenance is Inferred (pattern-based)', e?.provenance === 'Inferred');
}

// 3. No phone false-positive on a bare numeric ID (no separators, no hint)
{
  const exp = detectExposures('https://cdn.example/beacon?order_id=4155551234567');
  assert('no phone match on unhinted numeric string', !find(exp, 'phone'));
}

// 4. Lat/long pair
{
  const exp = detectExposures('https://ads.example/loc?lat=37.774900&lng=-122.419400');
  const e = find(exp, 'geo');
  assert('coordinates detected from lat/lng params', !!e, exp);
  assert('coordinates rounded, not exact', e && e.redacted.includes('37.8') && !e.redacted.includes('37.7749'), e?.redacted);
}

// 5. ZIP code in a named param
{
  const exp = detectExposures('https://analytics.example/collect?zip=94107&uid=xyz');
  const e = find(exp, 'zip');
  assert('ZIP detected in zip param', !!e, exp);
  assert('ZIP redacted (only first 3 digits shown)', e && e.redacted === '941**', e?.redacted);
}

// 6. Known tracking-ID param names (Facebook/Google click IDs)
{
  const exp = detectExposures('https://track.example/px?fbclid=IwAR0aBcDeFgHiJkLmNoPqRs&gclid=Cj0KCQjw123456789');
  assert('fbclid recognized', !!find(exp, 'id', 'fbclid'));
  assert('gclid recognized', !!find(exp, 'id', 'gclid'));
  const fb = find(exp, 'id', 'fbclid');
  assert('opaque ID token is redacted, not shown in full', fb && !fb.redacted.includes('IwAR0aBcDeFgHiJkLmNoPqRs') && fb.redacted.endsWith('PqRs'), fb?.redacted);
}

// 7. Campaign params shown verbatim (low sensitivity, useful as-is)
{
  const exp = detectExposures('https://ads.example/px?utm_campaign=summer_sale&utm_source=newsletter');
  const c = find(exp, 'campaign', 'utm_campaign');
  assert('campaign param detected', !!c);
  assert('campaign value shown verbatim (not redacted)', c && c.redacted === 'summer_sale', c?.redacted);
}

// 8. Page context only appears alongside a genuine tracking signal
{
  const withSignal = detectExposures('https://analytics.example/collect?uid=88291&page=/mens-running-shoes');
  assert('page context included when a tracking ID is also present', !!find(withSignal, 'page'));

  const withoutSignal = detectExposures('https://cdn.example/asset?page=/mens-running-shoes');
  assert('page alone (no tracking signal) does NOT surface as a finding', !find(withoutSignal, 'page'));
}

// 9. JSON POST body — one level of keys scanned
{
  const requestBody = {
    raw: [{ bytes: new TextEncoder().encode(JSON.stringify({ email: 'user@example.org', uid: 'abcdef123456', nested: { skip: 'me' } })).buffer }],
  };
  const exp = detectExposures('https://api.example/submit', requestBody);
  assert('email detected in JSON POST body', !!find(exp, 'email'), exp);
  assert('uid detected in JSON POST body', !!find(exp, 'id', 'uid'), exp);
}

// 10. Form-urlencoded POST body via formData
{
  const requestBody = { formData: { email: ['test@site.com'], utm_campaign: ['fall_promo'] } };
  const exp = detectExposures('https://forms.example/submit', requestBody);
  assert('email detected in form-urlencoded body', !!find(exp, 'email'));
  assert('campaign detected in form-urlencoded body', !!find(exp, 'campaign'));
}

// 11. Dedup — same param repeated across calls collapses within one call
{
  const exp = detectExposures('https://x.example/px?uid=123&uid=123');
  const idMatches = exp.filter(e => e.type === 'id' && e.paramName === 'uid');
  assert('duplicate identical param produces exactly one finding', idMatches.length === 1, idMatches.length);
}

// 12. Clean URL with nothing sensitive -> no exposures
{
  const exp = detectExposures('https://example.com/about-us?ref=nav');
  assert('no false positives on an unremarkable URL', exp.length === 0, exp);
}

// 13. redacted field never contains the full raw value (raw field intentionally does,
// as of v0.12.1's reveal-on-demand design — UI shows `redacted` by default and only
// swaps in `raw` on an explicit user click; see classify/exposure.js header comment)
{
  const exp = detectExposures('https://analytics.example/collect?email=someone.private@personaldomain.com');
  const finding = exp.find(e => e.type === 'email');
  assert('redacted field never contains the full email', !finding.redacted.includes('someone.private@personaldomain.com'), finding.redacted);
  assert('raw field holds the exact matched email (by design, for reveal-on-demand)', finding.raw === 'someone.private@personaldomain.com', finding.raw);
}

console.log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
