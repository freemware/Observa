// Unit test for buildTrendDiff() (dashboard.js) — extracted verbatim so it
// can be exercised without the full browser/session harness, which hits an
// unrelated Playwright-only "about:blank first navigation" artifact when
// testing end to end (see redesign-verify.js comments). This validates the
// actual date math and delta wording shipped in dashboard.js.
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'ui', 'dashboard', 'dashboard.js'), 'utf8');
const m = src.match(/function buildTrendDiff\(days\) \{[\s\S]*?\n\}\n/);
if (!m) { console.error('FAIL: could not locate buildTrendDiff() in dashboard.js'); process.exit(1); }

const icon = (name) => `<svg data-icon="${name}"></svg>`;
const esc = s => String(s);
// eslint-disable-next-line no-eval
const buildTrendDiff = eval(`(function(){ ${m[0]}; return buildTrendDiff; })()`);

let failures = 0;
function assert(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}${detail !== undefined ? ' :: ' + detail : ''}`);
  if (!cond) failures++;
}

// 1. Fewer than 2 days -> no diff shown
assert('empty for <2 days', buildTrendDiff([{ date:'2026-08-27', thirdPartyCount:1, trackerCount:1, cookieCount:1, longLivedCookieCount:0 }]) === '');

// 2. No change between the two most recent days -> "No change" message
const noChange = buildTrendDiff([
  { date:'2026-08-20', thirdPartyCount:3, trackerCount:1, cookieCount:5, longLivedCookieCount:1 },
  { date:'2026-08-27', thirdPartyCount:3, trackerCount:1, cookieCount:5, longLivedCookieCount:1 },
]);
assert('no-change message when all counts equal', /No change in tracking activity/.test(noChange), noChange);

// 3. Trackers + third-party increased -> "added" wording, warning tone
const today = new Date();
const yesterday = new Date(today.getTime() - 86400000);
const iso = d => d.toISOString().slice(0,10);
const added = buildTrendDiff([
  { date: iso(yesterday), thirdPartyCount:3, trackerCount:1, cookieCount:5, longLivedCookieCount:1 },
  { date: iso(today),     thirdPartyCount:5, trackerCount:3, cookieCount:6, longLivedCookieCount:2 },
]);
assert('increase -> "added" verb used', /added/.test(added), added.replace(/\s+/g,' '));
assert('increase -> mentions 2 trackers', /added <strong>2 trackers<\/strong>/.test(added), added.replace(/\s+/g,' '));
assert('increase -> mentions 2 third-party domains', /added <strong>2 third-party domains<\/strong>/.test(added), added.replace(/\s+/g,' '));
assert('increase -> singular cookie (1 not 1s)', /added <strong>1 cookie<\/strong>/.test(added), added.replace(/\s+/g,' '));
assert('increase -> since <weekday> (recent date)', /since <strong>\w+<\/strong>/.test(added), added.replace(/\s+/g,' '));
assert('increase -> warning tone icon used', /alert-triangle/.test(added));

// 4. Decrease only -> "removed" wording, positive/trending-up tone
const removed = buildTrendDiff([
  { date: iso(yesterday), thirdPartyCount:5, trackerCount:3, cookieCount:6, longLivedCookieCount:2 },
  { date: iso(today),     thirdPartyCount:3, trackerCount:1, cookieCount:6, longLivedCookieCount:2 },
]);
assert('decrease -> "removed" verb used', /removed/.test(removed), removed.replace(/\s+/g,' '));
assert('decrease -> no "added" wording', !/added/.test(removed));
assert('decrease -> trending-up icon used (good news)', /trending-up/.test(removed));

// 5. Old date (>6 days ago) falls back to month/day format instead of weekday
const old = buildTrendDiff([
  { date:'2026-08-01', thirdPartyCount:1, trackerCount:0, cookieCount:1, longLivedCookieCount:0 },
  { date: iso(today),  thirdPartyCount:2, trackerCount:1, cookieCount:1, longLivedCookieCount:0 },
]);
assert('old date -> month/day format, not weekday name', /since <strong>[A-Z][a-z]{2} \d{1,2}<\/strong>/.test(old), old.replace(/\s+/g,' '));

console.log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
