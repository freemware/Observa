// Unit test for classify/classify.js's getEtld1() — specifically the IPv4/
// IPv6 handling bug found while testing M6 blocking against a local (IP-
// hosted) test page: "127.0.0.1" was being sliced like a domain name and
// truncated to its last two octets ("0.1"), which silently misfiles any
// site-scoped block rule created on an IP-hosted page under the wrong
// site key. No chrome.* stub needed — classify.js's eTLD+1 logic is a pure
// function with no chrome dependency.
const { getEtld1, getParty } = await import('../classify/classify.js');

let failures = 0;
function assert(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}${detail !== undefined ? ' :: ' + detail : ''}`);
  if (!cond) failures++;
}

// ── IPv4 ────────────────────────────────────────────────────────────────
assert('IPv4 loopback returns itself, not truncated octets', getEtld1('127.0.0.1') === '127.0.0.1', getEtld1('127.0.0.1'));
assert('IPv4 arbitrary address returns itself', getEtld1('192.168.1.42') === '192.168.1.42', getEtld1('192.168.1.42'));
assert('IPv4 with a port-like trailing junk still not mistaken for a domain (defensive)', getEtld1('10.0.0.1') === '10.0.0.1', getEtld1('10.0.0.1'));

// ── IPv6 ────────────────────────────────────────────────────────────────
assert('IPv6 loopback returns itself', getEtld1('::1') === '::1', getEtld1('::1'));
assert('IPv6 full address returns itself', getEtld1('fe80::1234:5678') === 'fe80::1234:5678', getEtld1('fe80::1234:5678'));

// ── Ordinary domains — must be unaffected by the IP-detection guard ──────
assert('Plain two-part domain unchanged', getEtld1('example.com') === 'example.com', getEtld1('example.com'));
assert('Subdomain reduces to eTLD+1', getEtld1('www.example.com') === 'example.com', getEtld1('www.example.com'));
assert('Multi-part TLD (co.uk) keeps three parts', getEtld1('www.example.co.uk') === 'example.co.uk', getEtld1('www.example.co.uk'));
assert('Deep subdomain still reduces correctly', getEtld1('a.b.c.example.com') === 'example.com', getEtld1('a.b.c.example.com'));

// ── The real regression this bug caused: party detection + site-scoped
// blocking both key off getEtld1(pageUrl hostname) matching the block
// rule's initiatorDomains. Confirm an IP-hosted page and a same-IP request
// are correctly treated as first-party (matches the pre-bug expectation:
// a page loading its own resources from itself is first-party) rather than
// silently mismatching due to truncation. ──────────────────────────────
assert('IP-hosted page + same-IP resource -> first-party', getParty('127.0.0.1', 'http://127.0.0.1:8080/') === 'first-party', getParty('127.0.0.1', 'http://127.0.0.1:8080/'));
assert('IP-hosted page + real third-party domain -> third-party', getParty('example.com', 'http://127.0.0.1:8080/') === 'third-party', getParty('example.com', 'http://127.0.0.1:8080/'));

console.log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
