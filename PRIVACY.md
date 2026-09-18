# Observa Privacy Policy

*Last updated: September 2026*

## Summary

Observa runs entirely on your device. It has no backend server, no account
system, and does not transmit your browsing activity, cookies, or any data
about the sites you visit to Observa's developer or to any third party.

## What Observa observes

While an Observa session is active on a tab, the extension uses Chrome's own
`webRequest`, `webNavigation`, and `cookies` APIs to observe, for that tab:

- Which domains your browser contacts, and whether each is first-party or
  third-party to the site you're visiting.
- Basic request metadata (URL, request type, timing, and whether a request
  succeeded, failed, or was blocked).
- Cookie metadata (domain, path, expiry, security flags) set by the site.
- Whether a request's URL/POST body, or a cookie's value, contains a pattern
  that commonly indicates personal or tracking data (an email address, a
  phone number, a ZIP/postal code, a latitude/longitude pair, or a known
  tracking-ID parameter such as `fbclid`/`gclid`). This is a local pattern
  match only — Observa does not claim the matched value is accurate, real,
  or verified to belong to you, only that a request or cookie contained
  something matching the pattern.

All of this is processed and stored **locally, in your browser's own
per-tab session storage**, and is cleared automatically when you restart
your browser. It is never sent anywhere.

## What Observa does NOT do

- Observa does not have a server, and does not send your browsing data,
  cookie values, or any personally identifying information to Observa's
  developer or any third party.
- Observa does not sell or share data with advertisers or data brokers.
- Observa does not use your data to train any model.
- Observa does not track you across the sites you use it on — each tab's
  session is independent and (unless you opt in to the feature below) is
  discarded when that session ends.
- Cookie **values** are read only transiently, in memory, to check them
  against the pattern-matching described above. The actual cookie value is
  never stored, logged, or included in any message Observa's own UI
  components exchange — only the redacted/matched-pattern result is kept.

## Optional, opt-in features that store data longer

Two features are **off by default** and only take effect if you explicitly
turn them on in the dashboard's Settings panel:

- **Session history.** If enabled, Observa saves one summarized record per
  site per day — counts only (number of third-party domains, cookies, and
  tracker matches). It never stores URLs, cookie names, or cookie values.
  Records are capped in size, automatically aged out, and can be cleared
  at any time with a "Clear history data" control.
- **Tracker/cookie list refresh.** If enabled, Observa periodically
  re-downloads its bundled tracker and cookie classification lists from
  their original public sources (the Disconnect Tracking Protection list
  and the Open Cookie Database) so classification data stays current. This
  is the one case where Observa itself initiates a network request — it
  fetches two fixed, publicly documented URLs and sends no data about you,
  your browsing, or your device. You can revert to the bundled snapshot at
  any time.

## Blocking feature

If you choose to block a tracker on a specific site, Observa creates a
local Chrome `declarativeNetRequest` rule scoped to that site only. This
happens only when you explicitly click "Block" — never automatically or
based on classification alone — and can be undone at any time.

## Permissions, and why Observa requests them

| Permission | Why it's needed |
|---|---|
| `webRequest` | Observe which domains a page contacts and what it sends, including POST bodies for the exposure-pattern check described above. |
| `webNavigation` | Detect when a new page loads, to start/end a session at the right time. |
| `cookies` | Read cookie metadata (and, transiently, values for the pattern check) for the active site. |
| `storage` | Save your settings and, if enabled, session history — all locally. |
| `tabs` | Associate captured activity with the correct tab, and reload the tab as part of the block/unblock workflow. |
| `publicSuffix` | Correctly determine first-party vs. third-party domains. |
| `declarativeNetRequest` | Block a tracker on a site, only when you explicitly ask to. |
| `alarms` | Schedule the optional, opt-in daily tracker-list refresh. |
| Host permission (all sites) | Required so Observa can observe activity on whatever site you're currently visiting — it does not grant Observa the ability to modify page content. |

## Changes to this policy

If Observa's data practices change, this document will be updated and the
extension's changelog will note it.

## Contact

Questions about this policy or Observa's source code can be raised via the
project's GitHub repository: https://github.com/freemware/Observa
