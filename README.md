# WebLens

WebLens is a Chrome/Brave browser extension that shows what a website is
actually doing behind the scenes — which third-party domains it talks to,
which of those are known trackers or advertisers, what cookies it sets, and
whether anything sent looks like personal or trackable data. It turns raw
network activity into an interactive map instead of a developer console log.

Everything runs **entirely on your machine**. There's no backend and no
server — WebLens observes your browser's own requests locally and never
sends your browsing data anywhere. The one narrow exception is described
below under [Privacy](#privacy).

## Features

- **Live map of a page's connections** — an interactive bubble graph grouping
  requests by owning organization (e.g. every Google-owned domain collapses
  into one node), with first-party/third-party and tracker/advertiser/
  analytics classification.
- **Table view** — the same data grouped by domain in a sortable table, for
  when a list is more useful than a graph.
- **Cookie inspection** — every cookie the site set, with purpose, expiry,
  and security attributes (`Secure`, `HttpOnly`, `SameSite`), sourced from an
  open cookie-purpose database.
- **Data Journey replay** — watch the actual order your browser contacted
  third parties in, timed against when the page really loaded.
- **Data Exposure Detector** — flags requests whose URL or POST body matches
  patterns for personal data (email, phone, ZIP, geo) or known tracking IDs
  (`fbclid`, `gclid`, etc.), with the matched value always redacted before
  it's shown or stored.
- **Verify & Protect** — block a specific tracker on the current site only,
  reload, and see a plain before/after comparison of what changed.
- **Trend / history (opt-in)** — see whether a site's tracking footprint has
  grown or shrunk since your last visit. Off by default; counts only, never
  URLs or raw requests.
- **Always up to date** — the bundled tracker and cookie lists refresh
  automatically from their public sources once a day (toggleable off).

WebLens never produces a single "privacy score." It reports what it can
actually observe, tagged with where the information came from, and stays
quiet about anything it can't see.

## Installing

WebLens isn't on the Chrome Web Store yet — install it from source:

1. Download or clone this repository.
2. Open `chrome://extensions` (or `brave://extensions` in Brave).
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the repository folder (the one
   containing `manifest.json`).
5. Click the WebLens icon in your toolbar, then browse to any site — the
   popup and dashboard fill in as requests happen. Open the dashboard from
   the popup for the full graph, table, and Insights views.

Requires Chrome or Brave 116+.

## Privacy

- **No backend, no server.** WebLens is fully local — it reads your
  browser's own request/cookie events and keeps everything in
  `chrome.storage`, on your machine.
- **The one exception:** to keep its tracker and cookie classification data
  current, WebLens fetches two fixed public data files (Disconnect's tracker
  list and the Open Cookie Database) about once a day. This is the *only*
  outbound request WebLens itself ever makes — it sends nothing, no browsing
  data or identifiers, and it's toggleable off in settings if you'd rather
  stay on the bundled snapshot.
- **Durable data collection is opt-in and off by default.** Per-tab session
  data clears on browser restart automatically. The only thing that persists
  longer is trend history, and only if you explicitly turn it on — and even
  then it's counts only (never URLs, cookie names, or raw requests), capped,
  and clearable with one click.
- **Blocking is user-initiated only.** WebLens never blocks anything on its
  own; a tracker is only blocked when you click "Block" on that specific
  domain, on that specific site.

See `CONTEXT.md` for the full architecture, the reasoning behind every
permission WebLens requests, and known limitations (e.g. Brave's Shields
blocks some requests before WebLens ever sees them, which is a visibility
gap the UI discloses rather than silently producing an incomplete-looking
graph).

## Permissions

| Permission | Why |
|---|---|
| `webRequest` | See outbound requests (and, for the exposure detector, POST body content). |
| `webNavigation` | Know when a page navigation starts/ends, to scope a session to one page view. |
| `cookies` | Read cookie metadata for the active site. |
| `storage` | Persist session data and (opt-in) history/settings locally. |
| `tabs` | Associate requests with the right tab; reload the tab as part of a verify-and-block action. |
| `publicSuffix` | Correctly determine first-party vs. third-party domains. |
| `declarativeNetRequest` | Block a specific tracker on the current site, only when you ask. |
| `alarms` | Schedule the once-a-day tracker/cookie list refresh. |
| `<all_urls>` (host permission) | Needed so WebLens can observe requests on any site you visit. This is the largest privacy-relevant permission WebLens requests, and it's necessary because request capture would otherwise miss the page load itself. |

## Project structure

```
manifest.json          MV3 manifest
background/             service worker: request capture, sessions, settings, blocking, list refresh
classify/               domain/cookie classification, tracker & cookie data, exposure detection
ui/                      popup, dashboard, and shared theme/icon code
shared/                  data shapes used across background and UI
test/                    unit tests (no browser required — see below)
```

## Running the tests

The unit tests are plain Node scripts with no build step and no browser
dependency:

```
node test/classify-unit.mjs
node test/exposure-unit.mjs
node test/list-refresh-unit.mjs
node test/settings-default-verify.mjs
node test/trend-diff-unit.js
```

Each prints PASS/FAIL per check and exits non-zero on any failure. (A larger
Playwright-based end-to-end suite exists internally and will be published
here once it's trimmed down to something contributors can run without extra
setup.)

## Contributing

WebLens is intentionally simple: plain JavaScript, no build step, no
framework, no bundler — see `CONTEXT.md`'s "Build tooling" note. Before
proposing a change, especially anything touching permissions, data
retention, or what WebLens observes, please read `CONTEXT.md` for the
project's privacy/security principles and existing architecture decisions.

## License

WebLens's own code is [MIT](LICENSE). It bundles third-party tracker/cookie
data and a third-party graph library under their own separate licenses —
see [NOTICE.md](NOTICE.md).
