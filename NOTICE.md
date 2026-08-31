# Third-party notices

WebLens's own code is MIT-licensed (see `LICENSE`). It bundles the following
third-party data and code, each under its own license:

## Disconnect Tracking Protection list

- **File:** `classify/tracker-list.js`
- **Source:** https://github.com/disconnectme/disconnect-tracking-protection
- **License:** [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — Attribution, NonCommercial, ShareAlike
- **Copyright:** Disconnect, Inc.

Non-commercial use only. This is why WebLens itself must stay free — see
`CONTEXT.md`'s Open Decisions for how this constrains any future paid tier.

## Open Cookie Database

- **File:** `classify/cookie-db.js`
- **Source:** https://github.com/jkwakman/Open-Cookie-Database
- **License:** [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- **Copyright:** the Open Cookie Database contributors

Permissive, commercial-use-friendly. Redistributed here as a compact
snapshot in the shape WebLens's classifier expects.

## Cytoscape.js

- **File:** `ui/dashboard/cytoscape.min.js`
- **Source:** https://js.cytoscape.org/
- **License:** [MIT](https://opensource.org/licenses/MIT)
- **Copyright:** 2016-2024, The Cytoscape Consortium

Used for the dashboard's interactive bubble-map graph. Vendored (not a
package dependency) to keep the extension buildless per the project's
"no build step until something demands one" principle.

---

Both data sources are periodically refreshed from the same upstream URLs
(opt-in-turned-default as of v0.11.2 — see `CONTEXT.md`) to stay current;
the license terms above apply to whichever snapshot is active, live or
bundled.
