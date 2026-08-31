// WebLens shared schema — M2.

/**
 * @typedef {Object} CapturedRequest
 * @property {string}  id
 * @property {string}  url
 * @property {string}  domain        - hostname
 * @property {string}  etld1         - eTLD+1 of domain (M2+)
 * @property {string|null} initiator
 * @property {string}  type          - ResourceType
 * @property {number}  tabId
 * @property {number}  timestamp
 * @property {string}  status        - 'pending' | 'completed' | 'error'
 * @property {string|null} [error]   - Chrome net-error string when status is 'error'
 *                                     (e.g. 'net::ERR_BLOCKED_BY_CLIENT'). See isBlockedError().
 * @property {'first-party'|'third-party'|'unknown'} party
 * @property {string|null} organization
 * @property {string|null} category
 * @property {'Observed'|'Classified'|'Inferred'} provenance
 * @property {Array<{type:string,label:string,redacted:string,paramName:string,source:string,provenance:string}>} [exposures]
 *   Data Exposure Detector matches (v0.11.0) — patterns found in this
 *   request's URL/body by classify/exposure.js. Redacted values only; the
 *   full matched string is never retained. Omitted (not an empty array)
 *   when nothing matched, to avoid bloating every stored request.
 */

/**
 * @param {object} details - raw webRequest event details
 * @param {object} classification - from classify()
 * @param {Array<object>} [exposures] - from classify/exposure.js's detectExposures()
 * @returns {CapturedRequest}
 */
export function makeRequest(details, classification, exposures) {
  const req = {
    id:           details.requestId,
    url:          details.url,
    domain:       classification.domain,
    etld1:        classification.etld1,
    initiator:    details.initiator ?? null,
    type:         details.type,
    tabId:        details.tabId,
    timestamp:    details.timeStamp,
    status:       'pending',
    party:        classification.party,
    organization: classification.organization,
    category:     classification.category,
    provenance:   classification.provenance,
  };
  if (exposures?.length) req.exposures = exposures;
  return req;
}

/**
 * @typedef {Object} Session
 * @property {string}   id
 * @property {number}   tabId
 * @property {string}   pageUrl
 * @property {number}   startedAt
 * @property {number|null} endedAt
 * @property {CapturedRequest[]} requests
 */

export function makeSession(tabId, pageUrl) {
  return {
    id:        `tab-${tabId}`,
    tabId,
    pageUrl,
    startedAt: Date.now(),
    endedAt:   null,
    requests:  [],
  };
}

export function hostnameFromUrl(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

/**
 * True when a request's net-error indicates it was cancelled by an
 * extension's blocking rule (WebLens's own M6 block, or another blocker
 * like an ad blocker) rather than a genuine network failure (DNS, timeout,
 * connection reset, etc). This is Chrome's actual net-error string, not a
 * guess — Observed, not Inferred. It cannot say WHICH extension blocked it,
 * only that something did.
 * @param {{status?:string, error?:string|null}} request
 */
export function isBlockedError(request) {
  return request?.status === 'error' && request?.error === 'net::ERR_BLOCKED_BY_CLIENT';
}
