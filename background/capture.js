// WebLens capture — M2.
// Observes webRequest events, classifies at capture time, hands to session.js.
// Provenance of raw data: OBSERVED. Classification provenance set by classify().

import { makeRequest, hostnameFromUrl } from '../shared/schema.js';
import { classify } from '../classify/classify.js';
import { detectExposures } from '../classify/exposure.js';
import { handleRequest, handleRequestComplete, handleRequestError, getPageUrlForTab } from './session.js';

export function registerCaptureListeners() {
  // 'requestBody' needs no new manifest permission — it's part of the
  // existing 'webRequest' grant — but it is a deeper level of inspection
  // than WebLens did before (v0.11.0, Data Exposure Detector): POST bodies
  // are decoded in-memory just long enough to run local pattern detectors
  // (classify/exposure.js) and are never stored raw — only a redacted
  // preview of whatever pattern matched survives into the session.
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (!isCaptureable(details)) return;
      const domain = hostnameFromUrl(details.url);
      const pageUrl = getPageUrlForTab(details.tabId);
      const classification = classify(domain, pageUrl);
      const exposures = detectExposures(details.url, details.requestBody);
      handleRequest(makeRequest(details, classification, exposures));
    },
    { urls: ['<all_urls>'] },
    ['requestBody']
  );

  chrome.webRequest.onCompleted.addListener(
    (details) => {
      if (!isCaptureable(details)) return;
      handleRequestComplete(details.requestId, details.tabId, details.statusCode);
    },
    { urls: ['<all_urls>'] }
  );

  chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
      if (!isCaptureable(details)) return;
      handleRequestError(details.requestId, details.tabId, details.error);
    },
    { urls: ['<all_urls>'] }
  );
}

function isCaptureable(details) {
  if (details.tabId === -1) return false;
  if (details.url?.startsWith('chrome-extension://')) return false;
  return true;
}
