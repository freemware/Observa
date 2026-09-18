// Observa shared icon set — small inline SVGs (Lucide-style line icons)
// replacing emoji in structural UI chrome (nav, buttons, category badges,
// status indicators). stroke="currentColor" so every icon automatically
// matches its surrounding text color and theme — no per-theme icon assets.
// Fully self-contained, no network fetch, no external CDN — works offline
// like the rest of the extension.

const PATHS = {
  shield:        '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V5l-8-3Z"/>',
  'shield-check':'<path d="M12 2 4 5v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V5l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
  ban:           '<circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/>',
  undo:          '<path d="M4 10h11a5 5 0 0 1 0 10H9"/><path d="M9 5 4 10l5 5"/>',
  'alert-triangle': '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4"/><circle cx="12" cy="17" r="0.6" fill="currentColor" stroke="none"/>',
  zap:           '<path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z"/>',
  megaphone:     '<path d="M4 10v4a1 1 0 0 0 1 1h2l7 4V5L7 9H5a1 1 0 0 0-1 1Z"/><path d="M17 9a4 4 0 0 1 0 6"/>',
  'bar-chart':   '<path d="M4 20V10"/><path d="M12 20V4"/><path d="M20 20v-7"/>',
  users:         '<circle cx="9" cy="8" r="3"/><path d="M2 20c0-3.3 3-6 7-6s7 2.7 7 6"/><circle cx="17" cy="9" r="2.4"/><path d="M15.5 14.2c2.6.4 4.5 2.4 4.5 5.8"/>',
  user:          '<circle cx="12" cy="8" r="3.5"/><path d="M4.5 20c0-4 3.4-7 7.5-7s7.5 3 7.5 7"/>',
  search:        '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.3-4.3"/>',
  package:       '<path d="m3.5 7.5 8.5-4 8.5 4-8.5 4-8.5-4Z"/><path d="M3.5 7.5v9l8.5 4 8.5-4v-9"/><path d="M12 11.5v9"/>',
  'check-circle':'<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  clock:         '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
  globe:         '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 2.6 4 5.8 4 9s-1.4 6.4-4 9c-2.6-2.6-4-5.8-4-9s1.4-6.4 4-9Z"/>',
  'file-text':   '<path d="M6 2.5h8l4 4V21a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1Z"/><path d="M14 2.5V7h4"/><path d="M8 12h8M8 16h8"/>',
  'book-open':   '<path d="M12 6.5C10.5 5 8 4.5 4.5 4.5v14c3.5 0 6 .5 7.5 2 1.5-1.5 4-2 7.5-2v-14C16 4.5 13.5 5 12 6.5Z"/><path d="M12 6.5v14"/>',
  settings:      '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.5v3M12 18.5v3M4.6 6.6l2.1 2.1M17.3 15.3l2.1 2.1M2.5 12h3M18.5 12h3M4.6 17.4l2.1-2.1M17.3 8.7l2.1-2.1"/>',
  trash:         '<path d="M4.5 7h15"/><path d="M9.5 7V4.5h5V7"/><path d="M6.5 7 7.3 19.2a1 1 0 0 0 1 .8h7.4a1 1 0 0 0 1-.8L17.5 7"/><path d="M10 11v6M14 11v6"/>',
  x:             '<path d="m5 5 14 14M19 5 5 19"/>',
  'chevron-right':'<path d="m9 5 7 7-7 7"/>',
  'trending-up': '<path d="m3 17 6-6 4 4 8-8"/><path d="M15 6h6v6"/>',
  building:      '<rect x="5" y="3" width="14" height="18" rx="1"/><path d="M9 7.5h1M14 7.5h1M9 11.5h1M14 11.5h1M9 15.5h1M14 15.5h1"/>',
  cookie:        '<circle cx="12" cy="12" r="9"/><circle cx="9" cy="9.5" r="1" fill="currentColor" stroke="none"/><circle cx="14" cy="8.5" r="1" fill="currentColor" stroke="none"/><circle cx="15" cy="14" r="1" fill="currentColor" stroke="none"/><circle cx="9.5" cy="14.5" r="1" fill="currentColor" stroke="none"/>',
  'refresh-cw':  '<path d="M20 11a8 8 0 0 0-14.6-4.4M4 13a8 8 0 0 0 14.6 4.4"/><path d="M20 4v4h-4M4 20v-4h4"/>',
  layers:        '<path d="m12 3 8 4.5-8 4.5-8-4.5L12 3Z"/><path d="m4 12.5 8 4.5 8-4.5"/><path d="m4 16.5 8 4.5 8-4.5"/>',
  network:       '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M12 7.2v4M12 11.2 6.3 16M12 11.2 17.7 16"/>',
  table:         '<rect x="3.5" y="4.5" width="17" height="15" rx="1.5"/><path d="M3.5 10h17M9 4.5V19.5"/>',
  sun:           '<circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M4.2 4.2l1.8 1.8M18 18l1.8 1.8M2 12h2.5M19.5 12H22M4.2 19.8 6 18M18 6l1.8-1.8"/>',
  moon:          '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5Z"/>',
  monitor:       '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
  info:          '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="0.6" fill="currentColor" stroke="none"/>',
  'external-link':'<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
};

/**
 * Returns an inline <svg> string for `name`. `size` in px (default 14),
 * `strokeWidth` default 2. Caller controls color via CSS `color` on the
 * wrapping element (icons use currentColor).
 */
export function icon(name, { size = 14, strokeWidth = 2, className = '' } = {}) {
  const body = PATHS[name];
  if (!body) return '';
  return `<svg class="wl-icon ${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

// Category -> icon name, replacing the old emoji-keyed CAT_ICON dict.
export const CATEGORY_ICON_NAME = {
  Advertising: 'megaphone',
  Analytics: 'bar-chart',
  Social: 'users',
  Fingerprinting: 'search',
  Cryptomining: 'zap',
  Content: 'package',
  'Anti-fraud': 'shield',
  Consent: 'check-circle',
};
