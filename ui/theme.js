// WebLens shared theme controller — applies/toggles data-theme on <html>,
// persisted via the existing settings store (background/settings.js), so
// popup and dashboard always agree on which theme is active. 'system'
// (the default) means "no explicit choice" — theme.css's prefers-color-scheme
// block handles that case; only 'light'/'dark' set the attribute here.

export async function applyStoredTheme() {
  try {
    const settings = await chrome.runtime.sendMessage({ type: 'weblens:getSettings' });
    setThemeAttr(settings?.theme ?? 'system');
    return settings?.theme ?? 'system';
  } catch {
    return 'system';
  }
}

export function setThemeAttr(theme) {
  const root = document.documentElement;
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
  else root.removeAttribute('data-theme');
}

export async function setTheme(theme) {
  setThemeAttr(theme);
  try { await chrome.runtime.sendMessage({ type: 'weblens:setSetting', key: 'theme', value: theme }); }
  catch { /* best effort — UI already reflects the change */ }
}

// Cycles system -> light -> dark -> system, for a single compact toggle button.
export async function cycleTheme() {
  const current = document.documentElement.getAttribute('data-theme') ?? 'system';
  const next = current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system';
  await setTheme(next);
  return next;
}
