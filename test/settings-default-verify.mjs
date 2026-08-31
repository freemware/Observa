// Unit test for background/settings.js + background/list-refresh.js's init
// path, covering the v0.11.2 change: listRefreshEnabled default flipped
// from opt-in/off to on-by-default. Exercises the actual production
// functions in the actual order the service worker calls them (see
// background/service-worker.js's 'weblens:setSetting' handler), not
// reimplemented logic:
//   1. Fresh install (nothing in chrome.storage.local yet): getSettings()
//      must report listRefreshEnabled: true, and initListRefresh() (called
//      once at service-worker startup) must arm the daily alarm for it.
//   2. A user explicitly turning it off via setSetting() + the same
//      onListRefreshSettingChanged() call the real message handler makes
//      must disarm the alarm and must not be silently overridden by the
//      new default on a later getSettings() read.
//   3. Turning it back on re-arms the alarm.
const armedAlarms = [];
const clearedAlarms = [];
let storedSettings = {};

globalThis.chrome = {
  alarms: {
    onAlarm: { addListener() {} },
    create: (name, opts) => armedAlarms.push({ name, opts }),
    clear: (name) => clearedAlarms.push(name),
  },
  storage: {
    onChanged: { addListener() {} },
    local: {
      get: async (key) => ({ [key]: storedSettings[key] }),
      set: async (obj) => { storedSettings = { ...storedSettings, ...obj }; },
    },
  },
};

const { getSettings, setSetting } = await import('../background/settings.js');
const { initListRefresh, onListRefreshSettingChanged } = await import('../background/list-refresh.js');

let failures = 0;
function assert(name, cond, detail) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name}${detail !== undefined ? ' :: ' + detail : ''}`);
  if (!cond) failures++;
}

// ── Scenario 1: fresh install, nothing stored yet ──────────────────────────
{
  const settings = await getSettings();
  assert('Fresh install: listRefreshEnabled defaults to true', settings.listRefreshEnabled === true, JSON.stringify(settings));

  await initListRefresh();
  assert('Fresh install: initListRefresh() arms the daily refresh alarm', armedAlarms.some(a => a.name === 'weblens-list-refresh' && a.opts.periodInMinutes === 1440), JSON.stringify(armedAlarms));
}

// ── Scenario 2: user explicitly turns it off (real setSetting + onListRefreshSettingChanged path) ──
{
  armedAlarms.length = 0;
  clearedAlarms.length = 0;
  const next = await setSetting('listRefreshEnabled', false);
  await onListRefreshSettingChanged(false);
  assert('setSetting(false) is reflected immediately', next.listRefreshEnabled === false, JSON.stringify(next));

  const settings = await getSettings();
  assert('Explicit off is not overridden by the default on a later read', settings.listRefreshEnabled === false, JSON.stringify(settings));
  assert('Turning off clears the alarm', clearedAlarms.includes('weblens-list-refresh'), JSON.stringify(clearedAlarms));
  assert('Turning off does not (re)arm the alarm', !armedAlarms.some(a => a.name === 'weblens-list-refresh'), JSON.stringify(armedAlarms));
}

// ── Scenario 3: user turns it back on ──────────────────────────────────────
{
  armedAlarms.length = 0;
  clearedAlarms.length = 0;
  await setSetting('listRefreshEnabled', true);
  await onListRefreshSettingChanged(true);

  const settings = await getSettings();
  assert('Turning back on is reflected', settings.listRefreshEnabled === true, JSON.stringify(settings));
  assert('Turning back on re-arms the alarm', armedAlarms.some(a => a.name === 'weblens-list-refresh'), JSON.stringify(armedAlarms));
}

console.log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
