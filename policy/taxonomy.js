// Observa Policy Intelligence — clause taxonomy — policy/taxonomy.js
//
// Fixed list of clause categories a normal user would actually want to know
// about in a privacy policy / terms of use / cookie policy, per the Policy
// Intelligence spec. Detection is local pattern/keyword matching against the
// document's own text — no external AI call, no network egress beyond
// fetching the policy document itself (see background/policy-intel.js and
// CONTEXT.md for why: consistent with CLAUDE.md's "AI is not the primary
// detection engine" and "no unnecessary backend infrastructure" rules, and
// with the same technique classify/tracker-list.js and classify/cookie-db.js
// already use for domain/cookie classification).
//
// Every category carries a DEFAULT tone/importance, but individual signals
// can override both — the same clause topic can be reassuring ("we do not
// sell your data") or concerning ("we may sell your data") depending on
// which actual sentence matched. Nothing here fires without matching text:
// extract.js only emits a finding when a signal's pattern is found in the
// document, and the exact matched text is always carried as `evidence`.
//
// tone:       'concern' | 'neutral' | 'good' — drives the 🔴/🟠/🟢 in the UI.
// importance: 'high' | 'medium' | 'low' — only meaningful for tone:'concern'
//             (a 'good' finding is always shown as reassuring, regardless of
//             importance; 'neutral' findings are informational).
// confidence: 'high' | 'medium' | 'low' — how specific/unambiguous this
//             particular pattern is. A generic keyword match (e.g. the bare
//             word "arbitration" appearing once) is lower confidence than an
//             explicit clause phrase ("you agree to resolve disputes through
//             binding arbitration").
//
// This is a starting taxonomy, not a finished legal reference — real-world
// policies phrase things in many ways this won't catch (see extract.js's
// header for the same caveat). Expand the `signals` lists as gaps are found
// against real, tested policies (CLAUDE.md Rule 7).

export const CLAUSE_TAXONOMY = [
  // ── What is collected ────────────────────────────────────────────────────
  {
    id: 'personalData',
    title: 'Personal Data Collected',
    icon: 'user',
    defaultTone: 'neutral',
    defaultImportance: 'medium',
    why: 'Knowing what personal information a company collects is the starting point for deciding how much to trust it with your data.',
    recommendation: 'Check whether what’s collected matches what you’d expect for the service you’re using.',
    signals: [
      { re: /(we|company|service|us)\s+(may\s+)?(collect|gather|obtain)[^.]{0,100}(personal (information|data)|information that (identifies|relates to|can be used to identify)\s+you)/i, confidence: 'high' },
      { re: /personal (information|data)\s+(we|that we)\s+collect\s+(includes|may include|consists of)/i, confidence: 'high' },
      { re: /information you (provide|give us)\s+(directly|when you)[^.]{0,120}(name|email|address|phone|date of birth)/i, confidence: 'medium' },
      { re: /categories of personal (information|data)\s+(we|that we)\s+(collect|have collected)/i, confidence: 'high' },
    ],
  },
  {
    id: 'sensitiveData',
    title: 'Sensitive Data Collected',
    icon: 'alert-triangle',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'Sensitive categories (health, biometric, financial, government ID, precise identity data) carry higher real-world risk if mishandled or breached than ordinary contact details.',
    recommendation: 'Confirm this level of data collection is actually necessary for what the service does, and check for a stated legal basis or extra safeguards.',
    signals: [
      { re: /(health|medical|biometric|genetic)\s+(information|data)/i, importance: 'high', confidence: 'high' },
      { re: /(social security|government[- ]issued|passport|driver'?s license|national id)\s+(number|id)/i, importance: 'high', confidence: 'high' },
      { re: /(financial|payment|bank account|credit card)\s+(information|data|details)/i, importance: 'medium', confidence: 'medium' },
      { re: /racial or ethnic origin|religious (belief|affiliation)|sexual orientation|political (opinion|affiliation)/i, importance: 'high', confidence: 'high' },
      { re: /precise geolocation|precise location data/i, importance: 'medium', confidence: 'medium' },
    ],
  },
  {
    id: 'locationData',
    title: 'Location Data',
    icon: 'globe',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'Location history can reveal where you live, work, and travel — one of the more sensitive signals a service can collect about you.',
    recommendation: 'Look for a way to disable location collection in the app/device settings, and check if it’s required for core functionality or just for advertising.',
    signals: [
      { re: /(collect|use|obtain)[^.]{0,80}(precise|approximate|real[- ]time)?\s*(geolocation|geographic location|gps)/i, importance: 'medium', confidence: 'high' },
      { re: /location (information|data)\s+(from|via)\s+(your\s+)?(device|ip address|wi[- ]?fi|gps)/i, importance: 'medium', confidence: 'high' },
      { re: /we do not collect (your\s+)?(precise\s+)?location/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },
  {
    id: 'browsingActivity',
    title: 'Browsing / Activity Data',
    icon: 'bar-chart',
    defaultTone: 'neutral',
    defaultImportance: 'medium',
    why: 'Activity and usage data builds a behavioral profile of you over time, separate from anything you explicitly typed in.',
    recommendation: 'This is common and often needed for the product to work — the real question is who else it’s shared with (see Third-Party Sharing).',
    signals: [
      { re: /(pages you (visit|view)|browsing (history|activity|behavior)|usage (data|information)|clickstream)/i, confidence: 'medium' },
      { re: /(log|usage) (data|information)\s+(such as|including)[^.]{0,120}(pages|features|clicks|time spent)/i, confidence: 'high' },
      { re: /(cookies|pixels|similar technologies)[^.]{0,120}(track|monitor|analy[sz]e)\s+(your\s+)?(activity|behavior|usage)/i, confidence: 'high' },
    ],
  },
  {
    id: 'deviceIdentifiers',
    title: 'Device Identifiers',
    icon: 'monitor',
    defaultTone: 'neutral',
    defaultImportance: 'low',
    why: 'Device and advertising identifiers let a company (and its partners) recognize you across sessions and, often, across different apps and sites.',
    recommendation: 'Check your device’s ad-tracking / advertising-ID settings if you’d rather not be tracked this way.',
    signals: [
      { re: /(device (identifier|id)|advertising id|idfa|android advertising id|mac address|imei)/i, confidence: 'high' },
      { re: /(unique identifiers|hardware (id|identifiers))[^.]{0,80}(device|browser)/i, confidence: 'medium' },
    ],
  },

  // ── Where it goes ────────────────────────────────────────────────────────
  {
    id: 'thirdPartySharing',
    title: 'Third-Party Sharing',
    icon: 'users',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'Once your data is shared with another company, you’re also subject to that company’s privacy practices — which you likely haven’t reviewed.',
    recommendation: 'Look for exactly who "third parties" means in the policy (named categories are better than a vague blanket statement) and whether you can opt out.',
    signals: [
      { re: /(share|disclose|provide)\s+(your\s+)?(personal\s+)?(information|data)\s+with\s+(third[- ]part(y|ies)|our partners|affiliates|vendors|service providers)/i, importance: 'medium', confidence: 'high' },
      { re: /(may|might)\s+(share|disclose)[^.]{0,120}(third[- ]part(y|ies)|advertising|analytics|business)\s+partners/i, importance: 'medium', confidence: 'high' },
      { re: /we do not share your (personal\s+)?(information|data) with (third parties|anyone)/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },
  {
    id: 'advertising',
    title: 'Targeted / Interest-Based Advertising',
    icon: 'megaphone',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'Interest-based advertising means your activity is being profiled to predict what you’ll respond to — often shared with an ad-tech ecosystem well beyond the site you’re on.',
    recommendation: 'Look for an opt-out (often called "Do Not Sell/Share" or interest-based-ads settings) and use it if you don’t want to be profiled for ads.',
    signals: [
      { re: /(interest[- ]based|personali[sz]ed|targeted)\s+advertis(ing|ements)/i, importance: 'medium', confidence: 'high' },
      { re: /(information|data)\s+(may be|is)\s+used\s+(to|for)[^.]{0,80}(deliver|show|serve)\s+(you\s+)?(relevant\s+)?(ads|advertisements)/i, importance: 'medium', confidence: 'high' },
      { re: /third[- ]party advertising (network|partners)/i, importance: 'low', confidence: 'medium' },
      { re: /we do not (use|show)\s+(interest[- ]based|targeted|personali[sz]ed)\s+advertising/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },
  {
    id: 'dataSale',
    title: 'Sale / Sharing of Data for Value',
    icon: 'package',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'A sale of your personal data means a third party can obtain it in exchange for money or other value — the highest-impact form of data sharing, and the one privacy laws like the CCPA specifically regulate.',
    recommendation: 'If a sale is disclosed, look for the "Do Not Sell or Share My Personal Information" opt-out most US state privacy laws require.',
    signals: [
      { re: /we (may\s+)?sell\s+(your\s+)?(personal\s+)?(information|data)/i, importance: 'high', confidence: 'high' },
      { re: /(sale|sharing) of personal information[^.]{0,120}(cross[- ]context behavioral advertising|for valuable consideration)/i, importance: 'high', confidence: 'high' },
      // This exact string is the opt-out link title most US state privacy laws
      // REQUIRE a site to display. Its presence means the site is offering the
      // opt-out — a right you can exercise — so it is reassuring, not a
      // concern. It inherited defaultTone:'concern' and was reported as a high
      // concern on a document whose own `recommendation` (below) tells readers
      // to go looking for this very link. Same failure mode as the negation
      // bug: matching a phrase without regard to what it means in context.
      { re: /do not sell or share my personal information/i, tone: 'good', importance: 'low', confidence: 'medium' },
      { re: /we do not sell (your\s+)?(personal\s+)?(information|data)/i, tone: 'good', importance: 'low', confidence: 'high' },
      { re: /we have not sold (personal\s+)?(information|data) in the (preceding|past|last)\s+12\s+months/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },
  {
    id: 'dataFromOtherCompanies',
    title: 'Data Obtained From Other Companies',
    icon: 'network',
    defaultTone: 'neutral',
    defaultImportance: 'medium',
    why: 'A profile built partly from data bought or received from other companies (data brokers, partners) can be far more detailed than what you knowingly gave the service directly.',
    recommendation: 'Look for what categories of third-party sources are named — vague "other sources" language is harder to evaluate than a specific list.',
    signals: [
      { re: /(information|data)\s+(we\s+)?(receive|obtain|collect)\s+from\s+(other|third[- ]party)\s+(sources|companies|partners|providers)/i, confidence: 'high' },
      { re: /(data\s+)?(brokers|aggregators)/i, confidence: 'medium' },
      { re: /(combine|supplement)[^.]{0,100}information\s+(we\s+)?(receive|obtain)\s+from\s+(third parties|other sources)/i, confidence: 'high' },
    ],
  },

  // ── How long / your control ──────────────────────────────────────────────
  {
    id: 'retention',
    title: 'Data Retention',
    icon: 'clock',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'The longer data is kept, the longer it’s exposed to breaches, subpoenas, or future changes in how the company uses it.',
    recommendation: 'Look for a concrete retention period (a number of days/years) rather than an open-ended "as long as necessary" with no further detail.',
    signals: [
      { re: /retain[^.]{0,40}(information|data)\s+for\s+as\s+long\s+as\s+(necessary|needed)/i, importance: 'low', confidence: 'high' },
      { re: /(some|certain)\s+(information|data)\s+(may\s+)?(remain|persist)\s+(in our (systems|backups|servers)\s+)?(after|even after|following)\s+(you\s+)?(delete|deactivat|clos)/i, importance: 'medium', confidence: 'high' },
      { re: /(we retain|retention period of)[^.]{0,60}\b\d+\s*(days|months|years)\b/i, tone: 'good', importance: 'low', confidence: 'high' },
      { re: /(we\s+)?(may\s+)?keep\s+(backup|archived)\s+copies\s+(of\s+)?(your\s+)?(information|data)/i, importance: 'low', confidence: 'medium' },
    ],
  },
  {
    id: 'deletion',
    title: 'Account / Data Deletion',
    icon: 'trash',
    defaultTone: 'good',
    defaultImportance: 'low',
    why: 'A clear, working deletion process is one of the strongest practical signs a company respects your control over your own data.',
    recommendation: 'If deletion rights are described, note whether it’s a simple self-service action or requires contacting support.',
    signals: [
      { re: /(request|ask)\s+(that we\s+)?delete\s+(your\s+)?(personal\s+)?(information|data|account)/i, tone: 'good', confidence: 'high' },
      { re: /(right to (delete|erasure)|right to be forgotten)/i, tone: 'good', confidence: 'high' },
      { re: /delete your account[^.]{0,80}(settings|going to|by)/i, tone: 'good', confidence: 'medium' },
      { re: /we (do not|cannot|are unable to)\s+delete[^.]{0,80}(information|data)/i, tone: 'concern', importance: 'high', confidence: 'high' },
      { re: /(no\s+way|not\s+possible)\s+to\s+delete\s+(your\s+)?(account|data|information)/i, tone: 'concern', importance: 'high', confidence: 'high' },
    ],
  },
  {
    id: 'optOutRights',
    title: 'User Privacy / Opt-Out Rights',
    icon: 'shield-check',
    defaultTone: 'good',
    defaultImportance: 'low',
    why: 'Opt-out and access rights (seeing, correcting, or limiting use of your data) give you leverage even when a company collects a lot.',
    recommendation: 'Check whether the described rights apply to you regardless of location, or only to residents of specific states/countries.',
    signals: [
      { re: /(right to\s+)?(access|correct|opt out of|object to)[^.]{0,100}(processing|use|sale|sharing)\s+of\s+your\s+(personal\s+)?(information|data)/i, tone: 'good', confidence: 'high' },
      { re: /(california|virginia|colorado|connecticut|gdpr|european)\s+(residents|users)\s+(have|may have)\s+the\s+right/i, tone: 'good', confidence: 'high' },
      { re: /opt out of (marketing|promotional)\s+(emails|communications)/i, tone: 'good', importance: 'low', confidence: 'medium' },
      { re: /these rights (do not|may not)\s+apply\s+(to|if)/i, tone: 'concern', importance: 'medium', confidence: 'medium' },
    ],
  },

  // ── AI / model use ───────────────────────────────────────────────────────
  {
    id: 'aiTraining',
    title: 'AI / Model-Training Use',
    icon: 'zap',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'If your content or data is used to train AI/ML models, it can influence a model’s future outputs in ways that are difficult or impossible to undo later, even if you delete your account.',
    recommendation: 'Look specifically for an opt-out for AI training — many services now offer one even when training is on by default.',
    signals: [
      { re: /(use|process)\s+(your\s+)?(content|data|information)\s+to\s+(train|improve|develop)\s+(our\s+)?(ai|artificial intelligence|machine learning|models?)/i, importance: 'high', confidence: 'high' },
      { re: /(train|training of)\s+(our\s+)?(ai|machine learning|language)\s+models?/i, importance: 'high', confidence: 'high' },
      { re: /(opt out|do not use my data)[^.]{0,80}(ai|model)\s+training/i, tone: 'good', importance: 'low', confidence: 'high' },
      { re: /we do not use (your\s+)?(content|data)\s+to\s+train/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },

  // ── Policy governance ────────────────────────────────────────────────────
  {
    id: 'policyChanges',
    title: 'Policy Changes',
    icon: 'refresh-cw',
    defaultTone: 'neutral',
    defaultImportance: 'low',
    why: 'How a company handles future changes to its policy tells you whether you’ll actually find out before new terms take effect.',
    recommendation: 'Look for whether they promise advance notice (email, in-app banner) versus just posting a new "effective date" silently.',
    signals: [
      { re: /(we\s+)?(may\s+)?(update|change|modify|revise)\s+this\s+(privacy\s+)?(policy|notice)\s+from\s+time\s+to\s+time/i, confidence: 'high' },
      { re: /continued\s+use\s+of\s+(the\s+)?(service|site|app)\s+(after|following)\s+(any\s+)?changes?\s+constitutes/i, tone: 'concern', importance: 'medium', confidence: 'high' },
      { re: /we will (notify|email|alert)\s+you\s+(of|about)\s+(material\s+)?changes/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },

  // ── Dispute resolution ───────────────────────────────────────────────────
  {
    id: 'arbitration',
    title: 'Binding Arbitration',
    icon: 'file-text',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'Binding arbitration usually means you give up your right to sue in court, and disputes are decided privately instead of through the public court system.',
    recommendation: 'Check whether there’s an opt-out window (often 30 days after signup) to reject the arbitration clause specifically.',
    signals: [
      { re: /(resolve|settle)\s+(any\s+)?disputes?\s+(through|by|via)\s+(binding\s+)?arbitration/i, importance: 'medium', confidence: 'high' },
      { re: /you and (we|company)\s+(agree|waive)[^.]{0,80}arbitrat/i, importance: 'medium', confidence: 'high' },
      { re: /\barbitration\b[^.]{0,150}\b(AAA|American Arbitration Association|JAMS)\b/i, importance: 'medium', confidence: 'high' },
      { re: /agree(s|d)?\s+to\s+(binding\s+)?arbitration/i, importance: 'low', confidence: 'medium' },
      { re: /(binding\s+)?arbitration\s+for\s+(any|all)\s+disputes?/i, importance: 'low', confidence: 'medium' },
    ],
  },
  {
    id: 'classActionWaiver',
    title: 'Class-Action Waiver',
    icon: 'ban',
    defaultTone: 'concern',
    defaultImportance: 'high',
    why: 'A class-action waiver means you can only bring a claim individually, not join with other affected users — which makes it far less practical to challenge small, widespread harms.',
    recommendation: 'This is often bundled with arbitration; check if there’s a shared opt-out for both.',
    signals: [
      { re: /(waive|give up)\s+(your\s+)?right\s+to\s+(participate in|bring|join)\s+a\s+class[- ]action/i, importance: 'high', confidence: 'high' },
      { re: /class\s+action\s+waiver/i, importance: 'high', confidence: 'high' },
      { re: /on\s+an\s+individual\s+basis[^.]{0,100}not\s+(as|on behalf of)\s+a\s+class/i, importance: 'medium', confidence: 'medium' },
    ],
  },

  // ── Money / content ──────────────────────────────────────────────────────
  {
    id: 'autoRenewal',
    title: 'Auto-Renewal / Cancellation',
    icon: 'refresh-cw',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'Auto-renewing subscriptions can keep charging you until you actively cancel, and cancellation is sometimes made deliberately harder than sign-up.',
    recommendation: 'Note the renewal cycle and how far in advance you need to cancel to avoid the next charge.',
    signals: [
      { re: /(subscription|membership|plan)\s+(will\s+)?automatically\s+renew/i, importance: 'medium', confidence: 'high' },
      { re: /(auto[- ]renew|automatic renewal)/i, importance: 'medium', confidence: 'high' },
      { re: /cancel\s+(at least|no later than)\s+\d+\s+(hours|days)\s+before/i, importance: 'medium', confidence: 'medium' },
      { re: /no\s+refunds?\s+(will be (given|issued|provided)|for)/i, importance: 'medium', confidence: 'medium' },
    ],
  },
  {
    id: 'contentOwnership',
    title: 'Content Ownership / License Rights',
    icon: 'book-open',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'Broad licenses over what you upload (photos, writing, code) can let a company use, modify, or sublicense your content well beyond just running the service for you.',
    recommendation: 'Look for whether the license is limited to "operating the service" or is broader (e.g. includes marketing, sublicensing, or is irrevocable/perpetual).',
    signals: [
      { re: /(grant|give)\s+(us|the company)\s+a\s+(worldwide|perpetual|irrevocable|royalty[- ]free|sublicensable|transferable)\s+license/i, importance: 'medium', confidence: 'high' },
      { re: /license\s+to\s+(use|reproduce|distribute|modify|display|create derivative works)[^.]{0,120}content you (post|upload|submit)/i, importance: 'medium', confidence: 'high' },
      { re: /you retain (all\s+)?ownership\s+of\s+(your\s+)?content/i, tone: 'good', importance: 'low', confidence: 'high' },
    ],
  },
  {
    id: 'limitationOfLiability',
    title: 'Limitation of Liability',
    icon: 'shield',
    defaultTone: 'concern',
    defaultImportance: 'medium',
    why: 'A broad liability cap or "as is" disclaimer limits what you can recover if the service causes you harm or loss — including from a data breach.',
    recommendation: 'Check whether liability is capped at a specific (often small) dollar amount and whether that cap covers data-breach scenarios.',
    signals: [
      { re: /(service|software|app)\s+is\s+provided\s+["'“]?as\s+is["'”]?/i, importance: 'low', confidence: 'high' },
      { re: /(shall not|will not|is not)\s+be\s+liable\s+for\s+(any\s+)?(indirect|incidental|special|consequential|punitive)\s+damages/i, importance: 'low', confidence: 'high' },
      { re: /(our|the company'?s)\s+(total\s+)?liability\s+(shall not exceed|is limited to)/i, importance: 'low', confidence: 'high' },
    ],
  },
];

export function findCategory(id) {
  return CLAUSE_TAXONOMY.find(c => c.id === id) ?? null;
}
