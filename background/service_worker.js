// ============================================================
// PhishGuard — Background Service Worker
// background/service_worker.js
// ============================================================

importScripts('../utils/detector.js');
importScripts('../utils/threat_intel.js');

// ── In-memory cache for scan results ────────────────────────
const verdictCache = new Map();
const pageStatsByTab = new Map();
const serpStatsByTab = new Map();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const MAX_CACHE_ENTRIES = 200;

// ── Extension icon states ─────────────────────────────────────
const BADGE_CONFIG = {
  SAFE:       { text: '✓',   color: '#22c55e', bg: '#14532d' },
  SUSPICIOUS: { text: '!',   color: '#f59e0b', bg: '#78350f' },
  DANGEROUS:  { text: '✕',   color: '#ef4444', bg: '#7f1d1d' },
  SCANNING:   { text: '...',  color: '#94a3b8', bg: '#1e293b' },
  UNKNOWN:    { text: '?',   color: '#94a3b8', bg: '#1e293b' }
};

// ── Stats tracking ─────────────────────────────────────────────
let stats = {
  totalScanned: 0,
  safe: 0,
  suspicious: 0,
  dangerous: 0,
  blockedClicks: 0,
  hindi: 0
};

// Load persisted stats on startup
chrome.storage.session.get(['phishguard_stats'], (sessionResult) => {
  if (sessionResult.phishguard_stats) {
    stats = sessionResult.phishguard_stats;
    return;
  }

  chrome.storage.local.get(['phishguard_stats'], (result) => {
    if (result.phishguard_stats) {
      stats = result.phishguard_stats;
      chrome.storage.session.set({ phishguard_stats: stats });
    }
  });
});

function saveStats() {
  chrome.storage.local.set({ phishguard_stats: stats });
  chrome.storage.session.set({ phishguard_stats: stats });
}

function rememberCache(urlString, result) {
  if (!urlString || !result) return;

  if (verdictCache.has(urlString)) {
    verdictCache.delete(urlString);
  }

  verdictCache.set(urlString, { result, timestamp: Date.now() });

  while (verdictCache.size > MAX_CACHE_ENTRIES) {
    const oldestKey = verdictCache.keys().next().value;
    if (oldestKey === undefined) break;
    verdictCache.delete(oldestKey);
  }
}

function isGoogleSerpUrl(urlString) {
  return /^https:\/\/(www\.)?google\.(com|co\.in)\/search/.test(String(urlString || ''));
}

function setSerpBadge(tabId, dangerCount, suspiciousCount) {
  let badgeText = '✓';
  let badgeColor = '#3B6D11';

  if (Number(dangerCount || 0) > 0) {
    badgeText = `${Number(dangerCount)}⚠`;
    badgeColor = '#E24B4A';
  } else if (Number(suspiciousCount || 0) > 0) {
    badgeText = `${Number(suspiciousCount)}⚠`;
    badgeColor = '#BA7517';
  }

  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
}

function storePageStats(tabId, urlString, pageData, result) {
  if (!tabId) return;

  const protocol = pageData?.protocol || (() => {
    try { return new URL(urlString).protocol; } catch { return 'https:'; }
  })();

  const cacheEntry = urlString ? verdictCache.get(urlString) : null;
  const cacheRemainingMs = cacheEntry ? Math.max(0, CACHE_TTL - (Date.now() - cacheEntry.timestamp)) : 0;

  pageStatsByTab.set(tabId, {
    links: Number(pageData?.linkCount ?? pageData?.totalLinks ?? 0),
    externalLinks: Number(pageData?.externalLinkCount ?? 0),
    ads: Number(pageData?.adCount ?? 0),
    suspicious: Number(result?.verdict === 'DANGEROUS' ? 1 : result?.verdict === 'SUSPICIOUS' ? 1 : 0),
    protocol,
    hasSensitiveForms: Number(pageData?.sensitiveFormCount ?? (pageData?.hasPasswordField || pageData?.hasOTPField ? 1 : 0)),
    cacheRemainingMs,
    tlsValid: typeof pageData?.tlsValid === 'boolean' ? pageData.tlsValid : protocol === 'https:',
    updatedAt: Date.now(),
    url: urlString
  });
}

// ── Badge update helper ────────────────────────────────────────
function updateBadge(tabId, verdict) {
  const config = BADGE_CONFIG[verdict] || BADGE_CONFIG.UNKNOWN;
  chrome.action.setBadgeText({ text: config.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

// ── Core scan function ─────────────────────────────────────────
async function scanURL(urlString, tabId) {
  if (!urlString || urlString.startsWith('chrome://') ||
      urlString.startsWith('chrome-extension://') ||
      urlString.startsWith('about:') || urlString.startsWith('data:')) {
    return null;
  }

  // Check cache
  const cached = verdictCache.get(urlString);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  // Update badge to scanning state
  if (tabId) updateBadge(tabId, 'SCANNING');

  // URL analysis
  const urlAnalysis = PhishGuardDetector.analyzeURL(urlString);

  // If trusted domain, short-circuit
  if (urlAnalysis.trusted) {
    const result = {
      verdict: 'SAFE',
      urlScore: 0,
      pageScore: 0,
      flags: ['Verified trusted domain'],
      url: urlString,
      timestamp: Date.now()
    };
    rememberCache(urlString, result);
    if (tabId) updateBadge(tabId, 'SAFE');
    updateStats('SAFE');
    return result;
  }

  return {
    urlScore: urlAnalysis.score,
    urlFlags: urlAnalysis.flags,
    url: urlString,
    pending: true // page analysis pending
  };
}

// ── Full scan with page data ───────────────────────────────────
async function fullScan(urlString, pageData, tabId) {
  const urlAnalysis = PhishGuardDetector.analyzeURL(urlString);

  if (urlAnalysis.trusted) {
    const result = {
      verdict: 'SAFE',
      urlScore: 0,
      pageScore: 0,
      flags: ['Verified trusted domain'],
      url: urlString,
      timestamp: Date.now()
    };
    rememberCache(urlString, result);
    if (tabId) updateBadge(tabId, 'SAFE');
    updateStats('SAFE');
    return result;
  }

  // Run local page analysis and live threat intel lookup in parallel
  const [pageAnalysis, threatResult] = await Promise.all([
    Promise.resolve(PhishGuardDetector.analyzePage(pageData)),
    ThreatIntel.lookup(urlString).catch(() => null)
  ]);

  // If threat intel flagged this URL, it overrides local verdict
  let verdict;
  let extraFlags = [];

  if (threatResult && threatResult.flagged) {
    verdict = threatResult.verdict; // DANGEROUS or SUSPICIOUS from live DB
    extraFlags = (threatResult.reasons || []).map(r => ({ type: 'threat_intel', text: r }));
    if (threatResult.checkedSources && threatResult.checkedSources.length > 0) {
      extraFlags.push({
        type: 'threat_intel',
        text: `Checked against: ${threatResult.checkedSources.join(', ')}`
      });
    }
  } else {
    verdict = PhishGuardDetector.getVerdict(urlAnalysis.score, pageAnalysis.score);
    // If threat intel ran clean, note it
    if (threatResult && !threatResult.flagged && threatResult.checkedSources && threatResult.checkedSources.length > 0) {
      extraFlags.push({
        type: 'threat_intel',
        text: `Clean on: ${threatResult.checkedSources.join(', ')}`
      });
    }
  }

  const allFlags = [
    ...extraFlags,
    ...urlAnalysis.flags.map(f => ({ type: 'url', text: f })),
    ...pageAnalysis.flags.map(f => ({ type: 'page', text: f }))
  ];

  const result = {
    verdict,
    urlScore: urlAnalysis.score,
    pageScore: pageAnalysis.score,
    threatIntel: threatResult || null,
    flags: allFlags,
    url: urlString,
    timestamp: Date.now()
  };

  if (pageAnalysis.flags.some(flag => /hindi|hinglish/i.test(flag))) {
    stats.hindi++;
  }

  // Cache the result
  rememberCache(urlString, result);

  // Update badge
  if (tabId) updateBadge(tabId, verdict);

  // Update stats
  updateStats(verdict);

  return result;
}

function updateStats(verdict) {
  stats.totalScanned++;
  if (verdict === 'SAFE') stats.safe++;
  else if (verdict === 'SUSPICIOUS') stats.suspicious++;
  else if (verdict === 'DANGEROUS') stats.dangerous++;
  saveStats();
}

function sendTabMessage(tabId, message) {
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }

        resolve(response || null);
      });
    } catch {
      resolve(null);
    }
  });
}

// ── Hover link scan (lightweight, URL-only + threat intel) ────
async function scanHoverLink(urlString) {
  if (!urlString) return null;

  const cached = verdictCache.get(urlString);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  // Hover scans are local-only — no API call to preserve rate limits
  const urlAnalysis = PhishGuardDetector.analyzeURL(urlString);
  const threatResult = await ThreatIntel.lookup(urlString, { hoverMode: true }).catch(() => null);

  let verdict;
  let extraFlags = [];

  if (threatResult && threatResult.flagged) {
    verdict = threatResult.verdict;
    extraFlags = (threatResult.reasons || []).map(r => ({ type: 'threat_intel', text: r }));
  } else {
    verdict = urlAnalysis.trusted ? 'SAFE' :
      urlAnalysis.score >= 55 ? 'DANGEROUS' :
      urlAnalysis.score >= 25 ? 'SUSPICIOUS' : 'SAFE';
  }

  const result = {
    verdict,
    urlScore: urlAnalysis.score,
    pageScore: 0,
    threatIntel: threatResult || null,
    flags: [
      ...extraFlags,
      ...urlAnalysis.flags.map(f => ({ type: 'url', text: f }))
    ],
    url: urlString,
    quickScan: true,
    offlineMode: !threatResult
  };

  // Cache hover results too so repeated hovers are instant
  rememberCache(urlString, result);
  return result;
}

async function resolveRedirectUrl(urlString) {
  if (!urlString) {
    return { original: urlString, final_url: 'Could not resolve', verdict: 'SUSPICIOUS' };
  }

  try {
    const firstAttempt = await fetch(urlString, {
      method: 'HEAD',
      redirect: 'follow',
      cache: 'no-store'
    });

    const finalUrl = String(firstAttempt.url || urlString);
    const finalAnalysis = PhishGuardDetector.analyzeURL(finalUrl);
    const verdict = finalAnalysis.trusted ? 'SAFE' :
      finalAnalysis.score >= 55 ? 'DANGEROUS' :
      finalAnalysis.score >= 25 ? 'SUSPICIOUS' : 'SAFE';

    return {
      original: urlString,
      final_url: finalUrl,
      verdict,
      flags: finalAnalysis.flags
    };
  } catch {
    try {
      const secondAttempt = await fetch(urlString, {
        method: 'GET',
        redirect: 'follow',
        cache: 'no-store'
      });

      const finalUrl = String(secondAttempt.url || urlString);
      const finalAnalysis = PhishGuardDetector.analyzeURL(finalUrl);
      const verdict = finalAnalysis.trusted ? 'SAFE' :
        finalAnalysis.score >= 55 ? 'DANGEROUS' :
        finalAnalysis.score >= 25 ? 'SUSPICIOUS' : 'SAFE';

      return {
        original: urlString,
        final_url: finalUrl,
        verdict,
        flags: finalAnalysis.flags
      };
    } catch {
      return { original: urlString, final_url: 'Could not resolve', verdict: 'SUSPICIOUS' };
    }
  }
}

// ── Message handler ────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'PAGE_SCAN_COMPLETE') {
    const { url, pageData } = message;
    const tabId = sender.tab?.id;

    fullScan(url, pageData, tabId).then(result => {
      storePageStats(tabId, url, pageData, result);
      sendResponse({ success: true, result });

      // If dangerous or suspicious, notify content script to show overlay
      if ((result.verdict === 'DANGEROUS' || result.verdict === 'SUSPICIOUS') && tabId) {
        sendTabMessage(tabId, {
          type: 'SHOW_WARNING',
          result
        });
      }
    });

    return true; // async response
  }

  if (message.type === 'PAGE_SERP_STATS') {
    const tabId = sender.tab?.id;
    if (tabId) {
      serpStatsByTab.set(tabId, {
        dangerCount: Number(message.dangerCount || 0),
        suspiciousCount: Number(message.suspiciousCount || 0),
        timestamp: Date.now()
      });

      chrome.tabs.get(tabId, (tab) => {
        if (!tab || !tab.url || !isGoogleSerpUrl(tab.url)) return;
        setSerpBadge(tabId, message.dangerCount, message.suspiciousCount);
      });
    }

    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'HOVER_LINK') {
    scanHoverLink(message.url).then(result => {
      sendResponse({ result });
    });
    return true;
  }

  if (message.type === 'RESOLVE_REDIRECT') {
    resolveRedirectUrl(message.url).then(result => {
      sendResponse({ result });
    });
    return true;
  }

  if (message.type === 'GET_CURRENT_VERDICT' || message.type === 'GET_VERDICT') {
    if (message.url) {
      const cached = verdictCache.get(message.url);
      sendResponse({ result: cached ? cached.result : null, stats });
      return true;
    }

    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse({ result: null }); return; }

    chrome.tabs.get(tabId, (tab) => {
      const cached = verdictCache.get(tab.url);
      sendResponse({ result: cached ? cached.result : null, stats });
    });
    return true;
  }

  if (message.type === 'GET_PAGE_STATS') {
    const tabId = message.tabId || sender.tab?.id;
    if (!tabId) {
      sendResponse({ result: null });
      return true;
    }

    sendResponse({ result: pageStatsByTab.get(tabId) || null });
    return true;
  }

  if (message.type === 'GET_STATS') {
    sendResponse({ stats });
    return true;
  }

  if (message.type === 'SAVE_API_KEYS') {
    ThreatIntel.saveApiKeys(message.keys || {}).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'GET_API_KEYS') {
    ThreatIntel.loadApiKeys().then((keys) => {
      sendResponse({ keys });
    });
    return true;
  }

  if (message.type === 'GET_RATE_STATUS') {
    sendResponse({ status: ThreatIntel.getRateLimitStatus() });
    return true;
  }

  if (message.type === 'REPORT_FALSE_POSITIVE') {
    // In production: send to backend for model improvement
    console.log('False positive reported:', message.url);
    chrome.storage.local.get(['fp_reports'], (r) => {
      const reports = r.fp_reports || [];
      reports.push({ url: message.url, timestamp: Date.now() });
      chrome.storage.local.set({ fp_reports: reports });
    });
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'BLOCKED_CLICK') {
    stats.blockedClicks++;
    saveStats();
    sendResponse({ success: true });
    return true;
  }
});

// ── Tab navigation listener (trigger scan on page load) ────────
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return; // main frame only
  if (details.url.startsWith('chrome://') || details.url.startsWith('chrome-extension://')) return;

  // Update badge to scanning while waiting for page data
  updateBadge(details.tabId, 'SCANNING');

  // Request page data from content script
  sendTabMessage(details.tabId, { type: 'REQUEST_PAGE_DATA' }).then((response) => {
    if (response) return;

    // Content script may not be ready yet; try URL-only scan
    const urlAnalysis = PhishGuardDetector.analyzeURL(details.url);
    const verdict = urlAnalysis.trusted ? 'SAFE' :
      urlAnalysis.score >= 55 ? 'DANGEROUS' :
      urlAnalysis.score >= 25 ? 'SUSPICIOUS' : 'SAFE';
    updateBadge(details.tabId, verdict);
  });
});

// ── Tab change: restore badge from cache ───────────────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!tab || !tab.url) return;

    if (isGoogleSerpUrl(tab.url) && serpStatsByTab.has(tabId)) {
      const serpStats = serpStatsByTab.get(tabId);
      setSerpBadge(tabId, serpStats.dangerCount, serpStats.suspiciousCount);
      return;
    }

    const cached = verdictCache.get(tab.url);
    if (cached) {
      updateBadge(tabId, cached.result.verdict);
    } else {
      updateBadge(tabId, 'UNKNOWN');
    }
  });
});

console.log('PhishGuard service worker initialized ✓');
