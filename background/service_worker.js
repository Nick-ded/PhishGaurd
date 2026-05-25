// ============================================================
// PhishGuard — Background Service Worker
// background/service_worker.js
// ============================================================

importScripts('../utils/detector.js');

// ── In-memory cache for scan results ────────────────────────
const verdictCache = new Map();
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

  const pageAnalysis = PhishGuardDetector.analyzePage(pageData);
  const verdict = PhishGuardDetector.getVerdict(urlAnalysis.score, pageAnalysis.score);

  const allFlags = [
    ...urlAnalysis.flags.map(f => ({ type: 'url', text: f })),
    ...pageAnalysis.flags.map(f => ({ type: 'page', text: f }))
  ];

  const result = {
    verdict,
    urlScore: urlAnalysis.score,
    pageScore: pageAnalysis.score,
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

// ── Hover link scan (lightweight, URL-only) ───────────────────
async function scanHoverLink(urlString) {
  if (!urlString) return null;

  const cached = verdictCache.get(urlString);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  const urlAnalysis = PhishGuardDetector.analyzeURL(urlString);
  const verdict = urlAnalysis.trusted ? 'SAFE' :
    urlAnalysis.score >= 60 ? 'DANGEROUS' :
    urlAnalysis.score >= 30 ? 'SUSPICIOUS' : 'SAFE';

  return {
    verdict,
    urlScore: urlAnalysis.score,
    pageScore: 0,
    flags: urlAnalysis.flags.map(f => ({ type: 'url', text: f })),
    url: urlString,
    quickScan: true,
    offlineMode: true
  };
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
      finalAnalysis.score >= 60 ? 'DANGEROUS' :
      finalAnalysis.score >= 30 ? 'SUSPICIOUS' : 'SAFE';

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
        finalAnalysis.score >= 60 ? 'DANGEROUS' :
        finalAnalysis.score >= 30 ? 'SUSPICIOUS' : 'SAFE';

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
      sendResponse({ success: true, result });

      // If dangerous, notify content script to show overlay
      if (result.verdict === 'DANGEROUS' && tabId) {
        chrome.tabs.sendMessage(tabId, {
          type: 'SHOW_WARNING',
          result
        }).catch(() => {});
      }
    });

    return true; // async response
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

  if (message.type === 'GET_CURRENT_VERDICT') {
    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse({ result: null }); return; }

    chrome.tabs.get(tabId, (tab) => {
      const cached = verdictCache.get(tab.url);
      sendResponse({ result: cached ? cached.result : null, stats });
    });
    return true;
  }

  if (message.type === 'GET_STATS') {
    sendResponse({ stats });
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
  chrome.tabs.sendMessage(details.tabId, { type: 'REQUEST_PAGE_DATA' }).catch(() => {
    // Content script may not be ready yet; try URL-only scan
    const urlAnalysis = PhishGuardDetector.analyzeURL(details.url);
    const verdict = urlAnalysis.trusted ? 'SAFE' :
      urlAnalysis.score >= 60 ? 'DANGEROUS' :
      urlAnalysis.score >= 30 ? 'SUSPICIOUS' : 'SAFE';
    updateBadge(details.tabId, verdict);
  });
});

// ── Tab change: restore badge from cache ───────────────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!tab || !tab.url) return;
    const cached = verdictCache.get(tab.url);
    if (cached) {
      updateBadge(tabId, cached.result.verdict);
    } else {
      updateBadge(tabId, 'UNKNOWN');
    }
  });
});

console.log('PhishGuard service worker initialized ✓');
