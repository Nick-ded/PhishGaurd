// ============================================================
// PhishGuard — Background Service Worker
// background/service_worker.js
// ============================================================

importScripts('../utils/detector.js', '../utils/ml_scorer.js');

const verdictCache = new Map();
const pageStatsMap = new Map();
const serpStatsByTab = new Map();
const CACHE_TTL = 10 * 60 * 1000;
const MAX_CACHE_ENTRIES = 200;

const BADGE_CONFIG = {
  SAFE: { text: '100', color: '#22863a' },
  SUSPICIOUS: { text: '50', color: '#b08800' },
  DANGEROUS: { text: '0', color: '#cb2431' },
  SCANNING: { text: '...', color: '#94a3b8' },
  UNKNOWN: { text: '?', color: '#94a3b8' }
};

let stats = {
  totalScanned: 0,
  safe: 0,
  suspicious: 0,
  dangerous: 0,
  blockedClicks: 0,
  hindi: 0
};

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

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function purgeCache() {
  while (verdictCache.size > MAX_CACHE_ENTRIES) {
    const oldestKey = verdictCache.keys().next().value;
    if (oldestKey === undefined) break;
    verdictCache.delete(oldestKey);
  }
}

function rememberCache(urlString, entry) {
  if (!urlString || !entry) return;
  verdictCache.set(urlString, { ...entry, ts: Date.now() });
  purgeCache();
}

function getCacheEntry(urlString) {
  const entry = verdictCache.get(urlString);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) {
    verdictCache.delete(urlString);
    return null;
  }
  return entry;
}

function isGoogleSerpUrl(urlString) {
  return /^https:\/\/(www\.)?google\.(com|co\.in)\/search/.test(String(urlString || ''));
}

function setSerpBadge(tabId, dangerCount, suspiciousCount) {
  let badgeText = '0';
  let badgeColor = '#22863a';

  if (Number(dangerCount || 0) > 0) {
    badgeText = String(Number(dangerCount));
    badgeColor = '#cb2431';
  } else if (Number(suspiciousCount || 0) > 0) {
    badgeText = String(Number(suspiciousCount));
    badgeColor = '#b08800';
  }

  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
}

function updateBadge(tabId, verdict, trustScore) {
  const config = BADGE_CONFIG[verdict] || BADGE_CONFIG.UNKNOWN;
  const text = Number.isFinite(Number(trustScore)) ? String(Math.round(Number(trustScore))) : (config.text || '?');
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

function buildPageStats(tabId, urlString, pageData, entry) {
  const protocol = String(pageData?.protocol || (() => {
    try { return new URL(urlString).protocol; } catch { return 'https:'; }
  })() || 'https:').toUpperCase().replace(':', '');

  const cacheEntry = getCacheEntry(urlString);
  const cacheRemainingMs = cacheEntry ? Math.max(0, CACHE_TTL - (Date.now() - cacheEntry.ts)) : 0;

  pageStatsMap.set(tabId, {
    links: Number(pageData?.linkCount ?? pageData?.totalLinks ?? 0),
    externalLinks: Number(pageData?.externalLinkCount ?? 0),
    ads: Number(pageData?.adCount ?? 0),
    suspicious: Number(entry?.verdict === 'DANGEROUS' || entry?.verdict === 'SUSPICIOUS' ? 1 : 0),
    protocol,
    tlsValid: typeof pageData?.tlsValid === 'boolean' ? pageData.tlsValid : String(pageData?.protocol || '').toLowerCase() === 'https:',
    hasSensitiveForms: Number(pageData?.sensitiveFormCount ?? (pageData?.hasPasswordField || pageData?.hasOTPField ? 1 : 0)),
    cacheRemainingMs,
    updatedAt: Date.now(),
    url: urlString
  });
}

function updateStats(verdict) {
  stats.totalScanned++;
  if (verdict === 'SAFE') stats.safe++;
  else if (verdict === 'SUSPICIOUS') stats.suspicious++;
  else if (verdict === 'DANGEROUS') stats.dangerous++;
  saveStats();
}

function safeSendTabMessage(tabId, message) {
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

function normalizeHeuristics(items) {
  return Array.isArray(items) ? items.map((item) => (typeof item === 'string' ? item : String(item?.text || item || ''))).filter(Boolean) : [];
}

function buildEntry(urlString, trustScore, heuristics, pageStats, extra = {}) {
  const verdict = PhishGuardDetector.getVerdict(trustScore);
  return {
    url: urlString,
    verdict,
    trustScore: clamp(Math.round(trustScore || 0), 0, 100),
    heuristics: normalizeHeuristics(heuristics),
    pageStats: pageStats || {},
    ts: Date.now(),
    ...extra
  };
}

async function scoreFullPage(urlString, pageData) {
  const urlAnalysis = PhishGuardDetector.analyzeURL(urlString);
  const pageAnalysis = PhishGuardDetector.analyzePage(pageData);

  const baseTrustScore = clamp(Math.round((Number(urlAnalysis.score || 0) + Number(pageAnalysis.score || 0)) / 2), 0, 100);
  const hfTokenResult = await new Promise((resolve) => {
    chrome.storage.local.get(['hf_token'], (result) => resolve(result?.hf_token || ''));
  });

  const boost = await mlBoost(urlString, pageData?.text || pageData?.bodyText || '', hfTokenResult);
  const trustScore = clamp(baseTrustScore + Number(boost || 0), 0, 100);

  const heuristics = [
    ...urlAnalysis.heuristics,
    ...pageAnalysis.heuristics
  ];

  if (boost !== 0) {
    heuristics.push(boost > 0 ? 'ML boost' : 'ML penalty');
  }

  const entry = buildEntry(urlString, trustScore, heuristics, null, {
    rawRiskScore: clamp(100 - trustScore, 0, 100)
  });

  return entry;
}

async function scanHoverLink(urlString) {
  if (!urlString) return null;

  const cached = getCacheEntry(urlString);
  if (cached) {
    return {
      verdict: cached.verdict,
      score: cached.trustScore,
      heuristics: cached.heuristics || [],
      url: urlString
    };
  }

  const analysis = PhishGuardDetector.analyzeURL(urlString);
  return {
    verdict: analysis.verdict,
    score: analysis.score,
    heuristics: analysis.heuristics || [],
    url: urlString
  };
}

function getResponseForVerdict(urlString, entry) {
  if (!entry) return null;

  return {
    verdict: entry.verdict,
    score: entry.trustScore,
    heuristics: entry.heuristics || [],
    stats: entry.pageStats || {},
    url: urlString
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PAGE_SCAN_COMPLETE') {
    const { url, pageData } = message;
    const tabId = sender.tab?.id;

    scoreFullPage(url, pageData).then((entry) => {
      const pageStats = {
        links: Number(pageData?.linkCount ?? pageData?.totalLinks ?? 0),
        externalLinks: Number(pageData?.externalLinkCount ?? 0),
        ads: Number(pageData?.adCount ?? 0),
        suspicious: Number(entry.verdict === 'DANGEROUS' || entry.verdict === 'SUSPICIOUS' ? 1 : 0),
        protocol: String(pageData?.protocol || 'https:').toUpperCase().replace(':', ''),
        tlsValid: typeof pageData?.tlsValid === 'boolean' ? pageData.tlsValid : String(pageData?.protocol || '').toLowerCase() === 'https:',
        hasSensitiveForms: Number(pageData?.sensitiveFormCount ?? (pageData?.hasPasswordField || pageData?.hasOTPField ? 1 : 0)),
        cacheRemainingMs: 0
      };

      entry.pageStats = pageStats;
      rememberCache(url, entry);
      if (tabId) {
        buildPageStats(tabId, url, pageData, entry);
        updateBadge(tabId, entry.verdict, entry.trustScore);
      }
      updateStats(entry.verdict);
      sendResponse({ success: true, result: entry });

      if (entry.verdict === 'DANGEROUS' && tabId) {
        safeSendTabMessage(tabId, { type: 'SHOW_WARNING', result: entry });
      }
    });

    return true;
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
    scanHoverLink(message.url).then((result) => {
      sendResponse(result ? {
        verdict: result.verdict,
        score: result.score,
        heuristics: result.heuristics || [],
        url: result.url
      } : null);
    });
    return true;
  }

  if (message.type === 'GET_VERDICT') {
    const cacheKey = message.url || sender.tab?.url || '';
    const entry = getCacheEntry(cacheKey);
    sendResponse(getResponseForVerdict(cacheKey, entry));
    return true;
  }

  if (message.type === 'GET_PAGE_STATS') {
    const tabId = message.tabId || sender.tab?.id;
    if (!tabId) {
      sendResponse(null);
      return true;
    }

    sendResponse(pageStatsMap.get(tabId) || null);
    return true;
  }

  if (message.type === 'GET_STATS') {
    sendResponse({ stats });
    return true;
  }

  if (message.type === 'REPORT_FALSE_POSITIVE') {
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

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (details.url.startsWith('chrome://') || details.url.startsWith('chrome-extension://')) return;

  updateBadge(details.tabId, 'SCANNING');

  safeSendTabMessage(details.tabId, { type: 'REQUEST_PAGE_DATA' }).then((response) => {
    if (response) return;

    const fallback = PhishGuardDetector.analyzeURL(details.url);
    updateBadge(details.tabId, fallback.verdict, fallback.score);
  });
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!tab || !tab.url) return;

    if (isGoogleSerpUrl(tab.url) && serpStatsByTab.has(tabId)) {
      const serpStats = serpStatsByTab.get(tabId);
      setSerpBadge(tabId, serpStats.dangerCount, serpStats.suspiciousCount);
      return;
    }

    const cached = getCacheEntry(tab.url);
    if (cached) {
      updateBadge(tabId, cached.verdict, cached.trustScore);
    } else {
      updateBadge(tabId, 'UNKNOWN');
    }
  });
});

console.log('PhishGuard service worker initialized ✓');
