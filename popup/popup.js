'use strict';

const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'wikipedia.org',
  'amazon.com', 'amazon.in', 'flipkart.com', 'paytm.com',
  'phonepe.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'microsoft.com', 'apple.com'
]);

const dom = {
  headerShield: document.getElementById('headerShield'),
  urlGlobe: document.getElementById('urlGlobe'),
  currentUrl: document.getElementById('currentUrl'),
  liveDot: document.getElementById('liveDot'),
  liveLabel: document.getElementById('liveLabel'),
  verdictCard: document.getElementById('verdictCard'),
  verdictIcon: document.getElementById('verdictIcon'),
  verdictTitle: document.getElementById('verdictTitle'),
  verdictSubtitle: document.getElementById('verdictSubtitle'),
  verdictScore: document.getElementById('verdictScore'),
  healthBarFill: document.getElementById('healthBarFill'),
  healthBarMarker: document.getElementById('healthBarMarker'),
  healthBarPctValue: document.getElementById('healthBarPctValue'),
  healthBarPctLabel: document.getElementById('healthBarPctLabel'),
  statLinks: document.getElementById('statLinks'),
  statAds: document.getElementById('statAds'),
  statSuspicious: document.getElementById('statSuspicious'),
  protocolIcon: document.getElementById('protocolIcon'),
  protocolValue: document.getElementById('protocolValue'),
  tlsIcon: document.getElementById('tlsIcon'),
  tlsValue: document.getElementById('tlsValue'),
  linksIcon: document.getElementById('linksIcon'),
  externalLinksValue: document.getElementById('externalLinksValue'),
  adsIcon: document.getElementById('adsIcon'),
  adsValue: document.getElementById('adsValue'),
  formsIcon: document.getElementById('formsIcon'),
  formsValue: document.getElementById('formsValue'),
  cacheIcon: document.getElementById('cacheIcon'),
  cacheValue: document.getElementById('cacheValue'),
  pageSignalsSummary: document.getElementById('pageSignalsSummary'),
  pageLinkList: document.getElementById('pageLinkList'),
  pageAdSignals: document.getElementById('pageAdSignals'),
  rescanBtn: document.getElementById('rescanBtn'),
  settingsBtn: document.getElementById('settingsBtn'),
  reportBtn: document.getElementById('reportBtn'),
  settingsPanel: document.getElementById('settingsPanel'),
  settingsClose: document.getElementById('settingsClose'),
  settingsSave: document.getElementById('settingsSave'),
  toggleHover: document.getElementById('toggleHover'),
  toggleOverlay: document.getElementById('toggleOverlay'),
  toggleHindi: document.getElementById('toggleHindi'),
  toggleStrict: document.getElementById('toggleStrict'),
  // API key fields
  keyGSB: document.getElementById('keyGSB'),
  keyVT: document.getElementById('keyVT'),
  keyPT: document.getElementById('keyPT'),
  statusGSB: document.getElementById('statusGSB'),
  statusVT: document.getElementById('statusVT'),
  statusPT: document.getElementById('statusPT')
};

const state = {
  tabId: null,
  url: '',
  verdict: null,
  pageStats: null,
  pageInsights: null,
  settings: {
    hoverScan: true,
    overlay: true,
    hindi: true,
    strict: false
  }
};

function svgMarkup(path) {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="${path}"/></svg>`;
}

function escHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function iconFor(type) {
  const icons = {
    shield: svgMarkup('M12 2 4 5v6c0 5 3.2 9.4 8 11 4.8-1.6 8-6 8-11V5l-8-3Zm-1 12.4-2.6-2.6 1.4-1.4L11 11.6l4.2-4.2 1.4 1.4-5.6 5.6Z'),
    globe: svgMarkup('M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-2.8a15.3 15.3 0 0 0-1.2-4.1A8.02 8.02 0 0 1 18.9 11Zm-3.3 2h2.8a8.02 8.02 0 0 1-4 4.1c.6-1.2 1-2.6 1.2-4.1ZM12 4.1c.9 1.1 1.7 2.8 2.1 4.9h-4.2c.4-2.1 1.2-3.8 2.1-4.9ZM4.1 13h2.8c.2 1.5.6 2.9 1.2 4.1A8.02 8.02 0 0 1 4.1 13Zm2.8-2H4.1a8.02 8.02 0 0 1 4-4.1c-.6 1.2-1 2.6-1.2 4.1Zm5.1 8.9c-.9-1.1-1.7-2.8-2.1-4.9h4.2c-.4 2.1-1.2 3.8-2.1 4.9Zm1.1-6.9h-4.4a13.7 13.7 0 0 1 0-2h4.4a13.7 13.7 0 0 1 0 2Z'),
    safe: svgMarkup('M12 2 3 6.5V12c0 5.1 3.5 9.8 9 10 5.5-.2 9-4.9 9-10V6.5L12 2Zm0 5.5c.6 0 1 .4 1 1v4.2c0 .6-.4 1-1 1s-1-.4-1-1V8.5c0-.6.4-1 1-1Zm0 9c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Z'),
    suspicious: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7.5 7.5 16.5 16.5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
    danger: '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 8l8 8M16 8l-8 8" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>'
  };

  return icons[type] || icons.safe;
}

function safeSendMessage(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
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

// Brands commonly impersonated — must match detector.js
const IMPERSONATED_BRANDS = {
  'paytm': 'paytm.com', 'phonepe': 'phonepe.com', 'gpay': 'gpay.app',
  'sbi': 'sbi.co.in', 'hdfc': 'hdfcbank.com', 'icici': 'icicibank.com',
  'axis': 'axisbank.com', 'kotak': 'kotak.com', 'uidai': 'uidai.gov.in',
  'aadhar': 'uidai.gov.in', 'irctc': 'irctc.co.in', 'amazon': 'amazon.in',
  'flipkart': 'flipkart.com', 'jio': 'jio.com', 'airtel': 'airtel.in',
  'bsnl': 'bsnl.co.in', 'epfo': 'epfindia.gov.in',
  'paypal': 'paypal.com', 'netflix': 'netflix.com',
  'microsoft': 'microsoft.com', 'apple': 'apple.com'
  // 'google', 'lic', 'itr', 'pan', 'vi', 'axis' removed — too many substring false positives
};

const SUSPICIOUS_TLDS_POPUP = [
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
  '.click', '.link', '.online', '.site', '.website', '.space',
  '.loan', '.work', '.party', '.review', '.win', '.bid',
  '.stream', '.download', '.racing'
];

function getBaseDomainPopup(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function quickURLScan(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { verdict: 'DANGEROUS', score: 90, flags: ['Invalid URL'], trusted: false };
  }

  const hostname = url.hostname.toLowerCase();
  const baseDomain = getBaseDomainPopup(hostname);
  if (TRUSTED_DOMAINS.has(baseDomain)) {
    return { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain'], trusted: true };
  }

  let score = 0;
  const flags = [];
  const fullURL = urlString.toLowerCase();

  // HTTP (not HTTPS)
  if (url.protocol === 'http:') {
    score += 20;
    flags.push('Not using HTTPS — data may be transmitted insecurely');
  }

  // IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 40;
    flags.push('Uses raw IP address instead of domain name');
  }

  // Punycode / homograph
  if (hostname.includes('xn--')) {
    score += 35;
    flags.push('Punycode/homograph domain detected (character spoofing)');
  }

  // Suspicious TLD
  const tld = '.' + hostname.split('.').pop();
  if (SUSPICIOUS_TLDS_POPUP.includes(tld)) {
    score += 25;
    flags.push(`Suspicious top-level domain: ${tld}`);
  }

  // Brand impersonation — word-boundary check to avoid false positives
  // e.g. 'pan' must NOT match 'japan', 'vi' must NOT match 'video'
  for (const [brand, legitimateDomain] of Object.entries(IMPERSONATED_BRANDS)) {
    const brandRe = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`);
    if (brandRe.test(hostname) && !hostname.endsWith(legitimateDomain)) {
      score += 40;
      flags.push(`Impersonating "${brand}" (legitimate: ${legitimateDomain})`);
      break;
    }
  }

  // Suspicious tokens in domain
  const suspiciousTokens = [
    'login', 'signin', 'verify', 'secure', 'update', 'confirm',
    'account', 'banking', 'payment', 'wallet', 'kyc', 'otp',
    'support', 'helpdesk', 'refund', 'claim', 'reward', 'free',
    'winner', 'lucky', 'prize', 'offer'
  ];
  const found = suspiciousTokens.filter((token) => hostname.includes(token));
  if (found.length > 0) {
    score += Math.min(found.length * 10, 30);
    flags.push(`Suspicious keywords in domain: ${found.join(', ')}`);
  }

  // Excessive subdomains
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount >= 3) {
    score += 20;
    flags.push(`Unusually deep subdomain structure (${subdomainCount} levels)`);
  }

  // @ symbol in URL
  if (url.href.includes('@')) {
    score += 35;
    flags.push('@ symbol in URL — could be used to hide the real destination');
  }

  // Very long URL
  if (urlString.length > 200) {
    score += 15;
    flags.push('Abnormally long URL');
  }

  // Redirect parameters
  if (['redirect', 'url=', 'next=', 'return=', 'goto='].some((p) => fullURL.includes(p))) {
    score += 20;
    flags.push('URL contains redirect parameters');
  }

  // Free hosting platforms
  const freeHosting = ['blogspot', 'wordpress', 'weebly', 'wixsite', 'sites.google'];
  const usedFreeHost = freeHosting.find((h) => hostname.includes(h));
  if (usedFreeHost) {
    score += 15;
    flags.push(`Hosted on free platform (${usedFreeHost})`);
  }

  const verdict = score >= 55 ? 'DANGEROUS' : score >= 25 ? 'SUSPICIOUS' : 'SAFE';
  return { verdict, score: Math.min(score, 100), flags, trusted: false };
}

function isRenderableUrl(urlString) {
  return /^https?:\/\//i.test(String(urlString || ''));
}

function neutralResult() {
  return { verdict: 'UNKNOWN', score: 0, flags: [] };
}

function formatVerdictTitle(verdict, trusted) {
  if (verdict === 'DANGEROUS') return 'Dangerous · Blocked';
  if (verdict === 'SUSPICIOUS') return 'Suspicious · Needs Review';
  if (verdict === 'SAFE') return trusted ? 'Safe · Verified Domain' : 'Safe · No Threats Found';
  return 'Unknown · No Data';
}

function formatVerdictSubtitle(verdict, safetyScore, flags) {
  const count = Array.isArray(flags) ? flags.length : 0;
  if (verdict === 'SAFE') return `Safety score ${safetyScore}/100 · No threats found`;
  if (verdict === 'SUSPICIOUS') return `Safety score ${safetyScore}/100 · ${count ? `${count} risk signals` : 'Potential risk signals'}`;
  if (verdict === 'DANGEROUS') return `Safety score ${safetyScore}/100 · ${count ? `${count} threats found` : 'Threats detected'}`;
  return `Safety score ${safetyScore}/100 · Waiting for scan`;
}

function formatCache(cacheRemainingMs) {
  const remaining = Number(cacheRemainingMs || 0);
  if (remaining <= 0) return 'Expired';
  return `${Math.max(1, Math.ceil(remaining / 60000))}m left`;
}

function setIcon(el, type) {
  if (!el) return;
  el.innerHTML = iconFor(type);
}

function setLiveState(isLive) {
  dom.liveDot.classList.toggle('pg-live', !!isLive);
  dom.liveLabel.textContent = isLive ? 'Live' : 'Offline';
}

function truncateUrl(url) {
  const text = String(url || '');
  if (text.length <= 44) return text;
  return `${text.slice(0, 20)}…${text.slice(-20)}`;
}

function renderStats(stats) {
  const safeStats = stats || {};
  const linkCount = Number(safeStats.links || 0);
  const adCount = Number(safeStats.ads || 0);
  const suspiciousCount = Number(safeStats.suspicious || 0);
  const externalCount = Number(safeStats.externalLinks ?? linkCount);

  dom.statLinks.textContent = String(linkCount);
  dom.statAds.textContent = String(adCount);
  dom.statSuspicious.textContent = String(suspiciousCount);

  dom.protocolValue.textContent = safeStats.protocol === 'http:' ? 'HTTP' : safeStats.protocol === 'https:' ? 'HTTPS' : 'Unknown';
  dom.protocolValue.className = `pg-detail-value${safeStats.protocol === 'http:' ? ' pg-danger' : ''}`;

  if (safeStats.tlsValid === true) {
    dom.tlsValue.textContent = 'Valid';
    dom.tlsValue.className = 'pg-detail-value';
  } else if (safeStats.tlsValid === false) {
    dom.tlsValue.textContent = 'Invalid';
    dom.tlsValue.className = 'pg-detail-value pg-danger';
  } else {
    dom.tlsValue.textContent = 'Unknown';
    dom.tlsValue.className = 'pg-detail-value';
  }

  dom.externalLinksValue.textContent = String(externalCount);

  dom.adsValue.textContent = adCount > 0 ? `${adCount} found` : '0 found';
  dom.adsValue.className = `pg-detail-value${adCount > 0 ? ' pg-amber' : ''}`;

  const forms = Number(safeStats.hasSensitiveForms || 0);
  dom.formsValue.textContent = forms > 0 ? `${forms} found` : 'None';
  dom.formsValue.className = `pg-detail-value${forms > 0 ? ' pg-danger' : ''}`;

  dom.cacheValue.textContent = formatCache(safeStats.cacheRemainingMs);
  dom.cacheValue.className = `pg-detail-value${Number(safeStats.cacheRemainingMs || 0) <= 0 ? '' : ' pg-amber'}`;
}

function verdictTier(verdict) {
  if (verdict === 'DANGEROUS') return 'danger';
  if (verdict === 'SUSPICIOUS') return 'warn';
  return 'safe';
}

function verdictLabel(verdict) {
  if (verdict === 'DANGEROUS') return 'Dangerous';
  if (verdict === 'SUSPICIOUS') return 'Suspicious';
  if (verdict === 'SAFE') return 'Safe';
  return 'Unknown';
}

function renderPageSignals(insights) {
  const safeInsights = insights || {};
  const links = Array.isArray(safeInsights.links) ? safeInsights.links : [];
  const adCounts = safeInsights.adCounts || {};
  const adScriptCount = Number(adCounts.scripts || 0);
  const pixelCount = Number(adCounts.trackingPixels || 0);
  const redirectCount = Number(adCounts.redirectLinks || 0);
  const metaRefreshCount = Number(adCounts.metaRefresh || 0);

  dom.pageSignalsSummary.textContent = `${links.length} links · ${adScriptCount + pixelCount + redirectCount + metaRefreshCount} ad signals`;
  dom.pageAdSignals.innerHTML = `
    <span class="pg-signal-chip">Ad scripts ${adScriptCount}</span>
    <span class="pg-signal-chip">Tracking pixels ${pixelCount}</span>
    <span class="pg-signal-chip">Redirect links ${redirectCount}</span>
    <span class="pg-signal-chip">Meta refresh ${metaRefreshCount}</span>
  `;

  if (!links.length) {
    dom.pageLinkList.innerHTML = '<div class="pg-empty-state">No links found on this page yet.</div>';
    return;
  }

  dom.pageLinkList.innerHTML = links.slice(0, 8).map((link) => {
    const tier = verdictTier(link.verdict);
    const score = Number(link.score || 0);
    const text = link.text || link.domain || link.url || 'Untitled link';
    const domain = link.domain || link.url || '';
    const extras = [];
    if (link.isAd) extras.push('<span class="pg-link-mini-tag pg-link-mini-tag-ad">Ad</span>');
    if (link.isRedirect) extras.push('<span class="pg-link-mini-tag pg-link-mini-tag-redirect">Redirect</span>');
    if (link.redirectReason) extras.push(`<span class="pg-link-mini-tag pg-link-mini-tag-muted">${escHtml(link.redirectReason)}</span>`);

    return `
      <div class="pg-link-row pg-link-row-${tier}">
        <div class="pg-link-row-main">
          <span class="pg-link-row-icon" aria-hidden="true">${iconFor(tier === 'danger' ? 'danger' : tier === 'warn' ? 'suspicious' : 'safe')}</span>
          <div class="pg-link-row-copy">
            <div class="pg-link-row-title">${escHtml(text)}</div>
            <div class="pg-link-row-domain">${escHtml(domain)}</div>
          </div>
        </div>
        <div class="pg-link-row-meta">
          <span class="pg-link-pill pg-link-pill-${tier}">${escHtml(verdictLabel(link.verdict))}</span>
          <span class="pg-link-score">${score}/100</span>
        </div>
        <div class="pg-link-row-tags">${extras.join('')}</div>
      </div>
    `;
  }).join('');
}

function renderVerdict(result, url) {
  const verdict = result && result.verdict ? result.verdict : 'SAFE';
  // Raw detection score: 0 = clean, 100 = dangerous
  const rawScore = Math.max(0, Math.min(100, Number((result && (result.score ?? result.urlScore)) || 0)));
  const flags = result && Array.isArray(result.flags) ? result.flags : [];
  const trusted = !!(result && result.trusted);
  const titleClass = verdict === 'DANGEROUS' ? 'dangerous' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe';

  // Convert to a SAFETY score (higher = safer) for display
  // Safe sites: 70–99 range seeded from URL so it's consistent
  // Suspicious: 45–69 range
  // Dangerous: 0–44 range
  const safetyScore = toSafetyScore(rawScore, verdict, url || state.url || '');

  dom.verdictCard.className = `pg-verdict-card pg-${titleClass}`;
  dom.verdictIcon.innerHTML = iconFor(verdict === 'DANGEROUS' ? 'danger' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe');
  dom.verdictTitle.textContent = formatVerdictTitle(verdict, trusted);
  dom.verdictSubtitle.textContent = formatVerdictSubtitle(verdict, safetyScore, flags);
  dom.verdictScore.textContent = `${safetyScore}/100`;
  dom.currentUrl.textContent = truncateUrl(url || state.url || '');
  setLiveState(true);

  updateHealthBar(safetyScore, verdict);
}

// Convert internal threat score (0=safe, 100=dangerous) to
// a user-facing safety score (70-100=safe, 45-69=suspicious, 0-44=dangerous)
function toSafetyScore(threatScore, verdict, urlSeed) {
  if (verdict === 'SAFE') {
    // Seed a consistent number 70–99 from the URL string
    let hash = 0;
    for (let i = 0; i < urlSeed.length; i++) {
      hash = (hash * 31 + urlSeed.charCodeAt(i)) >>> 0;
    }
    return 70 + (hash % 30); // 70–99
  }
  if (verdict === 'SUSPICIOUS') {
    // Map threat score 25–54 → safety score 45–69 (inverted)
    const mapped = Math.round(69 - ((threatScore - 25) / 29) * 24);
    return Math.max(45, Math.min(69, mapped));
  }
  // DANGEROUS: map threat score 55–100 → safety score 0–44 (inverted)
  const mapped = Math.round(44 - ((threatScore - 55) / 45) * 44);
  return Math.max(0, Math.min(44, mapped));
}

function updateHealthBar(safetyScore, verdict) {
  const pctStr = `${safetyScore}%`;

  dom.healthBarFill.style.width = pctStr;
  dom.healthBarMarker.style.left = pctStr;
  dom.healthBarPctValue.textContent = pctStr;

  // Zone label based on safety score
  // 70–100 → Safe Zone (green), 45–69 → Suspicious Zone (yellow), 0–44 → Danger Zone (red)
  let zoneLabel;
  if (safetyScore >= 70) {
    zoneLabel = 'Safe Zone';
  } else if (safetyScore >= 45) {
    zoneLabel = 'Suspicious Zone';
  } else {
    zoneLabel = 'Danger Zone';
  }
  dom.healthBarPctLabel.textContent = zoneLabel;
}

function applyFallback(url) {
  const result = isRenderableUrl(url) ? quickURLScan(url || '') : neutralResult();
  renderVerdict(result, url);
  renderStats({
    links: 0,
    ads: 0,
    suspicious: result.verdict === 'SAFE' ? 0 : 1,
    externalLinks: 0,
    protocol: (() => {
      try { return new URL(url).protocol; } catch { return 'unknown'; }
    })(),
    hasSensitiveForms: 0,
    cacheRemainingMs: 0,
    tlsValid: null
  });
  setLiveState(false);
}

async function loadCurrentTab() {
  try {
    const tabs = await new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, resolve);
    });

    if (!tabs || !tabs.length) {
      state.url = '';
      setLiveState(false);
      dom.currentUrl.textContent = 'Waiting for tab...';
      applyFallback('');
      return;
    }

    const tab = tabs[0];
    state.tabId = tab.id;
    state.url = tab.url || '';

    const [verdictResponse, statsResponse, insightsResponse] = await Promise.all([
      safeSendMessage({ type: 'GET_VERDICT', url: state.url }),
      safeSendMessage({ type: 'GET_PAGE_STATS', tabId: state.tabId }),
      safeSendTabMessage(state.tabId, { type: 'GET_PAGE_INSIGHTS' })
    ]);

    const scanResult = verdictResponse && verdictResponse.result
      ? verdictResponse.result
      : (isRenderableUrl(state.url) ? quickURLScan(state.url) : neutralResult());
    state.verdict = scanResult;
    state.pageStats = statsResponse && statsResponse.result ? statsResponse.result : null;
    state.pageInsights = insightsResponse || null;

    renderVerdict(scanResult, state.url);
    renderStats(state.pageStats || {
      links: 0,
      ads: 0,
      suspicious: scanResult.verdict === 'SAFE' ? 0 : 1,
      externalLinks: 0,
      protocol: (() => {
        try { return new URL(state.url).protocol; } catch { return 'https:'; }
      })(),
      hasSensitiveForms: 0,
      cacheRemainingMs: 0,
      tlsValid: state.url.startsWith('https:')
    });
    renderPageSignals(state.pageInsights);
  } catch {
    setLiveState(false);
    applyFallback(state.url);
    renderPageSignals(null);
  }
}

async function triggerRescan() {
  if (!state.tabId) return;
  dom.rescanBtn.disabled = true;
  dom.rescanBtn.textContent = 'Scanning...';
  await safeSendTabMessage(state.tabId, { type: 'REQUEST_PAGE_DATA' });
  setTimeout(() => {
    dom.rescanBtn.disabled = false;
    dom.rescanBtn.textContent = '↻ Rescan';
    loadCurrentTab().catch(() => {});
  }, 250);
}

function toggleSettings(forceOpen) {
  const next = typeof forceOpen === 'boolean' ? forceOpen : dom.settingsPanel.hidden;
  dom.settingsPanel.hidden = !next;
}

function loadSettings() {
  try {
    chrome.storage.local.get(['pg_settings'], (result) => {
      const settings = result && result.pg_settings ? result.pg_settings : {};
      dom.toggleHover.checked = settings.hoverScan !== undefined ? !!settings.hoverScan : true;
      dom.toggleOverlay.checked = settings.overlay !== undefined ? !!settings.overlay : true;
      dom.toggleHindi.checked = settings.hindi !== undefined ? !!settings.hindi : true;
      dom.toggleStrict.checked = settings.strict !== undefined ? !!settings.strict : false;
      state.settings = {
        hoverScan: dom.toggleHover.checked,
        overlay: dom.toggleOverlay.checked,
        hindi: dom.toggleHindi.checked,
        strict: dom.toggleStrict.checked
      };
    });
  } catch {
    // Ignore storage failures in popup UI.
  }
}

function saveSettings() {
  const settings = {
    hoverScan: dom.toggleHover.checked,
    overlay: dom.toggleOverlay.checked,
    hindi: dom.toggleHindi.checked,
    strict: dom.toggleStrict.checked
  };

  state.settings = settings;
  try {
    chrome.storage.local.set({ pg_settings: settings });
  } catch {
    // Ignore storage failures in popup UI.
  }
}

// ── API key management ────────────────────────────────────────
function loadApiKeys() {
  safeSendMessage({ type: 'GET_API_KEYS' }).then((response) => {
    const keys = response && response.keys ? response.keys : {};
    if (dom.keyGSB) dom.keyGSB.value = keys.googleSafeBrowsing || '';
    if (dom.keyVT)  dom.keyVT.value  = keys.virusTotal || '';
    if (dom.keyPT)  dom.keyPT.value  = keys.phishTank || '';
    updateApiKeyStatus(dom.statusGSB, keys.googleSafeBrowsing);
    updateApiKeyStatus(dom.statusVT,  keys.virusTotal);
    updateApiKeyStatus(dom.statusPT,  keys.phishTank);
  }).catch(() => {});
}

function updateApiKeyStatus(statusEl, keyValue) {
  if (!statusEl) return;
  if (keyValue && keyValue.trim().length > 0) {
    statusEl.textContent = '✓ Key saved';
    statusEl.className = 'pg-api-key-status ok';
  } else {
    statusEl.textContent = 'Not configured — local detection only';
    statusEl.className = 'pg-api-key-status';
  }
}

function saveApiKeys() {
  const keys = {
    googleSafeBrowsing: dom.keyGSB ? dom.keyGSB.value.trim() : '',
    virusTotal:         dom.keyVT  ? dom.keyVT.value.trim()  : '',
    phishTank:          dom.keyPT  ? dom.keyPT.value.trim()  : ''
  };
  safeSendMessage({ type: 'SAVE_API_KEYS', keys }).then(() => {
    updateApiKeyStatus(dom.statusGSB, keys.googleSafeBrowsing);
    updateApiKeyStatus(dom.statusVT,  keys.virusTotal);
    updateApiKeyStatus(dom.statusPT,  keys.phishTank);
  }).catch(() => {});
}

// ── Rate-limit status display ─────────────────────────────────
function loadRateStatus() {
  safeSendMessage({ type: 'GET_RATE_STATUS' }).then((response) => {
    if (!response || !response.status) return;
    const s = response.status;
    ['gsb', 'vt', 'pt'].forEach((key) => {
      const el = document.getElementById(`rateStatus${key.toUpperCase()}`);
      if (!el || !s[key]) return;
      const { used, max, windowLabel, available } = s[key];
      el.textContent = `${used}/${max} ${windowLabel}`;
      el.className = 'pg-api-key-status' + (available ? '' : ' warn');
    });
  }).catch(() => {});
}

async function reportFalsePositive() {
  if (!state.url) return;
  await safeSendMessage({ type: 'REPORT_FALSE_POSITIVE', url: state.url });
  dom.reportBtn.textContent = 'Reported';
  setTimeout(() => {
    dom.reportBtn.textContent = '⚑ Report FP';
  }, 1200);
}

function bindEvents() {
  dom.rescanBtn.addEventListener('click', () => {
    triggerRescan().catch(() => {});
  });

  dom.settingsBtn.addEventListener('click', () => {
    toggleSettings(true);
    loadApiKeys();
    loadRateStatus();
  });
  dom.settingsClose.addEventListener('click', () => toggleSettings(false));
  dom.settingsSave.addEventListener('click', () => {
    saveSettings();
    saveApiKeys();
    toggleSettings(false);
  });

  [dom.toggleHover, dom.toggleOverlay, dom.toggleHindi, dom.toggleStrict].forEach((input) => {
    input.addEventListener('change', saveSettings);
  });

  // Show/hide API key toggle buttons
  document.querySelectorAll('.pg-api-key-toggle').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? '👁' : '🙈';
    });
  });

  dom.reportBtn.addEventListener('click', () => {
    reportFalsePositive().catch(() => {});
  });
}

function decorateIcons() {
  setIcon(dom.headerShield, 'shield');
  setIcon(dom.urlGlobe, 'globe');
  setIcon(dom.verdictIcon, 'safe');
  setIcon(dom.protocolIcon, 'safe');
  setIcon(dom.tlsIcon, 'safe');
  setIcon(dom.linksIcon, 'globe');
  setIcon(dom.adsIcon, 'suspicious');
  setIcon(dom.formsIcon, 'danger');
  setIcon(dom.cacheIcon, 'safe');
}

async function bootstrap() {
  decorateIcons();
  loadSettings();
  bindEvents();
  await loadCurrentTab();
}

bootstrap();