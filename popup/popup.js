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
  rescanBtn: document.getElementById('rescanBtn'),
  settingsBtn: document.getElementById('settingsBtn'),
  reportBtn: document.getElementById('reportBtn'),
  settingsPanel: document.getElementById('settingsPanel'),
  settingsClose: document.getElementById('settingsClose'),
  settingsSave: document.getElementById('settingsSave'),
  toggleHover: document.getElementById('toggleHover'),
  toggleOverlay: document.getElementById('toggleOverlay'),
  toggleHindi: document.getElementById('toggleHindi'),
  toggleStrict: document.getElementById('toggleStrict')
};

const state = {
  tabId: null,
  url: '',
  verdict: null,
  pageStats: null,
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

function iconFor(type) {
  const icons = {
    shield: svgMarkup('M12 2 4 5v6c0 5 3.2 9.4 8 11 4.8-1.6 8-6 8-11V5l-8-3Zm-1 12.4-2.6-2.6 1.4-1.4L11 11.6l4.2-4.2 1.4 1.4-5.6 5.6Z'),
    globe: svgMarkup('M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-2.8a15.3 15.3 0 0 0-1.2-4.1A8.02 8.02 0 0 1 18.9 11Zm-3.3 2h2.8a8.02 8.02 0 0 1-4 4.1c.6-1.2 1-2.6 1.2-4.1ZM12 4.1c.9 1.1 1.7 2.8 2.1 4.9h-4.2c.4-2.1 1.2-3.8 2.1-4.9ZM4.1 13h2.8c.2 1.5.6 2.9 1.2 4.1A8.02 8.02 0 0 1 4.1 13Zm2.8-2H4.1a8.02 8.02 0 0 1 4-4.1c-.6 1.2-1 2.6-1.2 4.1Zm5.1 8.9c-.9-1.1-1.7-2.8-2.1-4.9h4.2c-.4 2.1-1.2 3.8-2.1 4.9Zm1.1-6.9h-4.4a13.7 13.7 0 0 1 0-2h4.4a13.7 13.7 0 0 1 0 2Z'),
    safe: svgMarkup('M12 2 3 6.5V12c0 5.1 3.5 9.8 9 10 5.5-.2 9-4.9 9-10V6.5L12 2Zm0 5.5c.6 0 1 .4 1 1v4.2c0 .6-.4 1-1 1s-1-.4-1-1V8.5c0-.6.4-1 1-1Zm0 9c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Z'),
    suspicious: svgMarkup('M1.8 20.5h20.4L12 2.5 1.8 20.5Zm10.2-3.1c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Zm1-3.7h-2l-.2-5.5h2.4l-.2 5.5Z'),
    danger: svgMarkup('M12 2 3 6.5V12c0 5.1 3.5 9.8 9 10 5.5-.2 9-4.9 9-10V6.5L12 2Zm0 5.5c.6 0 1 .4 1 1v4.2c0 .6-.4 1-1 1s-1-.4-1-1V8.5c0-.6.4-1 1-1Zm0 9c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Z')
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

function quickURLScan(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { verdict: 'DANGEROUS', score: 90, flags: ['Invalid URL'], trusted: false };
  }

  const hostname = url.hostname.toLowerCase();
  const baseDomain = hostname.split('.').slice(-2).join('.');
  if (TRUSTED_DOMAINS.has(baseDomain)) {
    return { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain'], trusted: true };
  }

  let score = 0;
  const flags = [];

  if (url.protocol === 'http:') {
    score += 20;
    flags.push('Not HTTPS');
  }

  const suspiciousTokens = ['login', 'verify', 'secure', 'kyc', 'otp', 'refund', 'claim', 'winner'];
  const found = suspiciousTokens.filter((token) => hostname.includes(token));
  if (found.length > 0) {
    score += found.length * 10;
    flags.push(`Suspicious keywords: ${found.join(', ')}`);
  }

  if (hostname.endsWith('.xyz') || hostname.endsWith('.tk') || hostname.endsWith('.click')) {
    score += 25;
    flags.push('Suspicious TLD');
  }

  const verdict = score >= 60 ? 'DANGEROUS' : score >= 30 ? 'SUSPICIOUS' : 'SAFE';
  return { verdict, score: Math.min(score, 100), flags, trusted: false };
}

function isRenderableUrl(urlString) {
  return /^https?:\/\//i.test(String(urlString || ''));
}

function neutralResult() {
  return { verdict: 'UNKNOWN', score: 0, flags: [] };
}

function formatVerdictTitle(verdict) {
  if (verdict === 'DANGEROUS') return 'Dangerous · Blocked';
  if (verdict === 'SUSPICIOUS') return 'Suspicious · Needs Review';
  if (verdict === 'SAFE') return 'Safe · Verified Domain';
  return 'Unknown · No Data';
}

function formatVerdictSubtitle(verdict, score, flags) {
  const count = Array.isArray(flags) ? flags.length : 0;
  if (verdict === 'SAFE') return `Score ${score}/100 · No threats found`;
  if (verdict === 'SUSPICIOUS') return `Score ${score}/100 · ${count ? `${count} risk signals` : 'Potential risk signals'}`;
  if (verdict === 'DANGEROUS') return `Score ${score}/100 · ${count ? `${count} threats found` : 'Threats detected'}`;
  return `Score ${score}/100 · Waiting for scan`;
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

function renderVerdict(result, url) {
  const verdict = result && result.verdict ? result.verdict : 'SAFE';
  const score = Math.max(0, Math.min(100, Number((result && (result.score ?? result.urlScore)) || 0)));
  const flags = result && Array.isArray(result.flags) ? result.flags : [];
  const titleClass = verdict === 'DANGEROUS' ? 'dangerous' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe';

  dom.verdictCard.className = `pg-verdict-card pg-${titleClass}`;
  dom.verdictIcon.innerHTML = iconFor(verdict === 'DANGEROUS' ? 'danger' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe');
  dom.verdictTitle.textContent = formatVerdictTitle(verdict);
  dom.verdictSubtitle.textContent = formatVerdictSubtitle(verdict, score, flags);
  dom.verdictScore.textContent = `${score}/100`;
  dom.currentUrl.textContent = truncateUrl(url || state.url || '');
  setLiveState(true);
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

    const [verdictResponse, statsResponse] = await Promise.all([
      safeSendMessage({ type: 'GET_VERDICT', url: state.url }),
      safeSendMessage({ type: 'GET_PAGE_STATS', tabId: state.tabId })
    ]);

    const verdict = verdictResponse && verdictResponse.result
      ? verdictResponse.result
      : (isRenderableUrl(state.url) ? quickURLScan(state.url) : neutralResult());
    state.verdict = verdict;
    state.pageStats = statsResponse && statsResponse.result ? statsResponse.result : null;

    renderVerdict(verdict, state.url);
    renderStats(state.pageStats || {
      links: 0,
      ads: 0,
      suspicious: verdict.verdict === 'SAFE' ? 0 : 1,
      externalLinks: 0,
      protocol: (() => {
        try { return new URL(state.url).protocol; } catch { return 'https:'; }
      })(),
      hasSensitiveForms: 0,
      cacheRemainingMs: 0,
      tlsValid: state.url.startsWith('https:')
    });
  } catch {
    setLiveState(false);
    applyFallback(state.url);
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

  dom.settingsBtn.addEventListener('click', () => toggleSettings(true));
  dom.settingsClose.addEventListener('click', () => toggleSettings(false));
  dom.settingsSave.addEventListener('click', () => {
    saveSettings();
    toggleSettings(false);
  });

  [dom.toggleHover, dom.toggleOverlay, dom.toggleHindi, dom.toggleStrict].forEach((input) => {
    input.addEventListener('change', saveSettings);
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