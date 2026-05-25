// GuardianAI - popup.js
// Modified: Rebuilt the popup around the dashboard layout and wired the new sections to the existing scan flow.
// New additions: Session stats, current page verdict card, link list, redirect preview card, ads summary, and dashboard mode.
// Unchanged: Inline URL scanning still uses the same local heuristics fallback as before.

const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'wikipedia.org',
  'amazon.com', 'amazon.in', 'flipkart.com', 'paytm.com',
  'phonepe.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'microsoft.com', 'apple.com'
]);

const VERDICT_CONFIG = {
  SAFE: { icon: '✅', label: 'SAFE', cssClass: 'safe' },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', cssClass: 'suspicious' },
  DANGEROUS: { icon: '🔴', label: 'DANGEROUS', cssClass: 'dangerous' }
};

const dom = {
  currentPageCard: document.getElementById('currentPageCard'),
  currentPageLoading: document.getElementById('currentPageLoading'),
  currentPageContent: document.getElementById('currentPageContent'),
  currentPageVerdictBanner: document.getElementById('currentPageVerdictBanner'),
  currentPageVerdictIcon: document.getElementById('currentPageVerdictIcon'),
  currentPageVerdictLabel: document.getElementById('currentPageVerdictLabel'),
  currentPageVerdictScore: document.getElementById('currentPageVerdictScore'),
  currentPageDomain: document.getElementById('currentPageDomain'),
  currentPageReasons: document.getElementById('currentPageReasons'),
  currentBlockBtn: document.getElementById('currentBlockBtn'),
  offlinePill: document.getElementById('offlinePill'),
  extensionStatusDot: document.getElementById('extensionStatusDot'),
  extensionStatusText: document.getElementById('extensionStatusText'),
  statScanned: document.getElementById('statScanned'),
  statBlocked: document.getElementById('statBlocked'),
  statHindi: document.getElementById('statHindi'),
  pageLinksList: document.getElementById('pageLinksList'),
  scanAllBtn: document.getElementById('scanAllBtn'),
  redirectPreviewCard: document.getElementById('redirectPreviewCard'),
  redirectPreviewClose: document.getElementById('redirectPreviewClose'),
  redirectOriginal: document.getElementById('redirectOriginal'),
  redirectFinal: document.getElementById('redirectFinal'),
  redirectVerdict: document.getElementById('redirectVerdict'),
  redirectPreviewOpen: document.getElementById('redirectPreviewOpen'),
  adsSection: document.getElementById('adsSection'),
  adsHideBtn: document.getElementById('adsHideBtn'),
  adScriptsCount: document.getElementById('adScriptsCount'),
  adPixelsCount: document.getElementById('adPixelsCount'),
  adRedirectCount: document.getElementById('adRedirectCount'),
  blockAdsBtn: document.getElementById('blockAdsBtn'),
  reportPageBtn: document.getElementById('reportPageBtn'),
  copyReportBtn: document.getElementById('copyReportBtn'),
  settingsBtn: document.getElementById('settingsBtn'),
  settingsActionBtn: document.getElementById('settingsActionBtn'),
  dashboardBtn: document.getElementById('dashboardBtn'),
  settingsPanel: document.getElementById('settingsPanel'),
  settingsClose: document.getElementById('settingsClose'),
  settingsDone: document.getElementById('settingsDone'),
  scanBtn: document.getElementById('scanBtn'),
  urlInput: document.getElementById('urlInput'),
  inlineResult: document.getElementById('inlineResult')
};

const state = {
  activeTabId: null,
  activeUrl: '',
  currentResult: null,
  pageInsights: null,
  stats: { scanned: 0, blocked: 0, hindi: 0 },
  settings: { hoverScan: true, overlay: true, hindi: true, strict: false },
  redirectPreview: null,
  dashboardMode: false,
  adsHidden: false
};

function getBaseDomain(hostname) {
  const parts = String(hostname || '').split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function quickURLScan(urlString) {
  let score = 0;
  const flags = [];
  let url;

  try {
    url = new URL(urlString);
  } catch {
    return { score: 90, flags: ['Invalid URL'], verdict: 'DANGEROUS' };
  }

  const hostname = url.hostname.toLowerCase();
  const baseDomain = getBaseDomain(hostname);

  if (TRUSTED_DOMAINS.has(baseDomain)) {
    return { score: 0, flags: ['Verified trusted domain'], verdict: 'SAFE', trusted: true };
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 40;
    flags.push('Raw IP address');
  }

  if (hostname.includes('xn--')) {
    score += 35;
    flags.push('Punycode domain');
  }

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

  const tld = '.' + hostname.split('.').pop();
  const badTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click'];
  if (badTLDs.includes(tld)) {
    score += 25;
    flags.push(`Suspicious TLD: ${tld}`);
  }

  const verdict = score >= 60 ? 'DANGEROUS' : score >= 30 ? 'SUSPICIOUS' : 'SAFE';
  return { score: Math.min(score, 100), flags, verdict };
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function normalizeFlag(flag) {
  if (typeof flag === 'string') return flag;
  if (flag && typeof flag === 'object' && 'text' in flag) return flag.text;
  return String(flag || '');
}

function sendMessage(message, tabId) {
  return new Promise((resolve) => {
    const callback = (response) => {
      if (chrome.runtime.lastError) {
        resolve(null);
        return;
      }
      resolve(response || null);
    };

    if (tabId) {
      chrome.tabs.sendMessage(tabId, message, callback);
    } else {
      chrome.runtime.sendMessage(message, callback);
    }
  });
}

function setViewMode() {
  const params = new URLSearchParams(location.search);
  state.dashboardMode = params.get('view') === 'dashboard';
  document.body.dataset.view = state.dashboardMode ? 'dashboard' : 'popup';
}

function setLoadingState(isLoading) {
  dom.currentPageLoading.hidden = !isLoading;
  dom.currentPageContent.hidden = isLoading;
}

function animateNumber(el, target) {
  const start = Number(el.textContent || 0) || 0;
  const end = Number(target || 0);
  const duration = 320;
  const startedAt = performance.now();

  const tick = (now) => {
    const progress = Math.min(1, (now - startedAt) / duration);
    el.textContent = String(Math.round(start + ((end - start) * progress)));
    if (progress < 1) requestAnimationFrame(tick);
  };

  requestAnimationFrame(tick);
}

function updateSessionStats(stats) {
  state.stats = {
    scanned: Number(stats.totalScanned || stats.scanned || 0),
    blocked: Number(stats.blockedClicks || stats.blocked || 0),
    hindi: Number(stats.hindi || 0)
  };

  animateNumber(dom.statScanned, state.stats.scanned);
  animateNumber(dom.statBlocked, state.stats.blocked);
  animateNumber(dom.statHindi, state.stats.hindi);
}

function verdictClass(verdict) {
  return (VERDICT_CONFIG[verdict] || VERDICT_CONFIG.SAFE).cssClass;
}

function setExtensionStatus(label, offline) {
  dom.extensionStatusText.textContent = label;
  dom.extensionStatusDot.className = `pg-status-dot ${offline ? 'pg-status-dot-offline' : 'pg-status-dot-active'}`;
}

function renderReasons(target, flags) {
  target.innerHTML = '';
  const items = (flags || []).slice(0, 6).map(normalizeFlag);

  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'pg-reason-item pg-reason-safe';
    empty.textContent = 'No suspicious patterns detected';
    target.appendChild(empty);
    return;
  }

  items.forEach((flag) => {
    const item = document.createElement('div');
    item.className = 'pg-reason-item';
    item.textContent = flag;
    target.appendChild(item);
  });
}

function showCurrentPage(result) {
  state.currentResult = result;
  setLoadingState(false);

  const config = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.SAFE;
  const currentClass = verdictClass(result.verdict);
  dom.currentPageCard.className = `pg-card pg-current-card pg-${currentClass}`;
  dom.currentPageVerdictBanner.className = `pg-verdict-banner pg-${currentClass}`;
  dom.currentPageVerdictIcon.textContent = config.icon;
  dom.currentPageVerdictLabel.textContent = config.label;

  const score = Math.max(0, Math.min(100, Number(result.urlScore || result.score || 0)));
  dom.currentPageVerdictScore.textContent = `${score}/100`;

  let domain = '';
  try {
    domain = new URL(result.url || '').hostname;
  } catch {
    domain = result.url || '';
  }

  dom.currentPageDomain.textContent = domain;
  renderReasons(dom.currentPageReasons, result.flags || []);
  dom.currentBlockBtn.hidden = result.verdict !== 'DANGEROUS';
  dom.offlinePill.hidden = !result.offlineMode;
  dom.offlinePill.textContent = result.offlineMode ? 'Offline mode' : 'Online scan';

  if (result.verdict === 'DANGEROUS') {
    dom.currentPageCard.classList.add('pg-card-pulse');
  } else {
    dom.currentPageCard.classList.remove('pg-card-pulse');
  }
}

function renderLinksList(links) {
  const items = Array.isArray(links) ? links : [];
  dom.pageLinksList.innerHTML = '';

  if (!items.length) {
    dom.pageLinksList.innerHTML = '<div class="pg-empty-state">No links found on this page.</div>';
    return;
  }

  const fragment = document.createDocumentFragment();

  items.forEach((link) => {
    const row = document.createElement('div');
    row.className = `pg-link-row pg-link-${(link.verdict || 'SAFE').toLowerCase()}`;

    const icon = document.createElement('span');
    icon.className = 'pg-link-icon';
    icon.textContent = link.isRedirect ? '🔗' : link.isAd ? '📢' : (link.verdict === 'DANGEROUS' ? '🔴' : link.verdict === 'SUSPICIOUS' ? '⚠️' : '✅');

    const body = document.createElement('div');
    body.className = 'pg-link-body';

    const domain = document.createElement('div');
    domain.className = 'pg-link-domain';
    domain.textContent = link.domain || link.url || '';

    const text = document.createElement('div');
    text.className = 'pg-link-text';
    text.textContent = link.text || link.url || '';

    body.appendChild(domain);
    body.appendChild(text);

    const badges = document.createElement('div');
    badges.className = 'pg-link-badges';

    if (link.isAd) {
      const adBadge = document.createElement('span');
      adBadge.className = 'pg-mini-badge pg-mini-badge-ad';
      adBadge.title = 'This is an advertisement link';
      adBadge.textContent = '📢 AD';
      badges.appendChild(adBadge);
    }

    if (link.isRedirect) {
      const redirectBadge = document.createElement('button');
      redirectBadge.type = 'button';
      redirectBadge.className = `pg-mini-badge pg-mini-badge-redirect${link.finalUrl && link.verdict === 'DANGEROUS' ? ' pg-mini-badge-danger' : ''}`;
      redirectBadge.textContent = link.finalUrl && link.verdict === 'DANGEROUS' ? '🔴' : '[Redirect →]';
      redirectBadge.title = 'Open safe preview of the final destination';
      redirectBadge.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        showRedirectPreview(link, redirectBadge).catch(() => {});
      });
      badges.appendChild(redirectBadge);
    }

    row.appendChild(icon);
    row.appendChild(body);
    row.appendChild(badges);
    fragment.appendChild(row);
  });

  dom.pageLinksList.appendChild(fragment);
}

function renderAds(adCounts) {
  dom.adScriptsCount.textContent = String(adCounts?.scripts || 0);
  dom.adPixelsCount.textContent = String(adCounts?.trackingPixels || 0);
  dom.adRedirectCount.textContent = String(adCounts?.redirectLinks || 0);
}

function showRedirectPreviewCard(redirect, originalLink) {
  state.redirectPreview = redirect;
  dom.redirectPreviewCard.hidden = false;
  dom.redirectOriginal.textContent = redirect.original || originalLink.url;
  dom.redirectFinal.textContent = redirect.finalUrl || redirect.final_url || 'Could not resolve';

  const verdict = redirect.verdict || 'SUSPICIOUS';
  const config = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.SUSPICIOUS;
  dom.redirectVerdict.className = `pg-redirect-verdict pg-${verdictClass(verdict)}`;
  dom.redirectVerdict.textContent = `${config.icon} ${config.label}${redirect.finalUrl || redirect.final_url ? ' destination detected' : ' destination could not be resolved'}`;

  dom.redirectPreviewOpen.onclick = () => {
    const finalUrl = redirect.finalUrl || redirect.final_url;
    if (finalUrl && finalUrl !== 'Could not resolve') {
      window.open(finalUrl, '_blank', 'noopener,noreferrer');
    }
  };
}

async function showRedirectPreview(linkInfo, badge) {
  const response = await sendMessage({ type: 'RESOLVE_REDIRECT', url: linkInfo.url }, state.activeTabId);
  const redirect = response && response.result ? response.result : {
    original: linkInfo.url,
    final_url: linkInfo.finalUrl || 'Could not resolve',
    verdict: linkInfo.verdict || 'SUSPICIOUS'
  };

  if (badge && redirect.verdict === 'DANGEROUS') {
    badge.textContent = '🔴';
    badge.classList.add('pg-mini-badge-danger');
  }

  showRedirectPreviewCard({
    ...redirect,
    finalUrl: redirect.finalUrl || redirect.final_url || linkInfo.finalUrl || ''
  }, linkInfo);
}

function hideRedirectPreview() {
  dom.redirectPreviewCard.hidden = true;
  state.redirectPreview = null;
}

function buildReportSummary() {
  const result = state.currentResult || { verdict: 'SAFE', flags: [], url: state.activeUrl, urlScore: 0, pageScore: 0 };
  const insights = state.pageInsights || { links: [], adCounts: {} };
  const flags = (result.flags || []).slice(0, 5).map(normalizeFlag).join(' | ') || 'No major threats found';

  return [
    `GuardianAI Report`,
    `Page: ${state.activeUrl || 'unknown'}`,
    `Verdict: ${result.verdict || 'SAFE'}`,
    `URL risk: ${result.urlScore || result.score || 0}/100`,
    `Page risk: ${result.pageScore || 0}/100`,
    `Flags: ${flags}`,
    `Links scanned: ${insights.links ? insights.links.length : 0}`,
    `Ads scripts: ${insights.adCounts?.scripts || 0}`,
    `Tracking pixels: ${insights.adCounts?.trackingPixels || 0}`,
    `Redirect links: ${insights.adCounts?.redirectLinks || 0}`,
    `Session scanned: ${state.stats.scanned}`,
    `Session blocked: ${state.stats.blocked}`,
    `Hindi detections: ${state.stats.hindi}`
  ].join('\n');
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
  return Promise.resolve();
}

async function copyReport() {
  await copyText(buildReportSummary());
  dom.copyReportBtn.textContent = 'Copied!';
  setTimeout(() => { dom.copyReportBtn.textContent = '📋 Copy Report'; }, 1500);
}

async function reportCurrentPage() {
  if (!state.activeUrl) return;
  await sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: state.activeUrl }, state.activeTabId);
  dom.reportPageBtn.textContent = 'Reported!';
  setTimeout(() => { dom.reportPageBtn.textContent = '🚨 Report Page'; }, 1500);
}

function openDashboard() {
  const url = chrome.runtime.getURL('popup/popup.html?view=dashboard');
  const opened = window.open(url, '_blank', 'noopener,noreferrer');
  if (!opened) location.href = url;
}

function toggleSettings(forceOpen) {
  const nextVisible = typeof forceOpen === 'boolean' ? forceOpen : dom.settingsPanel.hidden;
  dom.settingsPanel.hidden = !nextVisible;
}

function saveSettings() {
  chrome.storage.local.set({
    pg_settings: {
      hoverScan: document.getElementById('toggleHover').checked,
      overlay: document.getElementById('toggleOverlay').checked,
      hindi: document.getElementById('toggleHindi').checked,
      strict: document.getElementById('toggleStrict').checked
    }
  });
}

function loadSettings() {
  chrome.storage.local.get(['pg_settings'], (result) => {
    const settings = result.pg_settings || {};
    if (settings.hoverScan !== undefined) document.getElementById('toggleHover').checked = settings.hoverScan;
    if (settings.overlay !== undefined) document.getElementById('toggleOverlay').checked = settings.overlay;
    if (settings.hindi !== undefined) document.getElementById('toggleHindi').checked = settings.hindi;
    if (settings.strict !== undefined) document.getElementById('toggleStrict').checked = settings.strict;
    state.settings = {
      hoverScan: document.getElementById('toggleHover').checked,
      overlay: document.getElementById('toggleOverlay').checked,
      hindi: document.getElementById('toggleHindi').checked,
      strict: document.getElementById('toggleStrict').checked
    };
  });
}

function renderFallbackInsights(tabUrl) {
  const result = quickURLScan(tabUrl || '');
  setExtensionStatus('Offline mode', true);
  dom.offlinePill.hidden = false;
  dom.offlinePill.textContent = 'Offline mode';
  state.pageInsights = { links: [], adCounts: { scripts: 0, trackingPixels: 0, redirectLinks: 0 }, offlineMode: true };
  renderLinksList([]);
  renderAds({ scripts: 0, trackingPixels: 0, redirectLinks: 0 });
  showCurrentPage({ ...result, url: tabUrl || '', pageScore: 0, offlineMode: true });
}

async function loadCurrentTab() {
  setLoadingState(true);

  const tabs = await new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, resolve);
  });

  if (!tabs || !tabs.length) {
    renderFallbackInsights('');
    return;
  }

  const tab = tabs[0];
  state.activeTabId = tab.id;
  state.activeUrl = tab.url || '';

  const [verdictResponse, insightsResponse] = await Promise.all([
    sendMessage({ type: 'GET_CURRENT_VERDICT' }),
    sendMessage({ type: 'GET_PAGE_INSIGHTS' }, tab.id)
  ]);

  const verdictResult = verdictResponse && verdictResponse.result ? verdictResponse.result : quickURLScan(state.activeUrl);
  const pageInsights = insightsResponse || {
    links: [],
    adCounts: { scripts: 0, trackingPixels: 0, redirectLinks: 0 },
    offlineMode: true
  };

  state.pageInsights = pageInsights;
  showCurrentPage({ ...verdictResult, url: state.activeUrl, offlineMode: !!pageInsights.offlineMode || !!verdictResult.offlineMode });
  renderLinksList(pageInsights.links || []);
  renderAds(pageInsights.adCounts || {});
  setExtensionStatus(pageInsights.offlineMode || verdictResult.offlineMode ? 'Offline mode' : 'Active', !!(pageInsights.offlineMode || verdictResult.offlineMode));

  if (verdictResponse && verdictResponse.stats) {
    updateSessionStats(verdictResponse.stats);
  }

  setLoadingState(false);
}

async function refreshPageInsights() {
  if (!state.activeTabId) return;
  const response = await sendMessage({ type: 'GET_PAGE_INSIGHTS' }, state.activeTabId);
  if (!response) return;
  state.pageInsights = response;
  renderLinksList(response.links || []);
  renderAds(response.adCounts || {});
}

async function scanAllLinks() {
  if (!state.activeTabId) return;
  dom.scanAllBtn.textContent = 'Scanning...';
  await sendMessage({ type: 'SCAN_ALL_LINKS' }, state.activeTabId);
  await refreshPageInsights();
  dom.scanAllBtn.textContent = 'Scan All';
}

function hookEvents() {
  dom.scanBtn.addEventListener('click', () => {
    const raw = dom.urlInput.value.trim();
    if (!raw) return;

    dom.inlineResult.textContent = '🔄 Scanning...';
    dom.inlineResult.className = 'pg-inline-result';

    const fullURL = raw.startsWith('http') ? raw : `https://${raw}`;
    const result = quickURLScan(fullURL);
    const config = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.SAFE;

    dom.inlineResult.textContent = `${config.icon} ${config.label}: ${result.flags[0] || 'No major threats found'}`;
    dom.inlineResult.className = `pg-inline-result pg-inline-${result.verdict.toLowerCase()}`;
  });

  dom.urlInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') dom.scanBtn.click();
  });

  dom.settingsBtn.addEventListener('click', () => toggleSettings(true));
  dom.settingsActionBtn.addEventListener('click', () => toggleSettings(true));
  dom.settingsClose.addEventListener('click', () => toggleSettings(false));
  dom.settingsDone.addEventListener('click', () => {
    saveSettings();
    toggleSettings(false);
  });

  ['toggleHover', 'toggleOverlay', 'toggleHindi', 'toggleStrict'].forEach((id) => {
    document.getElementById(id).addEventListener('change', saveSettings);
  });

  dom.currentBlockBtn.addEventListener('click', () => {
    if (!state.currentResult || !state.activeTabId) return;
    sendMessage({ type: 'SHOW_WARNING', result: state.currentResult }, state.activeTabId);
  });

  dom.scanAllBtn.addEventListener('click', () => scanAllLinks().catch(() => {}));
  dom.redirectPreviewClose.addEventListener('click', hideRedirectPreview);
  dom.redirectPreviewOpen.addEventListener('click', () => {
    const finalUrl = state.redirectPreview && (state.redirectPreview.finalUrl || state.redirectPreview.final_url);
    if (finalUrl && finalUrl !== 'Could not resolve') {
      window.open(finalUrl, '_blank', 'noopener,noreferrer');
    }
  });

  dom.adsHideBtn.addEventListener('click', () => {
    state.adsHidden = !state.adsHidden;
    dom.adsSection.querySelector('.pg-ads-grid').hidden = state.adsHidden;
    dom.blockAdsBtn.hidden = state.adsHidden;
    dom.adsHideBtn.textContent = state.adsHidden ? '[Show]' : '[Hide]';
  });

  dom.blockAdsBtn.addEventListener('click', () => {
    dom.blockAdsBtn.textContent = 'Ads labeled';
    setTimeout(() => { dom.blockAdsBtn.textContent = 'Block All Ads on Page'; }, 1200);
    refreshPageInsights().catch(() => {});
  });

  dom.reportPageBtn.addEventListener('click', () => reportCurrentPage().catch(() => {}));
  dom.copyReportBtn.addEventListener('click', () => copyReport().catch(() => {}));
  dom.dashboardBtn.addEventListener('click', openDashboard);
}

async function loadStats() {
  const response = await sendMessage({ type: 'GET_STATS' });
  if (response && response.stats) {
    updateSessionStats(response.stats);
    return;
  }

  chrome.storage.session.get(['phishguard_stats'], (result) => {
    if (result && result.phishguard_stats) {
      updateSessionStats(result.phishguard_stats);
    }
  });
}

async function bootstrap() {
  setViewMode();
  loadSettings();
  hookEvents();
  await loadStats();
  await loadCurrentTab();
}

bootstrap();