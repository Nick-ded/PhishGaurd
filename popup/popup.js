'use strict';

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
  hfTokenInput: document.getElementById('hfTokenInput'),
  saveHfToken: document.getElementById('saveHfToken')
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

function setIcon(el, type) {
  if (!el) return;
  el.innerHTML = iconFor(type);
}

function setLiveState() {
  dom.liveDot.classList.add('pg-live');
  dom.liveLabel.textContent = 'Live';
}

function formatVerdictTitle(verdict) {
  if (verdict === 'SAFE') return 'Safe · Verified Domain';
  if (verdict === 'SUSPICIOUS') return 'Suspicious · Proceed with caution';
  if (verdict === 'DANGEROUS') return 'Dangerous · Do not proceed';
  return 'Unknown · No Data';
}

function formatVerdictSubtitle(verdict, score, heuristics) {
  const count = Array.isArray(heuristics) ? heuristics.length : 0;
  if (verdict === 'SAFE') return `Trust score ${score}/100 · ${count ? `${count} rule hits` : 'No threats found'}`;
  if (verdict === 'SUSPICIOUS') return `Trust score ${score}/100 · ${count ? `${count} risk signals` : 'Potential risk signals'}`;
  if (verdict === 'DANGEROUS') return `Trust score ${score}/100 · ${count ? `${count} danger signals` : 'Threats detected'}`;
  return `Trust score ${score}/100 · Waiting for scan`;
}

function formatCache(cacheRemainingMs) {
  const remaining = Number(cacheRemainingMs || 0);
  if (remaining <= 0) return 'Expired';
  return `${Math.max(1, Math.ceil(remaining / 60000))}m left`;
}

function updateHealthBar(score) {
  const trustScore = clamp(Number(score || 0), 0, 100);
  const pct = `${trustScore}%`;

  dom.healthBarFill.style.width = pct;
  dom.healthBarMarker.style.left = pct;
  dom.healthBarPctValue.textContent = pct;

  if (trustScore >= 71) {
    dom.healthBarPctLabel.textContent = 'SAFE ZONE';
  } else if (trustScore >= 45) {
    dom.healthBarPctLabel.textContent = 'SUSPICIOUS';
  } else {
    dom.healthBarPctLabel.textContent = 'DANGEROUS';
  }
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
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

  dom.protocolValue.textContent = safeStats.protocol || 'Unknown';
  dom.protocolValue.className = `pg-detail-value${String(safeStats.protocol || '').toUpperCase() === 'HTTP' ? ' pg-danger' : ''}`;

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
    dom.pageLinkList.innerHTML = '<div class="pg-empty-state">Open a page with links to see per-link verdicts here.</div>';
    return;
  }

  dom.pageLinkList.innerHTML = links.slice(0, 8).map((link) => {
    const verdict = link.verdict || 'SAFE';
    const score = Number(link.score || 0);
    const text = link.text || link.domain || link.url || 'Untitled link';
    const domain = link.domain || link.url || '';
    const extras = [];
    if (link.isAd) extras.push('<span class="pg-link-mini-tag pg-link-mini-tag-ad">Ad</span>');
    if (link.isRedirect) extras.push('<span class="pg-link-mini-tag pg-link-mini-tag-redirect">Redirect</span>');
    if (link.redirectReason) extras.push(`<span class="pg-link-mini-tag pg-link-mini-tag-muted">${escHtml(link.redirectReason)}</span>`);

    const tier = verdict === 'DANGEROUS' ? 'danger' : verdict === 'SUSPICIOUS' ? 'warn' : 'safe';

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
          <span class="pg-link-pill pg-link-pill-${tier}">${escHtml(verdict)}</span>
          <span class="pg-link-score">${score}/100</span>
        </div>
        <div class="pg-link-row-tags">${extras.join('')}</div>
      </div>
    `;
  }).join('');
}

function renderPopup(url, verdictData, statsData, insightsData) {
  const score = Number(verdictData?.score ?? 50);
  const verdict = verdictData?.verdict ?? 'SAFE';
  const heuristics = Array.isArray(verdictData?.heuristics) ? verdictData.heuristics : [];
  const stats = statsData || {};

  setLiveState();
  dom.currentUrl.textContent = String(url || '');

  dom.verdictCard.className = `pg-verdict-card pg-${verdict === 'DANGEROUS' ? 'dangerous' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe'}`;
  dom.verdictIcon.innerHTML = iconFor(verdict === 'DANGEROUS' ? 'danger' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe');
  dom.verdictTitle.textContent = formatVerdictTitle(verdict);
  dom.verdictSubtitle.textContent = formatVerdictSubtitle(verdict, score, heuristics);
  dom.verdictScore.textContent = `${score}/100`;

  const verdictColors = {
    SAFE: '#22863a',
    SUSPICIOUS: '#b08800',
    DANGEROUS: '#cb2431'
  };
  dom.verdictTitle.style.color = verdictColors[verdict] || verdictColors.SAFE;
  dom.verdictScore.style.color = verdictColors[verdict] || verdictColors.SAFE;

  dom.healthBarFill.style.width = `${score}%`;
  dom.healthBarMarker.style.left = `${score}%`;
  dom.healthBarPctValue.textContent = `${score}%`;
  updateHealthBar(score);

  renderStats(stats);
  renderPageSignals(insightsData);
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

function saveHfToken() {
  const value = String(dom.hfTokenInput?.value || '').trim();
  chrome.storage.local.set({ hf_token: value }, () => {
    if (!dom.saveHfToken) return;
    dom.saveHfToken.textContent = 'Saved ✓';
    setTimeout(() => {
      dom.saveHfToken.textContent = 'Save token';
    }, 1500);
  });
}

function loadHfToken() {
  chrome.storage.local.get('hf_token', (result) => {
    if (result && result.hf_token && dom.hfTokenInput) {
      dom.hfTokenInput.value = result.hf_token;
    }
  });
}

function toggleSettings(forceOpen) {
  const next = typeof forceOpen === 'boolean' ? forceOpen : dom.settingsPanel.hidden;
  dom.settingsPanel.hidden = !next;
}

function bindEvents() {
  dom.rescanBtn.addEventListener('click', () => {
    loadPopupData();
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

  if (dom.saveHfToken) {
    dom.saveHfToken.addEventListener('click', saveHfToken);
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

async function loadPopupData() {
  const tabs = await new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, resolve);
  });

  const [tab] = tabs || [];
  if (!tab) return;

  state.tabId = tab.id;
  state.url = tab.url || '';

  chrome.runtime.sendMessage({ type: 'GET_VERDICT', url: tab.url }, (verdictData) => {
    chrome.runtime.sendMessage({ type: 'GET_PAGE_STATS', tabId: tab.id }, (statsData) => {
      chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_INSIGHTS' }, (insightsData) => {
        if (chrome.runtime.lastError) {
          renderPopup(tab.url, verdictData, statsData, null);
          return;
        }

        renderPopup(tab.url, verdictData, statsData, insightsData);
      });
    });
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

function bootstrap() {
  decorateIcons();
  loadSettings();
  loadHfToken();
  bindEvents();
  setLiveState();
  loadPopupData();
}

bootstrap();
