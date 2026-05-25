// ============================================================
// PhishGuard — Content Script
// content/content_script.js
// ============================================================

(function () {
  'use strict';

  const HOVER_DELAY_MS = 120;
  const GOOGLE_SERP_RE = /google\.(com|co\.in)\/search/;
  const HOVER_LIMIT = 150;

  const hoverCache = new Map();
  const hoverState = {
    timer: null,
    activeAnchor: null,
    tooltip: null,
    requestId: 0
  };

  function escHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function ensureUrl(urlString) {
    try {
      return new URL(urlString, location.href);
    } catch {
      return null;
    }
  }

  function getLinkUrl(link) {
    if (!link) return '';
    const rawHref = link.getAttribute('href') || link.href || '';
    if (!rawHref || rawHref.startsWith('javascript:') || rawHref.startsWith('#') || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) {
      return '';
    }
    const parsed = ensureUrl(rawHref);
    return parsed ? parsed.href : '';
  }

  function getLinkText(link) {
    const text = (link.textContent || link.getAttribute('aria-label') || link.title || link.href || '').trim();
    return text.replace(/\s+/g, ' ').slice(0, 140);
  }

  function getDisplayDomain(urlString) {
    const parsed = ensureUrl(urlString);
    if (!parsed) return String(urlString || '').slice(0, 64);
    return parsed.hostname || parsed.href;
  }

  function isAdMatch(value) {
    const text = String(value || '').toLowerCase();
    const patterns = [
      'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
      'amazon-adsystem.com', 'facebook.com/tr', 'analytics.google.com',
      'hotjar.com', 'clarity.ms', '/ads/', '/advertisement/', '/sponsored/',
      '/tracking/', '/pixel/', 'gtag(', 'fbq(', '_gaq.', 'datalayer'
    ];
    return patterns.some((pattern) => text.includes(pattern));
  }

  function isRedirectCandidate(urlString) {
    const parsed = ensureUrl(urlString);
    if (!parsed) return { hit: false, reason: '' };

    const hostname = parsed.hostname.toLowerCase();
    const href = parsed.href.toLowerCase();
    const redirectDomains = [
      'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'ow.ly',
      'buff.ly', 'tiny.cc', 'is.gd', 'rb.gy', 'cutt.ly', 'short.io'
    ];

    if (redirectDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`) || hostname.includes(domain))) {
      return { hit: true, reason: 'Shortened redirect domain detected' };
    }

    if (['?url=', '?redirect=', '?goto=', '?link='].some((part) => href.includes(part))) {
      return { hit: true, reason: 'Redirect parameter detected' };
    }

    if (href.includes('/redirect/')) {
      return { hit: true, reason: 'Redirect path detected' };
    }

    return { hit: false, reason: '' };
  }

  function getBaseDomain(hostname) {
    const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function sendRuntimeMessage(message) {
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

  function getLinkCacheKey(urlString) {
    return String(urlString || '');
  }

  function rememberHoverResult(urlString, result) {
    const key = getLinkCacheKey(urlString);
    if (!key || !result) return;
    if (hoverCache.has(key)) hoverCache.delete(key);
    hoverCache.set(key, { result, ts: Date.now() });
    while (hoverCache.size > HOVER_LIMIT) {
      const oldestKey = hoverCache.keys().next().value;
      if (oldestKey === undefined) break;
      hoverCache.delete(oldestKey);
    }
  }

  function readHoverResult(urlString) {
    const key = getLinkCacheKey(urlString);
    const entry = hoverCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > 10 * 60 * 1000) {
      hoverCache.delete(key);
      return null;
    }
    return entry.result;
  }

  async function scanHoverUrl(urlString) {
    const cached = readHoverResult(urlString);
    if (cached) return cached;

    const response = await sendRuntimeMessage({ type: 'HOVER_LINK', url: urlString });
    if (!response) return null;

    const result = {
      verdict: response.verdict || 'SAFE',
      score: Number(response.score || 0),
      heuristics: Array.isArray(response.heuristics) ? response.heuristics : [],
      url: urlString
    };
    rememberHoverResult(urlString, result);
    return result;
  }

  function removeTooltip() {
    if (hoverState.tooltip) {
      hoverState.tooltip.remove();
      hoverState.tooltip = null;
    }
  }

  function makeTooltip(anchor, verdict, score, heuristics) {
    removeTooltip();

    const tooltip = document.createElement('div');
    tooltip.className = 'pg-hover-tip';

    const color = verdict === 'SAFE' ? '#22863a' : verdict === 'SUSPICIOUS' ? '#b08800' : '#cb2431';
    const icon = verdict === 'SAFE' ? '✔' : verdict === 'SUSPICIOUS' ? '⚠' : '✕';
    const parsed = ensureUrl(anchor.href);
    const domain = parsed ? parsed.hostname : anchor.href;

    tooltip.innerHTML = `
      <div class="pg-tip-top">
        <span class="pg-tip-badge" style="background:${color}20;color:${color};border:1px solid ${color}40">
          ${icon} ${escHtml(verdict)} · ${Math.round(score)}%
        </span>
      </div>
      <div class="pg-tip-domain">${escHtml(domain)}</div>
      <div class="pg-tip-tags">${(heuristics || []).slice(0, 3).map((value) => `<span class="pg-tip-tag">${escHtml(value)}</span>`).join('')}</div>
    `;

    tooltip.style.cssText = `
      position:fixed;
      z-index:2147483647;
      background:#1a1a1a;
      color:#f5f5f5;
      border-radius:8px;
      padding:10px 12px;
      min-width:190px;
      max-width:260px;
      pointer-events:none;
      font-family:system-ui,sans-serif;
      box-shadow:0 4px 16px rgba(0,0,0,.35);
    `;

    document.body.appendChild(tooltip);
    hoverState.tooltip = tooltip;

    const rect = anchor.getBoundingClientRect();
    let top = rect.bottom + 6;
    let left = rect.left;
    if (top + 100 > window.innerHeight) top = rect.top - 110;
    if (left + 260 > window.innerWidth) left = window.innerWidth - 270;
    tooltip.style.top = `${clamp(top, 8, window.innerHeight - 20)}px`;
    tooltip.style.left = `${clamp(left, 8, window.innerWidth - 20)}px`;
  }

  function scheduleHover(anchor) {
    clearTimeout(hoverState.timer);
    hoverState.activeAnchor = anchor;
    const requestId = ++hoverState.requestId;

    hoverState.timer = setTimeout(async () => {
      const active = hoverState.activeAnchor;
      if (!active || requestId !== hoverState.requestId) return;

      const result = await scanHoverUrl(active.href);
      if (!result || requestId !== hoverState.requestId || hoverState.activeAnchor !== active) return;
      makeTooltip(active, result.verdict, result.score, result.heuristics || []);
    }, HOVER_DELAY_MS);
  }

  (function initHoverTooltips() {
    document.addEventListener('mouseover', function (event) {
      const anchor = event.target.closest('a[href^="http"]');
      if (!anchor) return;
      clearTimeout(hoverState.timer);
      scheduleHover(anchor);
    }, true);

    document.addEventListener('mouseout', function (event) {
      if (event.target.closest('a[href^="http"]')) {
        clearTimeout(hoverState.timer);
        setTimeout(removeTooltip, 200);
      }
    }, true);
  })();

  async function scanAndBadge(anchor) {
    if (anchor.dataset.pgDone) return;
    anchor.dataset.pgDone = '1';

    const href = anchor.href;
    if (!href || href.startsWith('javascript') || href.startsWith('#')) return;

    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'HOVER_LINK', url: href }, (resp) => {
        if (chrome.runtime.lastError || !resp) {
          resolve();
          return;
        }

        const verdict = resp.verdict || 'SAFE';
        const score = Math.round(Number(resp.score || 0));
        const colors = {
          SAFE: { bg: '#eaf3de', border: '#3b6d11', text: '#27500a', dot: '#22863a' },
          SUSPICIOUS: { bg: '#faeeda', border: '#854f0b', text: '#633806', dot: '#b08800' },
          DANGEROUS: { bg: '#fcebeb', border: '#a32d2d', text: '#791f1f', dot: '#cb2431' }
        };
        const c = colors[verdict] || colors.SAFE;
        const icon = verdict === 'SAFE' ? '✔' : verdict === 'SUSPICIOUS' ? '⚠' : '✕';

        const badge = document.createElement('span');
        badge.className = 'pg-serp-badge';
        badge.style.cssText = `
          display:inline-flex;align-items:center;gap:4px;
          font-size:11px;font-weight:500;padding:2px 8px;
          border-radius:10px;margin-left:8px;vertical-align:middle;
          background:${c.bg};color:${c.text};border:1px solid ${c.border};
          font-family:system-ui,sans-serif;white-space:nowrap;
        `;
        badge.textContent = `${icon} ${verdict} · ${score}%`;

        const h3 = anchor.closest('h3');
        if (h3 && !h3.querySelector('.pg-serp-badge')) {
          h3.style.display = 'flex';
          h3.style.alignItems = 'center';
          h3.style.flexWrap = 'wrap';
          h3.appendChild(badge);
        }

        resolve();
      });
    });
  }

  async function runSerpScan() {
    const selectors = [
      '#search h3 > a',
      '#search .yuRUbf > a',
      '#search a:has(> h3)',
      'div[data-sokoban-grid] h3 > a'
    ];

    const seen = new Set();
    for (const selector of selectors) {
      for (const anchor of document.querySelectorAll(selector)) {
        if (!seen.has(anchor)) {
          seen.add(anchor);
          await scanAndBadge(anchor);
        }
      }
    }
  }

  function isGoogleSERP() {
    return GOOGLE_SERP_RE.test(location.href);
  }

  function extractPageData() {
    const links = Array.from(document.querySelectorAll('a[href]'));
    const bodyText = document.body ? (document.body.innerText || document.body.textContent || '').slice(0, 5000) : '';
    const formFields = [];

    document.querySelectorAll('input').forEach((input) => {
      const name = (input.name || input.id || input.placeholder || '').toLowerCase();
      if (name) formFields.push(name);
    });

    const externalLinkCount = links.filter((link) => {
      const href = getLinkUrl(link);
      if (!href) return false;
      try {
        const parsed = new URL(href);
        return parsed.hostname && parsed.hostname !== location.hostname;
      } catch {
        return false;
      }
    }).length;

    const adCount = document.querySelectorAll('iframe[src*="doubleclick"], ins.adsbygoogle, [id*="google_ads"], div[data-ad-slot]').length;

    return {
      title: document.title || '',
      bodyText,
      text: bodyText,
      forms: formFields,
      linkCount: links.length,
      externalLinkCount,
      adCount,
      sensitiveFormCount: (document.querySelectorAll('input[type="password"]').length || 0) + (formFields.some((field) => /otp|pin|code/.test(field)) ? 1 : 0),
      hasPasswordField: !!document.querySelector('input[type="password"]'),
      hasOTPField: formFields.some((field) => /otp|pin|code/.test(field)),
      protocol: location.protocol,
      tlsValid: location.protocol === 'https:',
      url: window.location.href
    };
  }

  async function extractPageInsights() {
    const links = Array.from(document.querySelectorAll('a[href]'));
    const selectedLinks = links.slice(0, 20);
    const adSelectors = 'iframe[src*="doubleclick"], ins.adsbygoogle, [id*="google_ads"], div[data-ad-slot]';

    const scannedLinks = [];
    for (const link of selectedLinks) {
      const url = getLinkUrl(link);
      if (!url) continue;

      const result = await scanHoverUrl(url);
      const redirect = isRedirectCandidate(url);
      scannedLinks.push({
        url,
        text: getLinkText(link),
        domain: getDisplayDomain(url),
        verdict: result?.verdict || 'SAFE',
        score: Number(result?.score || 0),
        heuristics: Array.isArray(result?.heuristics) ? result.heuristics : [],
        isAd: isAdMatch(`${url} ${link.getAttribute('class') || ''} ${link.getAttribute('rel') || ''}`),
        isRedirect: redirect.hit,
        redirectReason: redirect.reason,
        finalUrl: ''
      });
    }

    return {
      url: window.location.href,
      title: document.title || '',
      links: scannedLinks,
      adCounts: {
        scripts: Array.from(document.querySelectorAll('script')).filter((script) => isAdMatch(`${script.src || ''} ${script.textContent || ''}`)).length,
        trackingPixels: Array.from(document.querySelectorAll('img, iframe, source, video')).filter((node) => isAdMatch(`${node.src || ''} ${node.alt || ''} ${node.title || ''}`)).length,
        redirectLinks: links.filter((link) => isRedirectCandidate(getLinkUrl(link)).hit).length,
        metaRefresh: document.querySelectorAll('meta[http-equiv="refresh" i]').length,
        adNodes: document.querySelectorAll(adSelectors).length
      },
      totalLinks: links.length,
      pageData: extractPageData()
    };
  }

  function showClickWarning(url, result) {
    const existing = document.getElementById('pg-click-warning');
    if (existing) existing.remove();

    const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();
    const flags = Array.isArray(result?.heuristics) ? result.heuristics.slice(0, 3) : [];

    const overlay = document.createElement('div');
    overlay.id = 'pg-click-warning';
    overlay.innerHTML = `
      <div class="pg-click-warning-box">
        <div class="pg-cw-header">
          <span class="pg-cw-icon">🚨</span>
          <span class="pg-cw-title">PhishGuard Blocked This Link</span>
          <button class="pg-cw-close" id="pg-cw-close">✕</button>
        </div>
        <div class="pg-cw-domain">${escHtml(domain)}</div>
        <div class="pg-cw-reasons">
          <div class="pg-cw-reasons-title">Why we flagged it:</div>
          ${flags.map((flag) => `<div class="pg-cw-flag">• ${escHtml(flag)}</div>`).join('')}
        </div>
        <div class="pg-cw-actions">
          <button class="pg-cw-btn-safe" id="pg-cw-dismiss">Go Back (Safe)</button>
          <button class="pg-cw-btn-risk" id="pg-cw-proceed">Proceed Anyway (Risk)</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    document.getElementById('pg-cw-close').onclick = () => overlay.remove();
    document.getElementById('pg-cw-dismiss').onclick = () => overlay.remove();
    document.getElementById('pg-cw-proceed').onclick = () => {
      overlay.remove();
      window.open(url, '_blank', 'noopener,noreferrer');
    };
  }

  function showDangerPageOverlay(result) {
    if (!result || document.getElementById('pg-page-overlay')) return;

    const domain = (() => { try { return new URL(result.url).hostname; } catch { return result.url; } })();
    const flags = Array.isArray(result.heuristics) ? result.heuristics.slice(0, 5) : [];

    const overlay = document.createElement('div');
    overlay.id = 'pg-page-overlay';
    overlay.innerHTML = `
      <div class="pg-overlay-box">
        <div class="pg-ov-logo">🛡️ PhishGuard</div>
        <div class="pg-ov-verdict-badge">⚠ DANGEROUS PAGE DETECTED</div>
        <h2 class="pg-ov-headline">This page may be a phishing or scam site</h2>
        <div class="pg-ov-domain">${escHtml(domain)}</div>
        <div class="pg-ov-reasons">
          <div class="pg-ov-reasons-title">Warning indicators found:</div>
          ${flags.map((flag) => `<div class="pg-ov-flag">🔴 ${escHtml(flag)}</div>`).join('')}
        </div>
        <p class="pg-ov-advice">Do NOT enter your OTP, PIN, password, UPI credentials, Aadhaar, or PAN on this page.</p>
        <div class="pg-ov-actions">
          <button class="pg-ov-btn-back" id="pg-ov-back">← Go Back to Safety</button>
          <button class="pg-ov-btn-ignore" id="pg-ov-ignore">Dismiss Warning</button>
        </div>
        <div class="pg-ov-report" id="pg-ov-report">Report as false positive</div>
      </div>
    `;

    document.body.prepend(overlay);
    document.body.style.overflow = 'hidden';

    document.getElementById('pg-ov-back').onclick = () => history.back();
    document.getElementById('pg-ov-ignore').onclick = () => {
      overlay.remove();
      document.body.style.overflow = '';
    };
    document.getElementById('pg-ov-report').onclick = () => {
      chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: result.url });
      document.getElementById('pg-ov-report').textContent = '✓ Reported — thank you!';
    };
  }

  function runPageScan() {
    const pageData = extractPageData();
    chrome.runtime.sendMessage({
      type: 'PAGE_SCAN_COMPLETE',
      url: window.location.href,
      pageData
    }, (response) => {
      if (response && response.result) {
        // Background keeps the authoritative verdict cache.
      }
    });
  }

  function initClickBlock() {
    document.addEventListener('click', (event) => {
      const anchor = event.target.closest('a[href^="http"]');
      if (!anchor) return;

      const url = getLinkUrl(anchor);
      if (!url) return;

      event.preventDefault();
      scanHoverUrl(url).then((result) => {
        if (result && result.verdict === 'DANGEROUS') {
          showClickWarning(url, result);
          chrome.runtime.sendMessage({ type: 'BLOCKED_CLICK' });
          return;
        }

        window.location.href = url;
      });
    }, true);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'REQUEST_PAGE_DATA') {
      sendResponse(extractPageData());
      runPageScan();
      return true;
    }

    if (message.type === 'GET_PAGE_INSIGHTS' || message.type === 'REQUEST_PAGE_INSIGHTS') {
      Promise.resolve(extractPageInsights()).then((result) => {
        sendResponse(result);
      });
      return true;
    }

    if (message.type === 'SHOW_WARNING') {
      showDangerPageOverlay(message.result);
      return;
    }

    if (message.type === 'SCAN_ALL_LINKS') {
      Promise.resolve(extractPageInsights()).then((result) => sendResponse(result));
      return true;
    }
  });

  function initSerp() {
    if (!isGoogleSERP()) return;

    setTimeout(() => {
      runSerpScan().catch(() => {});
    }, 800);

    const target = document.getElementById('search') || document.body;
    const observer = new MutationObserver(() => {
      clearTimeout(observer._t);
      observer._t = setTimeout(() => {
        runSerpScan().catch(() => {});
      }, 400);
    });

    observer.observe(target, { childList: true, subtree: true });
  }

  function init() {
    initHoverTooltips();
    initClickBlock();
    initSerp();
    runPageScan();
  }

  init();
})();
