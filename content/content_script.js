// GuardianAI - content_script.js
// Modified: Replaced the old hover tooltip with a shadow-DOM popup, added ad/redirect badges, and added page-insight message handling.
// New additions: Hover popup system, redirect preview support, ad detection badges, cached hover scans, and page summary responses.
// Unchanged: Existing full-page danger overlay flow, page scan message contract, and click-block warning behavior.

(function () {
  'use strict';

  const HOVER_DELAY_MS = 600;
  const CACHE_LIMIT = 200;
  const CACHE_TTL = 10 * 60 * 1000;
  const GOOGLE_SERP_RE = /^https:\/\/(www\.)?google\.(com|co\.in)\/search/;

  const TRUSTED_DOMAINS = new Set([
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'wikipedia.org',
    'amazon.com', 'amazon.in', 'flipkart.com', 'paytm.com',
    'phonepe.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
    'microsoft.com', 'apple.com'
  ]);

  const AD_PATTERNS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'amazon-adsystem.com', 'facebook.com/tr', 'analytics.google.com',
    'hotjar.com', 'clarity.ms', '/ads/', '/advertisement/', '/sponsored/',
    '/tracking/', '/pixel/', 'gtag(', 'fbq(', '_gaq.', 'datalayer'
  ];

  const REDIRECT_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'tiny.cc', 'is.gd', 'rb.gy', 'cutt.ly', 'short.io'
  ];

  const REDIRECT_PARAM_PATTERNS = ['?url=', '?redirect=', '?goto=', '?link='];

  const hoverCache = new Map();
  const redirectCache = new Map();

  let currentPageResult = null;
  let warningOverlayShown = false;

  let hoverPopupHost = null;
  let hoverPopupRoot = null;
  let hoverPopupRefs = null;
  let hoverStylesPromise = null;
  let serpScanTimer = null;
  let serpObserver = null;
  let serpObserverTarget = null;

  const hoverState = {
    timer: null,
    activeLink: null,
    requestId: 0,
    lastUrl: '',
    visible: false,
    lastPlacement: null,
    mutateTimer: null
  };

  const serpState = {
    requestId: 0,
    inFlight: 0,
    queue: [],
    observing: false,
    isScanning: false
  };

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function rememberCache(cache, key, value) {
    if (!key) return;
    if (cache.has(key)) cache.delete(key);
    cache.set(key, { value, timestamp: Date.now() });
    while (cache.size > CACHE_LIMIT) {
      const oldestKey = cache.keys().next().value;
      if (oldestKey === undefined) break;
      cache.delete(oldestKey);
    }
  }

  function readCache(cache, key) {
    const entry = cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > CACHE_TTL) {
      cache.delete(key);
      return null;
    }
    cache.delete(key);
    cache.set(key, entry);
    return entry.value;
  }

  function ensureUrl(urlString) {
    try {
      return new URL(urlString, location.href);
    } catch {
      return null;
    }
  }

  function getBaseDomain(hostname) {
    const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function getDisplayDomain(urlString) {
    const parsed = ensureUrl(urlString);
    if (!parsed) return String(urlString || '').slice(0, 64);
    return parsed.hostname || parsed.href;
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

  function quickURLScan(urlString) {
    const parsed = ensureUrl(urlString);
    if (!parsed) {
      return {
        verdict: 'DANGEROUS',
        score: 90,
        flags: ['Invalid or malformed URL'],
        url: urlString,
        offlineMode: true
      };
    }

    const hostname = parsed.hostname.toLowerCase();
    const baseDomain = getBaseDomain(hostname);

    if (TRUSTED_DOMAINS.has(baseDomain)) {
      return {
        verdict: 'SAFE',
        score: 0,
        flags: ['Verified trusted domain'],
        url: parsed.href,
        trusted: true,
        offlineMode: true
      };
    }

    let score = 0;
    const flags = [];
    const fullURL = parsed.href.toLowerCase();

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40;
      flags.push('Uses raw IP address instead of domain name');
    }

    if (hostname.includes('xn--')) {
      score += 35;
      flags.push('Punycode/homograph domain detected');
    }

    if (parsed.protocol === 'http:') {
      score += 20;
      flags.push('Not using HTTPS');
    }

    const suspiciousTokens = [
      'login', 'signin', 'verify', 'secure', 'update', 'confirm',
      'account', 'banking', 'payment', 'wallet', 'kyc', 'otp',
      'support', 'helpdesk', 'refund', 'claim', 'reward', 'free',
      'winner', 'lucky', 'prize', 'offer'
    ];
    const foundTokens = suspiciousTokens.filter((token) => hostname.includes(token));
    if (foundTokens.length > 0) {
      score += Math.min(foundTokens.length * 10, 30);
      flags.push(`Suspicious keywords: ${foundTokens.join(', ')}`);
    }

    const tld = '.' + (hostname.split('.').pop() || '');
    const badTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click'];
    if (badTLDs.includes(tld)) {
      score += 25;
      flags.push(`Suspicious TLD: ${tld}`);
    }

    if (fullURL.includes('@')) {
      score += 35;
      flags.push('@ symbol in URL could hide the real destination');
    }

    if (fullURL.length > 200) {
      score += 15;
      flags.push('Abnormally long URL');
    }

    if (['redirect', 'url=', 'next=', 'return=', 'goto='].some((part) => fullURL.includes(part))) {
      score += 20;
      flags.push('URL contains redirect parameters');
    }

    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      score += 20;
      flags.push(`Unusually deep subdomain structure (${subdomainCount} levels)`);
    }

    const verdict = score >= 60 ? 'DANGEROUS' : score >= 30 ? 'SUSPICIOUS' : 'SAFE';

    return {
      verdict,
      score: Math.min(score, 100),
      flags,
      url: parsed.href,
      offlineMode: true
    };
  }

  function isAdMatch(value) {
    const text = String(value || '').toLowerCase();
    return AD_PATTERNS.some((pattern) => text.includes(pattern));
  }

  function isRedirectCandidate(urlString) {
    const parsed = ensureUrl(urlString);
    if (!parsed) return { hit: false, reason: '' };

    const hostname = parsed.hostname.toLowerCase();
    const href = parsed.href.toLowerCase();

    if (REDIRECT_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`) || hostname.includes(domain))) {
      return { hit: true, reason: 'Shortened redirect domain detected' };
    }

    if (REDIRECT_PARAM_PATTERNS.some((pattern) => href.includes(pattern))) {
      return { hit: true, reason: 'Redirect parameter detected' };
    }

    if (href.includes('/redirect/')) {
      return { hit: true, reason: 'Redirect path detected' };
    }

    return { hit: false, reason: '' };
  }

  function getLinkText(link) {
    const text = (link.textContent || link.getAttribute('aria-label') || link.title || link.href || '').trim();
    return text.replace(/\s+/g, ' ').slice(0, 120);
  }

  function getBackgroundMessage(message) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response || null);
      });
    });
  }

  async function scanHoverUrl(urlString) {
    const cached = readCache(hoverCache, urlString);
    if (cached) return cached;

    const response = await getBackgroundMessage({ type: 'HOVER_LINK', url: urlString });
    const result = response && response.result ? response.result : quickURLScan(urlString);
    rememberCache(hoverCache, urlString, result);
    return result;
  }

  async function resolveRedirect(urlString) {
    const cached = readCache(redirectCache, urlString);
    if (cached) return cached;

    const response = await getBackgroundMessage({ type: 'RESOLVE_REDIRECT', url: urlString });
    const result = response && response.result ? response.result : {
      original: urlString,
      final_url: 'Could not resolve',
      verdict: 'SUSPICIOUS'
    };
    rememberCache(redirectCache, urlString, result);
    return result;
  }

  function extractPageData() {
    const links = Array.from(document.querySelectorAll('a[href]'));
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

    const adCount = document.querySelectorAll(
      'iframe[src*="doubleclick"], ins.adsbygoogle, [id*="google_ads"], div[data-ad-slot]'
    ).length;

    const bodyText = document.body
      ? (document.body.innerText || document.body.textContent || '').slice(0, 5000)
      : '';

    const formFields = [];
    document.querySelectorAll('input').forEach((input) => {
      const name = (input.name || input.id || input.placeholder || '').toLowerCase();
      if (name) formFields.push(name);
    });

    return {
      title: document.title || '',
      bodyText,
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

  function runPageScan() {
    const pageData = extractPageData();
    chrome.runtime.sendMessage({
      type: 'PAGE_SCAN_COMPLETE',
      url: window.location.href,
      pageData
    }, (response) => {
      if (response && response.result) {
        currentPageResult = response.result;
      }
    });
  }

  function buildPageSignals() {
    const links = Array.from(document.querySelectorAll('a[href]'));
    const scripts = Array.from(document.querySelectorAll('script'));
    const iframes = Array.from(document.querySelectorAll('iframe'));
    const metaRefresh = Array.from(document.querySelectorAll('meta[http-equiv="refresh" i]'));
    const adSelectors = 'iframe[src*="doubleclick"], ins.adsbygoogle, [id*="google_ads"], div[data-ad-slot]';

    let adScripts = 0;
    let trackingPixels = 0;
    let redirectLinks = 0;

    scripts.forEach((script) => {
      const payload = `${script.src || ''} ${script.textContent || ''}`;
      if (isAdMatch(payload)) adScripts++;
    });

    iframes.forEach((iframe) => {
      const payload = `${iframe.src || ''} ${iframe.title || ''}`;
      if (isAdMatch(payload)) adScripts++;
    });

    document.querySelectorAll('img, iframe, source, video').forEach((node) => {
      const payload = `${node.src || ''} ${node.alt || ''} ${node.title || ''}`;
      if (isAdMatch(payload)) trackingPixels++;
    });

    links.forEach((link) => {
      const url = getLinkUrl(link);
      if (!url) return;
      if (isRedirectCandidate(url).hit) redirectLinks++;
    });

    return {
      totalLinks: links.length,
      linkCount: links.length,
      adCount: document.querySelectorAll(adSelectors).length,
      externalLinkCount: links.filter((link) => {
        const url = getLinkUrl(link);
        if (!url) return false;
        try {
          const parsed = new URL(url);
          return parsed.hostname && parsed.hostname !== location.hostname;
        } catch {
          return false;
        }
      }).length,
      adScripts,
      trackingPixels,
      redirectLinks,
      metaRefresh: metaRefresh.length,
      offlineMode: true
    };
  }

  function getLinkVerdictMeta(urlString) {
    const quick = quickURLScan(urlString);
    const redirect = isRedirectCandidate(urlString);
    const adLink = isAdMatch(urlString);
    return {
      verdict: quick.verdict,
      score: quick.score,
      flags: quick.flags,
      isRedirect: redirect.hit,
      redirectReason: redirect.reason,
      isAd: adLink,
      url: urlString
    };
  }

  async function getResolvedLinkMeta(urlString) {
    const quickMeta = getLinkVerdictMeta(urlString);
    if (!quickMeta.isRedirect) return quickMeta;

    const redirect = await resolveRedirect(urlString);
    const finalUrl = redirect.final_url && redirect.final_url !== 'Could not resolve' ? redirect.final_url : '';
    const finalScan = finalUrl ? quickURLScan(finalUrl) : null;

    if (finalScan) {
      return {
        ...quickMeta,
        finalUrl,
        finalVerdict: finalScan.verdict,
        finalScore: finalScan.score,
        finalFlags: finalScan.flags,
        verdict: finalScan.verdict === 'DANGEROUS' ? 'DANGEROUS' : quickMeta.verdict,
        dangerousRedirect: finalScan.verdict === 'DANGEROUS'
      };
    }

    return {
      ...quickMeta,
      finalUrl: '',
      finalVerdict: redirect.verdict,
      dangerousRedirect: redirect.verdict === 'DANGEROUS'
    };
  }

  function getVerdictTier(verdict) {
    if (verdict === 'DANGEROUS') return 'danger';
    if (verdict === 'SUSPICIOUS') return 'warn';
    return 'safe';
  }

  function getVerdictBadgeText(verdict) {
    if (verdict === 'DANGEROUS') return '✕ DANGER';
    if (verdict === 'SUSPICIOUS') return '⚠ SUSP';
    return 'SAFE';
  }

  function getVerdictIconSvg(tier) {
    if (tier === 'danger') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 2 3 6.5V12c0 5.1 3.5 9.8 9 10 5.5-.2 9-4.9 9-10V6.5L12 2Zm0 5.5c.6 0 1 .4 1 1v4.2c0 .6-.4 1-1 1s-1-.4-1-1V8.5c0-.6.4-1 1-1Zm0 9c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Z"/></svg>';
    }

    if (tier === 'warn') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M1.8 20.5h20.4L12 2.5 1.8 20.5Zm10.2-3.1c-.8 0-1.4-.6-1.4-1.4s.6-1.4 1.4-1.4 1.4.6 1.4 1.4-.6 1.4-1.4 1.4Zm1-3.7h-2l-.2-5.5h2.4l-.2 5.5Z"/></svg>';
    }

    return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 2 4 5v6c0 5 3.2 9.4 8 11 4.8-1.6 8-6 8-11V5l-8-3Zm-1 12.4-2.6-2.6 1.4-1.4L11 11.6l4.2-4.2 1.4 1.4-5.6 5.6Z"/></svg>';
  }

  function normalizeFlagText(flag) {
    if (!flag) return '';
    if (typeof flag === 'string') return flag;
    if (typeof flag === 'object' && flag.text) return String(flag.text);
    return String(flag);
  }

  function getTooltipChips(flags) {
    const unique = [];
    const seen = new Set();

    flags.forEach((flag) => {
      const text = normalizeFlagText(flag).trim();
      if (!text || seen.has(text)) return;
      seen.add(text);
      unique.push(text);
    });

    return unique.slice(0, 3);
  }

  function buildBadgeMarkup(result) {
    const verdict = result.verdict || 'SAFE';
    const tier = getVerdictTier(verdict);
    const score = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));

    return `
      <span class="pg-badge pg-${tier}" aria-hidden="true">
        ${getVerdictIconSvg(tier)}
        <span>${escHtml(getVerdictBadgeText(verdict))}</span>
        <span>·</span>
        <span>${score}</span>
      </span>
    `;
  }

  function buildTooltipMarkup(result, domain) {
    const verdict = result.verdict || 'SAFE';
    const tier = getVerdictTier(verdict);
    const score = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const chips = getTooltipChips(result.flags || []);

    return `
      <span class="pg-badge-tooltip-line1">
        <span class="pg-badge pg-${tier}">${getVerdictIconSvg(tier)}<span>${escHtml(getVerdictBadgeText(verdict))}</span></span>
        <span class="pg-badge-tooltip-score">Score ${score}/100</span>
      </span>
      <div class="pg-badge-tooltip-domain">${escHtml(domain || '')}</div>
      <div class="pg-badge-tooltip-chips">
        ${chips.length
          ? chips.map((chip) => `<span class="pg-badge-chip">${escHtml(chip)}</span>`).join('')
          : '<span class="pg-badge-chip pg-badge-chip-muted">No major threats found</span>'}
      </div>
    `;
  }

  function ensureBadgeWrap(link) {
    if (!link || !link.parentNode) return null;

    const urlString = getLinkUrl(link);
    if (!urlString) return null;

    const existing = link.nextElementSibling;
    if (existing && existing.classList && existing.classList.contains('pg-link-badge-wrap')) {
      return existing;
    }

    const wrap = document.createElement('span');
    wrap.className = 'pg-link-badge-wrap';
    wrap.setAttribute('aria-hidden', 'true');

    const result = quickURLScan(urlString);
    const tier = getVerdictTier(result.verdict || 'SAFE');

    const badge = document.createElement('span');
    badge.className = 'pg-badge';
    badge.classList.add(`pg-${tier}`);
    badge.innerHTML = `${getVerdictIconSvg(tier)}<span>${escHtml(getVerdictBadgeText(result.verdict || 'SAFE'))}</span><span>·</span><span>${Math.max(0, Math.min(100, Number(result.score || 0)))}</span>`;

    const tooltip = document.createElement('span');
    tooltip.className = 'pg-badge-tooltip';
    tooltip.setAttribute('role', 'tooltip');
    tooltip.setAttribute('aria-hidden', 'true');
    tooltip.innerHTML = buildTooltipMarkup(result, getDisplayDomain(link.href || getLinkUrl(link)));

    wrap.appendChild(badge);
    wrap.appendChild(tooltip);
    link.insertAdjacentElement('afterend', wrap);

    const showTooltip = () => {
      wrap.classList.add('pg-tooltip-open');
    };

    const hideTooltip = () => {
      wrap.classList.remove('pg-tooltip-open');
    };

    badge.addEventListener('pointerenter', () => {
      showTooltip();
      showLinkBadgeTooltip(link, wrap).catch(() => {});
    });
    badge.addEventListener('focus', () => {
      showTooltip();
      showLinkBadgeTooltip(link, wrap).catch(() => {});
    });
    wrap.addEventListener('pointerleave', hideTooltip);
    wrap.addEventListener('focusout', hideTooltip);

    wrap.dataset.gaBadgeFor = urlString;
    wrap.dataset.gaBadgeInitialized = 'true';
    return wrap;
  }

  async function showLinkBadgeTooltip(link, wrap) {
    if (!link || !wrap) return;
    const urlString = getLinkUrl(link);
    if (!urlString) return;

    const result = await scanHoverUrl(urlString);
    if (!result || !wrap.isConnected || wrap.dataset.gaBadgeFor !== urlString) return;

    const score = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const tier = getVerdictTier(result.verdict || 'SAFE');
    const badge = wrap.querySelector('.pg-badge');
    const tooltip = wrap.querySelector('.pg-badge-tooltip');

    if (badge) {
      badge.className = `pg-badge pg-${tier}`;
      badge.innerHTML = `${getVerdictIconSvg(tier)}<span>${escHtml(getVerdictBadgeText(result.verdict || 'SAFE'))}</span><span>·</span><span>${score}</span>`;
    }

    if (tooltip) {
      tooltip.innerHTML = buildTooltipMarkup(result, getDisplayDomain(urlString));
    }
  }

  function extractGoogleSerpUrl(container) {
    if (!container) return '';

    const dataUrl = container.getAttribute('data-url') || container.dataset.url || '';
    if (dataUrl) {
      const parsedDataUrl = ensureUrl(dataUrl);
      if (parsedDataUrl) return parsedDataUrl.href;
    }

    const cite = container.querySelector('cite');
    const citeText = cite ? cite.textContent.trim() : '';
    const citeUrl = ensureUrl(citeText);
    if (citeUrl) return citeUrl.href;

    const anchor = Array.from(container.querySelectorAll('a[href]')).find((el) => getLinkUrl(el));
    if (anchor) return getLinkUrl(anchor);

    return '';
  }

  function getGoogleSerpStatusMarkup(result) {
    const verdict = result.verdict || 'SAFE';
    const tier = getVerdictTier(verdict);
    const score = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const chips = getTooltipChips(result.flags || []).slice(0, 2);
    const label = verdict === 'DANGEROUS' ? 'Dangerous' : verdict === 'SUSPICIOUS' ? 'Suspicious' : 'SAFE';

    return `
      ${getVerdictIconSvg(tier)} ${label} · Score ${score}${chips.length ? ` · ${chips.map((chip) => escHtml(chip)).join(' · ')}` : ''}
    `;
  }

  function applyGoogleSerpVerdict(container, urlString, result) {
    if (!container || !urlString || !result) return;

    const existingStatus = container.querySelector(':scope > .pg-serp-status');
    if (existingStatus) existingStatus.remove();

    container.classList.add('pg-serp-result');
    container.classList.remove('pg-serp-safe', 'pg-serp-warn', 'pg-serp-danger');
    container.classList.add(`pg-serp-${getVerdictTier(result.verdict || 'SAFE')}`);

    const status = document.createElement('div');
    status.innerHTML = getGoogleSerpStatusMarkup(result);
    status.className = `pg-serp-status pg-serp-status-${getVerdictTier(result.verdict || 'SAFE')}`;
    status.dataset.pgSerpFor = urlString;

    const cite = container.querySelector('cite');
    if (cite && cite.parentElement) {
      cite.insertAdjacentElement('afterend', status);
    } else {
      container.appendChild(status);
    }
  }

  async function scanGoogleSerpContainer(container, serpCounts) {
    if (!container) return;

    const urlString = extractGoogleSerpUrl(container);
    if (!urlString) return;

    const result = await scanHoverUrl(urlString);
    if (!result || !container.isConnected) return;

    applyGoogleSerpVerdict(container, urlString, result);

    if (result.verdict === 'DANGEROUS') serpCounts.dangerCount++;
    else if (result.verdict === 'SUSPICIOUS') serpCounts.suspiciousCount++;
  }

  async function scanGoogleSerpPage() {
    if (!GOOGLE_SERP_RE.test(location.href)) return;

    const requestId = ++serpState.requestId;
    const serpCounts = { dangerCount: 0, suspiciousCount: 0 };
    const containers = Array.from(document.querySelectorAll('div.g, div[data-sokoban-grid]'));
    const items = containers.filter((container) => extractGoogleSerpUrl(container));

    let index = 0;
    let active = 0;
    serpState.isScanning = true;

    const runNext = (resolve) => {
      if (requestId !== serpState.requestId) {
        serpState.isScanning = false;
        resolve();
        return;
      }

      while (active < 10 && index < items.length) {
        const container = items[index++];
        active++;

        Promise.resolve(scanGoogleSerpContainer(container, serpCounts))
          .catch(() => {})
          .finally(() => {
            active--;
            window.setTimeout(() => runNext(resolve), 50);
          });
      }

      if (index >= items.length && active === 0) {
        try {
          chrome.runtime.sendMessage({
            type: 'PAGE_SERP_STATS',
            dangerCount: serpCounts.dangerCount,
            suspiciousCount: serpCounts.suspiciousCount
          });
        } catch {
          // Ignore messaging failures in page-scoped observers.
        }
        serpState.isScanning = false;
        resolve();
      }
    };

    await new Promise((resolve) => runNext(resolve));
  }

  function scheduleGoogleSerpScan() {
    clearTimeout(serpScanTimer);
    serpScanTimer = setTimeout(() => {
      scanGoogleSerpPage().catch(() => {});
    }, 50);
  }

  function observeGoogleSerp() {
    if (!GOOGLE_SERP_RE.test(location.href)) return;

    const target = document.querySelector('#search') || document.querySelector('#rso') || document.body;
    if (!target) return;

    if (serpObserver && serpObserverTarget === target) return;

    if (serpObserver) {
      serpObserver.disconnect();
    }

    serpObserverTarget = target;
    serpObserver = new MutationObserver(() => {
      if (serpState.isScanning) return;
      scheduleGoogleSerpScan();
    });
    serpObserver.observe(target, { childList: true, subtree: true });
    scheduleGoogleSerpScan();
  }

  function createTooltipHost() {
    if (hoverPopupHost) return hoverPopupHost;

    const host = document.createElement('div');
    host.id = 'ga-hover-popup-host';
    host.setAttribute('aria-hidden', 'true');
    host.style.position = 'fixed';
    host.style.left = '0';
    host.style.top = '0';
    host.style.width = '0';
    host.style.height = '0';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'none';

    const root = host.attachShadow({ mode: 'open' });
    const shell = document.createElement('div');
    shell.className = 'ga-hover-popup';
    shell.innerHTML = `
      <div class="ga-hover-card" data-state="loading">
        <div class="ga-hover-header">
          <div class="ga-hover-header-left">
            <div class="ga-hover-icon" data-role="icon">🔄</div>
            <div class="ga-hover-header-text">
              <div class="ga-hover-title" data-role="title">Scanning...</div>
              <div class="ga-hover-subtitle" data-role="subtitle">Analyzing link</div>
            </div>
          </div>
          <button type="button" class="ga-hover-close" data-role="close" aria-label="Close">[X]</button>
        </div>
        <div class="ga-hover-body">
          <div class="ga-hover-loading" data-role="loading">
            <div class="ga-skeleton ga-skeleton-line"></div>
            <div class="ga-skeleton ga-skeleton-line ga-skeleton-short"></div>
            <div class="ga-skeleton ga-skeleton-progress"></div>
          </div>
          <div class="ga-hover-content" data-role="content" hidden>
            <div class="ga-hover-domain-label">Domain</div>
            <div class="ga-hover-domain" data-role="domain"></div>
            <div class="ga-hover-redirect" data-role="redirect" hidden></div>
            <div class="ga-hover-score-row">
              <span class="ga-hover-score-text">Risk score</span>
              <span class="ga-hover-score-value" data-role="score">0/100</span>
            </div>
            <div class="ga-hover-progress" aria-hidden="true">
              <div class="ga-hover-progress-fill" data-role="progress"></div>
            </div>
            <div class="ga-hover-reasons" data-role="reasons"></div>
          </div>
          <div class="ga-hover-actions" data-role="actions"></div>
          <div class="ga-hover-footer">
            <span>Powered by GuardianAI 🛡️</span>
            <span class="ga-hover-offline" data-role="offline" hidden>Offline mode</span>
          </div>
        </div>
      </div>
    `;

    root.appendChild(shell);
    document.documentElement.appendChild(host);

    hoverPopupHost = host;
    hoverPopupRoot = root;
    hoverPopupRefs = {
      shell,
      card: shell.querySelector('.ga-hover-card'),
      icon: shell.querySelector('[data-role="icon"]'),
      title: shell.querySelector('[data-role="title"]'),
      subtitle: shell.querySelector('[data-role="subtitle"]'),
      close: shell.querySelector('[data-role="close"]'),
      loading: shell.querySelector('[data-role="loading"]'),
      content: shell.querySelector('[data-role="content"]'),
      domain: shell.querySelector('[data-role="domain"]'),
      redirect: shell.querySelector('[data-role="redirect"]'),
      score: shell.querySelector('[data-role="score"]'),
      progress: shell.querySelector('[data-role="progress"]'),
      reasons: shell.querySelector('[data-role="reasons"]'),
      actions: shell.querySelector('[data-role="actions"]'),
      offline: shell.querySelector('[data-role="offline"]')
    };

    hoverPopupRefs.close.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      hideHoverPopup();
    });

    return hoverPopupHost;
  }

  async function ensureHoverStyles() {
    if (hoverStylesPromise) return hoverStylesPromise;

    hoverStylesPromise = fetch(chrome.runtime.getURL('content/hover-popup.css'))
      .then((response) => response.text())
      .catch(() => '');

    return hoverStylesPromise;
  }

  async function ensureTooltipReady() {
    const host = createTooltipHost();
    const styles = await ensureHoverStyles();
    if (hoverPopupRoot && !hoverPopupRoot.querySelector('style[data-ga-hover-style]')) {
      const style = document.createElement('style');
      style.dataset.gaHoverStyle = 'true';
      style.textContent = styles;
      hoverPopupRoot.prepend(style);
    }
    return host;
  }

  function setHoverTheme(verdict) {
    if (!hoverPopupRefs) return;
    hoverPopupRefs.card.dataset.verdict = verdict;

    const iconMap = {
      SAFE: '✅',
      SUSPICIOUS: '⚠️',
      DANGEROUS: '🔴',
      LOADING: '🔄'
    };

    const titleMap = {
      SAFE: 'SAFE',
      SUSPICIOUS: 'SUSPICIOUS',
      DANGEROUS: 'DANGEROUS',
      LOADING: 'Scanning...'
    };

    const subtitleMap = {
      SAFE: 'Verified Domain',
      SUSPICIOUS: 'Proceed with Caution',
      DANGEROUS: 'Do NOT click this link',
      LOADING: 'Analyzing link'
    };

    hoverPopupRefs.icon.textContent = iconMap[verdict] || '🔄';
    hoverPopupRefs.title.textContent = titleMap[verdict] || 'Scanning...';
    hoverPopupRefs.subtitle.textContent = subtitleMap[verdict] || 'Analyzing link';
  }

  function positionHoverPopup(link) {
    if (!hoverPopupHost || !hoverPopupRefs || !link) return;

    const rect = link.getBoundingClientRect();
    const popupRect = hoverPopupRefs.card.getBoundingClientRect();
    const width = popupRect.width || 280;
    const height = popupRect.height || 180;
    const gap = 12;

    let top = rect.bottom + gap;
    let topPlacement = false;
    if (rect.bottom + gap + height > window.innerHeight && rect.top - gap - height > 0) {
      top = rect.top - gap - height;
      topPlacement = true;
    }

    let left = rect.left + (rect.width / 2) - (width / 2);
    left = clamp(left, 10, window.innerWidth - width - 10);
    top = clamp(top, 10, window.innerHeight - height - 10);

    hoverPopupHost.style.left = `${left}px`;
    hoverPopupHost.style.top = `${top}px`;
    hoverPopupHost.style.width = `${width}px`;
    hoverPopupHost.style.height = `${height}px`;
    hoverPopupHost.dataset.placement = topPlacement ? 'top' : 'bottom';
  }

  function populateReasons(reasons) {
    if (!hoverPopupRefs) return;
    hoverPopupRefs.reasons.innerHTML = '';

    reasons.slice(0, 5).forEach((reason) => {
      const row = document.createElement('div');
      row.className = 'ga-hover-reason';
      row.textContent = reason;
      hoverPopupRefs.reasons.appendChild(row);
    });
  }

  function populateActions(verdict, urlString, result) {
    if (!hoverPopupRefs) return;
    hoverPopupRefs.actions.innerHTML = '';

    const addButton = (label, className, handler) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `ga-hover-action ${className}`;
      button.textContent = label;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        handler();
      });
      hoverPopupRefs.actions.appendChild(button);
    };

    if (verdict === 'SUSPICIOUS') {
      addButton('Scan Full Page', 'ga-hover-action-primary', () => runPageScan());
    }

    if (verdict === 'DANGEROUS') {
      addButton('Block Page', 'ga-hover-action-danger', () => {
        chrome.runtime.sendMessage({ type: 'BLOCKED_CLICK' });
        showDangerPageOverlay(result || { url: urlString, flags: [] });
      });
      addButton('Report', 'ga-hover-action-secondary', () => {
        chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: urlString });
      });
    }

    if (verdict === 'SAFE') {
      addButton('Scan Full Page', 'ga-hover-action-secondary', () => runPageScan());
    }
  }

  function renderHoverPopup(state) {
    if (!hoverPopupRefs) return;

    const verdict = state.verdict || 'SAFE';
    const score = Math.max(0, Math.min(100, Number(state.score || 0)));
    const domain = state.domain || state.url || '';
    const reasons = Array.isArray(state.reasons) ? state.reasons : [];

    setHoverTheme(verdict);
    hoverPopupRefs.loading.hidden = true;
    hoverPopupRefs.content.hidden = false;
    hoverPopupRefs.domain.textContent = domain;
    hoverPopupRefs.score.textContent = `${score}/100`;
    hoverPopupRefs.redirect.hidden = !state.redirectTarget;
    hoverPopupRefs.redirect.textContent = state.redirectTarget
      ? `Redirects to: ${state.redirectTarget}${state.dangerousRedirect ? '  🔴 Dangerous destination detected' : ''}`
      : '';
    hoverPopupRefs.offline.hidden = !state.offlineMode;

    populateReasons(reasons.length > 0 ? reasons : ['No major threats found']);
    populateActions(verdict, state.url, state.result || null);

    const fill = hoverPopupRefs.progress;
    fill.style.transform = 'scaleX(0)';
    requestAnimationFrame(() => {
      fill.style.transform = `scaleX(${score / 100})`;
    });

    hoverPopupHost.setAttribute('data-visible', 'true');
    hoverPopupHost.setAttribute('aria-hidden', 'false');
  }

  function renderHoverLoading(urlString) {
    if (!hoverPopupRefs) return;

    setHoverTheme('LOADING');
    hoverPopupRefs.loading.hidden = false;
    hoverPopupRefs.content.hidden = true;
    hoverPopupRefs.offline.hidden = false;
    hoverPopupRefs.offline.textContent = 'Offline mode';
    hoverPopupRefs.redirect.hidden = true;
    hoverPopupHost.setAttribute('data-visible', 'true');
    hoverPopupHost.setAttribute('aria-hidden', 'false');
    hoverPopupRefs.domain.textContent = getDisplayDomain(urlString);
  }

  function hideHoverPopup() {
    hoverState.requestId++;
    hoverState.activeLink = null;
    hoverState.lastUrl = '';
    clearTimeout(hoverState.timer);
    clearTimeout(hoverState.mutateTimer);

    if (hoverPopupHost) {
      hoverPopupHost.setAttribute('data-visible', 'false');
      hoverPopupHost.setAttribute('aria-hidden', 'true');
    }
  }

  async function showHoverPopup(link, event) {
    const urlString = getLinkUrl(link);
    if (!urlString) return;

    const requestId = ++hoverState.requestId;
    hoverState.activeLink = link;
    hoverState.lastUrl = urlString;

    await ensureTooltipReady();
    if (requestId !== hoverState.requestId) return;

    renderHoverLoading(urlString);
    positionHoverPopup(link);

    const baseResult = await scanHoverUrl(urlString);
    if (requestId !== hoverState.requestId) return;

    const redirectCandidate = isRedirectCandidate(urlString);
    let redirectInfo = null;

    if (redirectCandidate.hit) {
      redirectInfo = await resolveRedirect(urlString);
      if (requestId !== hoverState.requestId) return;
    }

    let reasons = Array.isArray(baseResult.flags)
      ? baseResult.flags.map((flag) => typeof flag === 'object' ? flag.text : flag)
      : [];

    let verdict = baseResult.verdict || 'SAFE';
    let score = typeof baseResult.score === 'number' ? baseResult.score : Number(baseResult.urlScore || 0);
    let redirectTarget = '';
    let dangerousRedirect = false;

    if (redirectInfo && redirectInfo.final_url && redirectInfo.final_url !== 'Could not resolve') {
      redirectTarget = getDisplayDomain(redirectInfo.final_url);
      const finalScan = quickURLScan(redirectInfo.final_url);
      if (finalScan.verdict === 'DANGEROUS' || (finalScan.verdict === 'SUSPICIOUS' && verdict === 'SAFE')) {
        verdict = finalScan.verdict;
        score = finalScan.score;
        reasons = [...reasons, `Redirects to ${redirectTarget}`];
        if (finalScan.flags.length) reasons = [...reasons, ...finalScan.flags];
      }
      dangerousRedirect = finalScan.verdict === 'DANGEROUS';
    } else if (redirectCandidate.hit) {
      reasons = [...reasons, redirectCandidate.reason];
    }

    const domain = getDisplayDomain(urlString);
    renderHoverPopup({
      verdict,
      score,
      domain,
      url: urlString,
      reasons,
      redirectTarget,
      dangerousRedirect,
      offlineMode: true,
      result: baseResult
    });

    positionHoverPopup(link);
  }

  function scheduleHover(link, event) {
    clearTimeout(hoverState.timer);
    hoverState.activeLink = link;
    hoverState.timer = setTimeout(() => {
      showHoverPopup(link, event).catch(() => {});
    }, HOVER_DELAY_MS);
  }

  function createBadge(label, className, title) {
    const badge = document.createElement('span');
    badge.className = `ga-link-badge ${className}`;
    badge.textContent = label;
    if (title) badge.title = title;
    return badge;
  }

  async function previewRedirectFromBadge(link, urlString, badge) {
    const resolved = await resolveRedirect(urlString);
    const finalUrl = resolved.final_url && resolved.final_url !== 'Could not resolve' ? resolved.final_url : '';
    const finalScan = finalUrl ? quickURLScan(finalUrl) : null;

    if (badge && finalScan && finalScan.verdict === 'DANGEROUS') {
      badge.textContent = '🔴';
      badge.classList.add('ga-link-badge-danger');
      badge.title = 'Dangerous final destination detected';
    }

    if (finalUrl) {
      await ensureTooltipReady();
      renderHoverPopup({
        verdict: finalScan ? finalScan.verdict : 'SUSPICIOUS',
        score: finalScan ? finalScan.score : 50,
        domain: getDisplayDomain(urlString),
        url: urlString,
        reasons: [
          `${getDisplayDomain(urlString)} redirects to ${getDisplayDomain(finalUrl)}`,
          ...(finalScan ? finalScan.flags : ['Redirect target resolved'])
        ],
        redirectTarget: getDisplayDomain(finalUrl),
        dangerousRedirect: !!(finalScan && finalScan.verdict === 'DANGEROUS'),
        offlineMode: true,
        result: finalScan || quickURLScan(finalUrl)
      });
      positionHoverPopup(link);
    }
  }

  function decorateLink(link) {
    const urlString = getLinkUrl(link);
    if (!urlString) return;

    if (link.dataset.gaDecoratedUrl === urlString) return;
    link.dataset.gaDecoratedUrl = urlString;

    const existing = link.nextElementSibling;
    if (existing && existing.classList && existing.classList.contains('pg-link-badge-wrap')) {
      if (existing.dataset.gaBadgeFor === urlString) return;
      existing.remove();
    }

    ensureBadgeWrap(link);
  }

  function attachLinkHover(link) {
    if (!link || link.dataset.gaHoverAttached === 'true') return;
    const urlString = getLinkUrl(link);
    if (!urlString) return;

    link.dataset.gaHoverAttached = 'true';

    link.addEventListener('click', (event) => {
      const href = getLinkUrl(link);
      if (!href) return;

      const cached = readCache(redirectCache, href);
      if (cached && cached.final_url && cached.final_url !== 'Could not resolve') {
        const finalScan = quickURLScan(cached.final_url);
        if (finalScan.verdict === 'DANGEROUS') {
          event.preventDefault();
          chrome.runtime.sendMessage({ type: 'BLOCKED_CLICK' });
          showInlineWarning(link, {
            verdict: 'DANGEROUS',
            flags: finalScan.flags.map((flag) => ({ type: 'url', text: flag }))
          }, href);
        }
      }
    }, true);
  }

  function showInlineWarning(link, result, url) {
    const existing = document.getElementById('pg-click-warning');
    if (existing) existing.remove();

    const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();
    const flags = (result.flags || []).slice(0, 3).map((flag) => typeof flag === 'object' ? flag.text : flag);

    const overlay = document.createElement('div');
    overlay.id = 'pg-click-warning';
    overlay.innerHTML = `
      <div class="pg-click-warning-box">
        <div class="pg-cw-header">
          <span class="pg-cw-icon">🚨</span>
          <span class="pg-cw-title">GuardianAI Blocked This Link</span>
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

    document.getElementById('pg-cw-close').onclick =
    document.getElementById('pg-cw-dismiss').onclick = () => overlay.remove();

    document.getElementById('pg-cw-proceed').onclick = () => {
      overlay.remove();
      window.open(url, '_blank', 'noopener,noreferrer');
    };
  }

  function showDangerPageOverlay(result) {
    if (warningOverlayShown) return;
    warningOverlayShown = true;

    const domain = (() => { try { return new URL(result.url).hostname; } catch { return result.url; } })();
    const flags = (result.flags || []).slice(0, 5).map((flag) => typeof flag === 'object' ? flag.text : flag);

    const overlay = document.createElement('div');
    overlay.id = 'pg-page-overlay';
    overlay.innerHTML = `
      <div class="pg-overlay-box">
        <div class="pg-ov-logo">🛡️ GuardianAI</div>
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

  function scanAndDecorateLinks() {
    document.querySelectorAll('a[href]').forEach((link) => {
      attachLinkHover(link);
      decorateLink(link);
    });
  }

  function scanAdSignals() {
    return buildPageSignals();
  }

  function extractPageInsights() {
    const signals = scanAdSignals();
    const links = Array.from(document.querySelectorAll('a[href]')).map((link) => {
      const url = getLinkUrl(link);
      const meta = getLinkVerdictMeta(url);
      return {
        url,
        text: getLinkText(link),
        domain: getDisplayDomain(url),
        verdict: meta.verdict,
        score: meta.score,
        flags: meta.flags,
        isAd: meta.isAd,
        isRedirect: meta.isRedirect,
        redirectReason: meta.redirectReason,
        finalUrl: readCache(redirectCache, url)?.final_url || ''
      };
    });

    return {
      url: window.location.href,
      title: document.title || '',
      links,
      adCounts: {
        scripts: signals.adScripts,
        trackingPixels: signals.trackingPixels,
        redirectLinks: signals.redirectLinks,
        metaRefresh: signals.metaRefresh
      },
      totalLinks: signals.totalLinks,
      offlineMode: true,
      pageData: extractPageData()
    };
  }

  function scheduleDecorationScan() {
    clearTimeout(hoverState.mutateTimer);
    hoverState.mutateTimer = setTimeout(() => {
      scanAndDecorateLinks();
      observeGoogleSerp();
    }, 250);
  }

  function observeLinks() {
    if (!document.body) return;

    const observer = new MutationObserver(() => {
      scheduleDecorationScan();
    });

    observer.observe(document.body, { childList: true, subtree: true });
    scanAndDecorateLinks();
    observeGoogleSerp();
  }

  async function scanAllLinksNow() {
    scanAndDecorateLinks();
    return extractPageInsights();
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'REQUEST_PAGE_DATA') {
      sendResponse(extractPageData());
      runPageScan();
      return true;
    }

    if (message.type === 'SHOW_WARNING') {
      showDangerPageOverlay(message.result);
      return;
    }

    if (message.type === 'GET_PAGE_INSIGHTS') {
      sendResponse(extractPageInsights());
      return true;
    }

    if (message.type === 'SCAN_ALL_LINKS') {
      Promise.resolve(scanAllLinksNow()).then((result) => sendResponse(result));
      return true;
    }
  });

  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        observeLinks();
        observeGoogleSerp();
        runPageScan();
      });
    } else {
      observeLinks();
      observeGoogleSerp();
      runPageScan();
    }
  }

  init();
})();