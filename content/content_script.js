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

  // ── Safe alternatives — real, free, legal options ────────────
  // Each entry: { name, url, free: true/false, note }
  // Shown when user visits a dangerous/suspicious site
  const SAFE_ALTERNATIVES = {
    // Piracy / illegal streaming → free legal streaming
    streaming: [
      { name: 'YouTube', url: 'youtube.com', free: true, note: 'Free movies & shows' },
      { name: 'Pluto TV', url: 'pluto.tv', free: true, note: '100% free, no signup' },
      { name: 'Tubi', url: 'tubitv.com', free: true, note: 'Free movies & TV' },
      { name: 'Crackle', url: 'crackle.com', free: true, note: 'Free Sony movies' },
      { name: 'MX Player', url: 'mxplayer.in', free: true, note: 'Free Indian content' },
      { name: 'JioCinema', url: 'jiocinema.com', free: true, note: 'Free with Jio' },
      { name: 'Hotstar', url: 'hotstar.com', free: false, note: 'Paid — Disney+ content' },
      { name: 'SonyLIV', url: 'sonyliv.com', free: false, note: 'Paid — Sony content' }
    ],
    // Piracy game repacks → free legal game sources
    gaming: [
      { name: 'Epic Games', url: 'store.epicgames.com', free: true, note: 'Free games weekly' },
      { name: 'Steam', url: 'store.steampowered.com', free: false, note: 'Paid — largest PC store' },
      { name: 'GOG', url: 'gog.com', free: true, note: 'Free games + DRM-free' },
      { name: 'Itch.io', url: 'itch.io', free: true, note: 'Thousands of free indie games' },
      { name: 'Xbox Game Pass', url: 'xbox.com/game-pass', free: false, note: 'Subscription — 100s of games' },
      { name: 'Humble Bundle', url: 'humblebundle.com', free: true, note: 'Pay-what-you-want bundles' }
    ],
    // Torrent / piracy general
    torrent: [
      { name: 'Internet Archive', url: 'archive.org', free: true, note: 'Free legal downloads' },
      { name: 'Project Gutenberg', url: 'gutenberg.org', free: true, note: 'Free ebooks' },
      { name: 'Open Library', url: 'openlibrary.org', free: true, note: 'Free book borrowing' }
    ],
    // Banking / KYC phishing
    banking: [
      { name: 'SBI Official', url: 'sbi.co.in', free: true, note: 'Official SBI website' },
      { name: 'HDFC Bank', url: 'hdfcbank.com', free: true, note: 'Official HDFC website' },
      { name: 'ICICI Bank', url: 'icicibank.com', free: true, note: 'Official ICICI website' },
      { name: 'Axis Bank', url: 'axisbank.com', free: true, note: 'Official Axis website' }
    ],
    // Shopping
    shopping: [
      { name: 'Amazon India', url: 'amazon.in', free: true, note: 'Trusted marketplace' },
      { name: 'Flipkart', url: 'flipkart.com', free: true, note: 'Trusted marketplace' },
      { name: 'Meesho', url: 'meesho.com', free: true, note: 'Budget shopping' },
      { name: 'Myntra', url: 'myntra.com', free: true, note: 'Fashion & lifestyle' }
    ],
    // Payment / UPI phishing
    payment: [
      { name: 'Paytm', url: 'paytm.com', free: true, note: 'Official Paytm app' },
      { name: 'PhonePe', url: 'phonepe.com', free: true, note: 'Official PhonePe' },
      { name: 'Google Pay', url: 'pay.google.com', free: true, note: 'Official Google Pay' }
    ],
    // Social media
    social: [
      { name: 'Instagram', url: 'instagram.com', free: true, note: 'Official Instagram' },
      { name: 'Facebook', url: 'facebook.com', free: true, note: 'Official Facebook' },
      { name: 'Twitter / X', url: 'x.com', free: true, note: 'Official X' }
    ],
    // Music piracy
    music: [
      { name: 'Spotify', url: 'spotify.com', free: true, note: 'Free tier available' },
      { name: 'JioSaavn', url: 'jiosaavn.com', free: true, note: 'Free Indian music' },
      { name: 'Gaana', url: 'gaana.com', free: true, note: 'Free Indian music' },
      { name: 'YouTube Music', url: 'music.youtube.com', free: true, note: 'Free with ads' }
    ]
  };

  // Returns array of { name, url, free, note } for a given domain
  function getSafeAlternatives(domain) {
    const h = String(domain || '').toLowerCase();

    // Piracy game repacks / cracks
    if (/repack|crack|fitgirl|dodi|skidrow|igg.game|ocean.game|steamunlock|pirat/i.test(h)) {
      return SAFE_ALTERNATIVES.gaming.slice(0, 4);
    }
    // Torrent / general piracy
    if (/torrent|rarbg|piratebay|kickass|1337x|nyaa/i.test(h)) {
      return SAFE_ALTERNATIVES.torrent.concat(SAFE_ALTERNATIVES.gaming.slice(0, 2));
    }
    // Illegal streaming / movies
    if (/movie|film|watch|series|stream|flix|rockers|rulz|yogi|isai|kutta|moviesda|fmovie|gomovie|soap2|putlock|tamilrock/i.test(h)) {
      return SAFE_ALTERNATIVES.streaming.slice(0, 4);
    }
    // Music piracy
    if (/mp3|song|music|pagalworld|djpunjab|downloadhub.*music/i.test(h)) {
      return SAFE_ALTERNATIVES.music.slice(0, 4);
    }
    // Banking / KYC phishing
    if (/bank|kyc|netbank|onlinebank|sbi|hdfc|icici|axis|kotak/i.test(h)) {
      return SAFE_ALTERNATIVES.banking.slice(0, 3);
    }
    // Payment / UPI phishing
    if (/pay|wallet|upi|transfer|money|paytm|phonepe/i.test(h)) {
      return SAFE_ALTERNATIVES.payment;
    }
    // Shopping
    if (/shop|store|buy|cart|deal|offer|discount/i.test(h)) {
      return SAFE_ALTERNATIVES.shopping.slice(0, 3);
    }
    // Social media impersonation
    if (/insta|facebook|twitter|whatsapp|social/i.test(h)) {
      return SAFE_ALTERNATIVES.social;
    }
    // Login / phishing keywords — suggest banking + payment
    if (/login|signin|account|secure|verify|update|kyc|otp/i.test(h)) {
      return [...SAFE_ALTERNATIVES.banking.slice(0, 2), ...SAFE_ALTERNATIVES.payment.slice(0, 1)];
    }
    // Default — show free streaming as most common use case
    return SAFE_ALTERNATIVES.streaming.filter(s => s.free).slice(0, 3);
  }

  const hoverCache = new Map();
  const redirectCache = new Map();

  let currentPageResult = null;
  let warningOverlayShown = false;
  let extensionSettings = { hoverScan: true, overlay: true };

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
    mutateTimer: null,
    overPopup: false,   // true while cursor is physically inside the popup card
    hideDelay: null     // timeout ID for the 200 ms grace period
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

    const verdict = score >= 55 ? 'DANGEROUS' : score >= 25 ? 'SUSPICIOUS' : 'SAFE';

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
    return '✓';
  }

  function getVerdictIconSvg(tier) {
    if (tier === 'danger') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 8l8 8M16 8l-8 8" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>';
    }

    if (tier === 'warn') {
      return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7.5 7.5 16.5 16.5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>';
    }

    return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 4 5 8v8l7 4 7-4V8l-7-4Z"/></svg>';
  }

  // ── Shared safety score conversion (matches popup.js toSafetyScore exactly) ──
  // Input:  threatScore 0–100 (0=clean, 100=dangerous), verdict, urlSeed string
  // Output: safetyScore 0–100 (100=safest, 0=most dangerous)
  //   SAFE/UNKNOWN  → 70–99 (hash-seeded from URL for consistency)
  //   SUSPICIOUS    → 45–69 (inverted from threat 25–54)
  //   DANGEROUS     → 0–44  (inverted from threat 55–100)
  function toSafetyScore(threatScore, verdict, urlSeed) {
    if (verdict === 'SAFE' || verdict === 'UNKNOWN' || !verdict) {
      let hash = 0;
      const seed = String(urlSeed || 'default');
      for (let i = 0; i < seed.length; i++) {
        hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
      }
      return 70 + (hash % 30); // 70–99
    }
    if (verdict === 'SUSPICIOUS') {
      const mapped = Math.round(69 - ((threatScore - 25) / 29) * 24);
      return Math.max(45, Math.min(69, mapped));
    }
    // DANGEROUS
    const mapped = Math.round(44 - ((threatScore - 55) / 45) * 44);
    return Math.max(0, Math.min(44, mapped));
  }

  // ── Mock/demo data for instant results on well-known sites ──
  // No hardcoded safetyScore — toSafetyScore() computes it from score+verdict
  const DEMO_SITE_DATA = {
    // Safe trusted sites
    'google.com':       { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Google LLC'] },
    'youtube.com':      { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Google LLC'] },
    'facebook.com':     { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Meta Platforms'] },
    'instagram.com':    { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Meta Platforms'] },
    'whatsapp.com':     { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Meta Platforms'] },
    'twitter.com':      { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — X Corp'] },
    'x.com':            { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — X Corp'] },
    'github.com':       { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Microsoft/GitHub'] },
    'microsoft.com':    { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Microsoft Corp'] },
    'amazon.com':       { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Amazon Inc'] },
    'amazon.in':        { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Amazon India'] },
    'flipkart.com':     { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Flipkart'] },
    'netflix.com':      { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Netflix Inc'] },
    'linkedin.com':     { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — LinkedIn/Microsoft'] },
    'wikipedia.org':    { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Wikimedia Foundation'] },
    'apple.com':        { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Apple Inc'] },
    'paytm.com':        { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Paytm/One97'] },
    'phonepe.com':      { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — PhonePe Pvt Ltd'] },
    'sbi.co.in':        { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — State Bank of India'] },
    'hdfcbank.com':     { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — HDFC Bank'] },
    'icicibank.com':    { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — ICICI Bank'] },
    'irctc.co.in':      { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Indian Railways'] },
    'reddit.com':       { verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Reddit Inc'] },
    'stackoverflow.com':{ verdict: 'SAFE', score: 0, flags: ['Verified trusted domain — Stack Exchange'] },
    // Unsafe/piracy sites — threat score 100 → toSafetyScore gives 0–44
    'filmyzilla.com':   { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy/illegal streaming site', 'Blocked by Cloudflare for copyright violations'] },
    'tamilrockers.ws':  { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy site — distributes copyrighted content illegally'] },
    'movierulz.tc':     { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy/illegal streaming site'] },
    'netmirror.plus':   { verdict: 'DANGEROUS', score: 100, flags: ['Blocked by Cloudflare for phishing/piracy', 'Known malicious domain'] },
    'soap2day.to':      { verdict: 'DANGEROUS', score: 100, flags: ['Known illegal streaming site', 'Malware distribution risk'] },
    'thepiratebay.org': { verdict: 'DANGEROUS', score: 100, flags: ['Known torrent/piracy site', 'Legal risk in most countries'] },
    'vegamovies.nl':    { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy/illegal streaming site'] },
    'bollyflix.com':    { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy/illegal streaming site'] },
    'kuttymovies.com':  { verdict: 'DANGEROUS', score: 100, flags: ['Known piracy site — Tamil movies'] },
    'fmovies.to':       { verdict: 'DANGEROUS', score: 100, flags: ['Known illegal streaming site', 'Adware/malware risk'] },
    'fitgirl-repacks.site': { verdict: 'SUSPICIOUS', score: 40, flags: ['Suspicious TLD (.site)', 'Distributes pirated game repacks', 'Unofficial software distribution'] }
  };

  function getDemoData(urlString) {
    try {
      const hostname = new URL(urlString).hostname.toLowerCase().replace(/^www\./, '');
      if (DEMO_SITE_DATA[hostname]) return DEMO_SITE_DATA[hostname];
      // Check base domain
      const parts = hostname.split('.');
      if (parts.length > 2) {
        const base = parts.slice(-2).join('.');
        if (DEMO_SITE_DATA[base]) return DEMO_SITE_DATA[base];
      }
    } catch { /* ignore */ }
    return null;
  }

  function loadExtensionSettings() {
    chrome.storage.local.get(['pg_settings'], (result) => {
      if (result && result.pg_settings) {
        extensionSettings = { ...extensionSettings, ...result.pg_settings };
      }
    });
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
    const rawScore = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const safetyScore = toSafetyScore(rawScore, verdict, result.url || '');
    const label = getVerdictBadgeText(verdict);
    const inner = verdict === 'SAFE'
      ? `${getVerdictIconSvg(tier)}<span>${escHtml(label)}</span>`
      : `${getVerdictIconSvg(tier)}<span>${escHtml(label)}</span><span>·</span><span>${safetyScore}</span>`;

    return `<span class="pg-badge pg-${tier}" aria-hidden="true">${inner}</span>`;
  }

  function buildTooltipMarkup(result, domain) {
    const verdict = result.verdict || 'SAFE';
    const tier = getVerdictTier(verdict);
    const rawScore = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const safetyScore = toSafetyScore(rawScore, verdict, result.url || domain || '');
    const chips = getTooltipChips(result.flags || []);

    return `
      <span class="pg-badge-tooltip-line1">
        <span class="pg-badge pg-${tier}">${getVerdictIconSvg(tier)}<span>${escHtml(getVerdictBadgeText(verdict))}</span></span>
        <span class="pg-badge-tooltip-score">Safety ${safetyScore}/100</span>
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
    const safeLabel = getVerdictBadgeText(result.verdict || 'SAFE');
    const rawThreat = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const safetyScoreBadge = toSafetyScore(rawThreat, result.verdict || 'SAFE', urlString);
    badge.innerHTML = result.verdict === 'SAFE' || !result.verdict
      ? `${getVerdictIconSvg(tier)}<span>${escHtml(safeLabel)}</span>`
      : `${getVerdictIconSvg(tier)}<span>${escHtml(safeLabel)}</span><span>·</span><span>${safetyScoreBadge}</span>`;

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
      const updatedLabel = getVerdictBadgeText(result.verdict || 'SAFE');
      const rawThreat2 = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
      const safetyScore2 = toSafetyScore(rawThreat2, result.verdict || 'SAFE', urlString);
      badge.innerHTML = result.verdict === 'SAFE' || !result.verdict
        ? `${getVerdictIconSvg(tier)}<span>${escHtml(updatedLabel)}</span>`
        : `${getVerdictIconSvg(tier)}<span>${escHtml(updatedLabel)}</span><span>·</span><span>${safetyScore2}</span>`;
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
    const rawScore = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const safetyScore = toSafetyScore(rawScore, verdict, result.url || '');
    const chips = getTooltipChips(result.flags || []).slice(0, 2);
    const label = verdict === 'DANGEROUS' ? 'Dangerous' : verdict === 'SUSPICIOUS' ? 'Suspicious' : 'Safe';

    return `
      ${getVerdictIconSvg(tier)} ${label} · Safety ${safetyScore}${chips.length ? ` · ${chips.map((chip) => escHtml(chip)).join(' · ')}` : ''}
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

  function createGoogleSerpBadge(result) {
    const verdict = result.verdict || 'SAFE';
    const tier = getVerdictTier(verdict);
    const rawScore = Math.max(0, Math.min(100, Number(result.score ?? result.urlScore ?? 0)));
    const safetyScore = toSafetyScore(rawScore, verdict, result.url || result.domain || '');
    const chips = getTooltipChips(result.flags || []).slice(0, 3);
    const badgeLabel = getVerdictBadgeText(verdict);

    const wrap = document.createElement('span');
    wrap.className = 'pg-link-badge-wrap';
    wrap.tabIndex = 0;

    const badge = document.createElement('span');
    badge.className = `pg-badge pg-${tier}`;
    badge.innerHTML = verdict === 'SAFE'
      ? `${getVerdictIconSvg(tier)}<span>${escHtml(badgeLabel)}</span>`
      : `${getVerdictIconSvg(tier)}<span>${escHtml(badgeLabel)}</span><span>·</span><span>${safetyScore}</span>`;

    const tooltip = document.createElement('span');
    tooltip.className = 'pg-badge-tooltip';
    tooltip.setAttribute('role', 'tooltip');
    tooltip.setAttribute('aria-hidden', 'true');
    tooltip.innerHTML = `
      <span class="pg-badge-tooltip-line1">
        <span class="pg-badge pg-${tier}">${getVerdictIconSvg(tier)}<span>${escHtml(badgeLabel)}</span></span>
        <span class="pg-badge-tooltip-score">Safety ${safetyScore}/100</span>
      </span>
      <div class="pg-badge-tooltip-domain">${escHtml(result.domain || '')}</div>
      <div class="pg-badge-tooltip-chips">
        ${chips.length
          ? chips.map((chip) => `<span class="pg-badge-chip">${escHtml(chip)}</span>`).join('')
          : '<span class="pg-badge-chip pg-badge-chip-muted">No major threats found</span>'}
      </div>
    `;

    wrap.appendChild(badge);
    wrap.appendChild(tooltip);

    const showTooltip = () => {
      wrap.classList.add('pg-tooltip-open');
    };

    const hideTooltip = () => {
      wrap.classList.remove('pg-tooltip-open');
    };

    badge.addEventListener('pointerenter', showTooltip);
    badge.addEventListener('focus', showTooltip);
    wrap.addEventListener('pointerleave', hideTooltip);
    wrap.addEventListener('blur', hideTooltip);
    return wrap;
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

  function isGoogleSerpTitleLink(anchor) {
    if (!anchor || anchor.closest('[data-ved]') === null) return false;
    if (anchor.closest('g-scrolling-carousel') !== null) return false;
    if (anchor.closest('[role="navigation"]') !== null) return false;
    if (anchor.closest('g-inner-card') !== null) return false;
    if (anchor.closest('.ULSxyf') !== null) return false;
    if (anchor.offsetParent === null) return false;

    const href = String(anchor.getAttribute('href') || anchor.href || '');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return false;

    return true;
  }

  async function scanGoogleSerpTitleLink(anchor) {
    if (!anchor || anchor.dataset.pgScanned === 'true') return null;
    if (!isGoogleSerpTitleLink(anchor)) return null;

    anchor.dataset.pgScanned = 'true';

    const urlString = getLinkUrl(anchor);
    if (!urlString) return null;

    const result = await scanHoverUrl(urlString);
    if (!result) return null;

    const h3 = anchor.closest('h3') || anchor.parentElement;
    if (!h3) return result;

    const container = anchor.closest('div.g, div[data-sokoban-grid]');
    if (container) {
      applyGoogleSerpVerdict(container, urlString, result);
    }

    const badgeEl = createGoogleSerpBadge({
      ...result,
      domain: getDisplayDomain(urlString)
    });

    h3.insertAdjacentElement('afterend', badgeEl);
    return result;
  }

  async function scanGoogleSerpPage() {
    if (!GOOGLE_SERP_RE.test(location.href)) return;

    const requestId = ++serpState.requestId;
    const serpCounts = { dangerCount: 0, suspiciousCount: 0 };
    const titleLinks = document.querySelectorAll(
      'div#search div.g a[jsname], ' +
      'div#search h3 > a, ' +
      'div[data-sokoban-grid] h3 > a'
    );
    const items = Array.from(titleLinks).filter((anchor) => isGoogleSerpTitleLink(anchor));

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
        const anchor = items[index++];
        active++;

        Promise.resolve(scanGoogleSerpTitleLink(anchor).then((result) => {
          if (!result) return;
          if (result.verdict === 'DANGEROUS') serpCounts.dangerCount++;
          else if (result.verdict === 'SUSPICIOUS') serpCounts.suspiciousCount++;
        }))
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
    host.setAttribute('data-visible', 'false');

    // All visibility is controlled via inline styles — we never rely on
    // shadow-DOM CSS to style the host (`:host` is fragile across browsers).
    host.style.cssText = [
      'position:fixed',
      'left:0', 'top:0',
      'width:0', 'height:0',
      'z-index:2147483647',
      'opacity:0',
      'pointer-events:none',
      'transform:translateY(6px) scale(0.98)',
      'transition:opacity 180ms ease,transform 180ms ease',
      'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif'
    ].join(';');

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

    // Keep the popup alive while the cursor is inside the card
    hoverPopupRefs.card.addEventListener('pointerenter', () => {
      hoverState.overPopup = true;
      clearTimeout(hoverState.hideDelay);
    });

    hoverPopupRefs.card.addEventListener('pointerleave', () => {
      hoverState.overPopup = false;
      hoverState.hideDelay = setTimeout(() => {
        if (!hoverState.overPopup) hideHoverPopup();
      }, 150);
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
      SAFE: '✓',
      SUSPICIOUS: '⚠',
      DANGEROUS: '✕',
      LOADING: '○'
    };

    const titleMap = {
      SAFE: 'Safe',
      SUSPICIOUS: 'Suspicious',
      DANGEROUS: 'Dangerous',
      LOADING: 'Scanning...'
    };

    const subtitleMap = {
      SAFE: 'No threats detected',
      SUSPICIOUS: 'Proceed with caution',
      DANGEROUS: 'Do not proceed',
      LOADING: 'Analyzing link'
    };

    hoverPopupRefs.icon.textContent = iconMap[verdict] || '○';
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

    // Show safe alternative link suggestions for DANGEROUS/SUSPICIOUS links
    if (verdict === 'DANGEROUS' || verdict === 'SUSPICIOUS') {
      const domain = getDisplayDomain(urlString);
      const alternatives = getSafeAlternatives(domain);
      if (alternatives.length > 0) {
        const altSection = document.createElement('div');
        altSection.className = 'ga-hover-alternatives';
        altSection.innerHTML = `<div class="ga-hover-alt-title">✅ Safe alternatives:</div>`;
        alternatives.forEach((alt) => {
          const altLink = document.createElement('a');
          altLink.href = `https://${alt.url}`;
          altLink.target = '_blank';
          altLink.rel = 'noopener noreferrer';
          altLink.className = 'ga-hover-alt-link';
          altLink.title = alt.note || '';
          altLink.innerHTML = `${alt.free ? '🆓 ' : ''}${escHtml(alt.name)}`;
          altLink.addEventListener('click', (event) => event.stopPropagation());
          altSection.appendChild(altLink);
        });
        hoverPopupRefs.actions.appendChild(altSection);
      }
    }
  }

  function showPopupHost() {
    if (!hoverPopupHost) return;
    hoverPopupHost.setAttribute('data-visible', 'true');
    hoverPopupHost.setAttribute('aria-hidden', 'false');
    hoverPopupHost.style.opacity = '1';
    hoverPopupHost.style.pointerEvents = 'auto';
    hoverPopupHost.style.transform = 'translateY(0) scale(1)';
  }

  function hidePopupHost() {
    if (!hoverPopupHost) return;
    hoverPopupHost.setAttribute('data-visible', 'false');
    hoverPopupHost.setAttribute('aria-hidden', 'true');
    hoverPopupHost.style.opacity = '0';
    hoverPopupHost.style.pointerEvents = 'none';
    hoverPopupHost.style.transform = 'translateY(6px) scale(0.98)';
  }

  function renderHoverPopup(state) {
    if (!hoverPopupRefs) return;

    const verdict = state.verdict || 'SAFE';
    // Normalize: service_worker returns urlScore, quickURLScan returns score
    const rawThreatScore = Math.max(0, Math.min(100, Number(state.score ?? state.urlScore ?? 0)));
    // Use the SAME toSafetyScore formula as popup.js — single source of truth
    const displayScore = toSafetyScore(rawThreatScore, verdict, state.url || state.domain || '');

    const domain = state.domain || state.url || '';
    const reasons = Array.isArray(state.reasons) ? state.reasons : [];

    setHoverTheme(verdict);
    hoverPopupRefs.loading.hidden = true;
    hoverPopupRefs.content.hidden = false;
    hoverPopupRefs.domain.textContent = domain;
    hoverPopupRefs.score.textContent = `${displayScore}/100`;
    hoverPopupRefs.redirect.hidden = !state.redirectTarget;
    hoverPopupRefs.redirect.textContent = state.redirectTarget
      ? `Redirects to: ${state.redirectTarget}${state.dangerousRedirect ? '  🔴 This destination is dangerous' : ''}`
      : '';
    hoverPopupRefs.offline.hidden = !state.offlineMode;

    populateReasons(reasons.length > 0 ? reasons : ['No major threats found']);
    populateActions(verdict, state.url, state.result || null);

    const fill = hoverPopupRefs.progress;
    fill.style.transform = 'scaleX(0)';
    requestAnimationFrame(() => {
      fill.style.transform = `scaleX(${displayScore / 100})`;
    });

    showPopupHost();
  }

  function renderHoverLoading(urlString) {
    if (!hoverPopupRefs) return;

    setHoverTheme('LOADING');
    hoverPopupRefs.loading.hidden = false;
    hoverPopupRefs.content.hidden = true;
    hoverPopupRefs.offline.hidden = true;
    hoverPopupRefs.redirect.hidden = true;
    hoverPopupRefs.domain.textContent = getDisplayDomain(urlString);

    showPopupHost();
  }

  function hideHoverPopup() {
    hoverState.requestId++;
    hoverState.activeLink = null;
    hoverState.lastUrl = '';
    hoverState.overPopup = false;
    clearTimeout(hoverState.timer);
    clearTimeout(hoverState.mutateTimer);
    clearTimeout(hoverState.hideDelay);

    hidePopupHost();
  }

  async function showHoverPopup(link, event) {
    const urlString = getLinkUrl(link);
    if (!urlString) return;

    const requestId = ++hoverState.requestId;
    hoverState.activeLink = link;
    hoverState.lastUrl = urlString;

    await ensureTooltipReady();
    if (requestId !== hoverState.requestId) return;

    // 1. Check demo/mock data first — instant, no async needed
    const demoData = getDemoData(urlString);
    const quickResult = demoData || readCache(hoverCache, urlString) || quickURLScan(urlString);
    const quickReasons = Array.isArray(quickResult.flags)
      ? quickResult.flags.map((flag) => typeof flag === 'object' ? flag.text : flag)
      : [];

    renderHoverPopup({
      verdict: quickResult.verdict || 'SAFE',
      score: typeof quickResult.score === 'number' ? quickResult.score : 0,
      domain: getDisplayDomain(urlString),
      url: urlString,
      reasons: quickReasons.length ? quickReasons : ['No major threats found'],
      redirectTarget: '',
      dangerousRedirect: false,
      offlineMode: !demoData,
      result: quickResult
    });
    positionHoverPopup(link);

    // 2. If we already have demo data, no need to fetch async
    if (demoData) return;

    // 3. Fetch full async result and update silently if still hovering
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

    renderHoverPopup({
      verdict,
      score: score ?? baseResult.urlScore ?? 0,
      domain: getDisplayDomain(urlString),
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

    link.addEventListener('pointerenter', (event) => {
      // Cancel any pending hide so re-entering a link keeps things alive
      clearTimeout(hoverState.hideDelay);
      scheduleHover(link, event);
    });

    link.addEventListener('focus', (event) => {
      clearTimeout(hoverState.hideDelay);
      scheduleHover(link, event);
    });

    link.addEventListener('pointerleave', () => {
      clearTimeout(hoverState.timer);
      // 250 ms grace period — if the cursor lands on the popup card within
      // this window, the card's own pointerenter cancels the hide.
      hoverState.hideDelay = setTimeout(() => {
        if (!hoverState.overPopup) hideHoverPopup();
      }, 250);
    });

    link.addEventListener('blur', () => {
      clearTimeout(hoverState.timer);
      hideHoverPopup();
    });

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

    const verdict = result.verdict || 'DANGEROUS';
    const domain = (() => { try { return new URL(result.url).hostname; } catch { return result.url; } })();
    const flags = (result.flags || []).slice(0, 5).map((flag) => typeof flag === 'object' ? flag.text : flag);
    const score = Math.max(0, Math.min(100, Number(result.score || result.urlScore || 0)));
    const alternatives = getSafeAlternatives(domain);

    // Use the shared toSafetyScore — same formula as popup.js and hover popup
    const safetyScore = toSafetyScore(score, verdict, result.url || '');

    const verdictConfig = {
      DANGEROUS: {
        icon: '🔴',
        badge: 'DANGEROUS WEBSITE',
        headline: 'This website is dangerous',
        advice: 'Do NOT enter your OTP, PIN, password, UPI credentials, Aadhaar, or PAN on this page.',
        color: '#A32D2D'
      },
      SUSPICIOUS: {
        icon: '⚠️',
        badge: 'SUSPICIOUS WEBSITE',
        headline: 'This website looks suspicious',
        advice: 'Proceed with extreme caution. Verify the website URL carefully before entering any personal information.',
        color: '#BA7517'
      }
    };

    const config = verdictConfig[verdict] || verdictConfig.DANGEROUS;

    const alternativesHtml = alternatives.length > 0 ? `
      <div class="pg-ov-alternatives">
        <div class="pg-ov-alternatives-title">✅ Safe Alternatives:</div>
        ${alternatives.map((alt) => `
          <a href="https://${escHtml(alt.url)}" target="_blank" rel="noopener noreferrer" class="pg-ov-alt-link" title="${escHtml(alt.note || '')}">
            ${alt.free ? '🆓 ' : ''}${escHtml(alt.name)}
          </a>
        `).join('')}
      </div>
    ` : '';

    const overlay = document.createElement('div');
    overlay.id = 'pg-page-overlay';
    overlay.innerHTML = `
      <div class="pg-overlay-box">
        <div class="pg-ov-header">
          <div class="pg-ov-brand">
            <span class="pg-ov-shield">🛡️</span>
            <div class="pg-ov-brand-text">
              <div class="pg-ov-brand-title">PhishGuard</div>
              <div class="pg-ov-brand-subtitle">Website Protection</div>
            </div>
          </div>
        </div>

        <div class="pg-ov-verdict-card pg-ov-${verdict.toLowerCase()}">
          <div class="pg-ov-verdict-icon">${config.icon}</div>
          <div class="pg-ov-verdict-badge">${config.badge}</div>
          <h2 class="pg-ov-headline">${config.headline}</h2>
          <div class="pg-ov-domain-label">Blocked website:</div>
          <div class="pg-ov-domain">${escHtml(domain)}</div>

          <div class="pg-ov-score-section">
            <div class="pg-ov-score-row">
              <span class="pg-ov-score-label">Safety Score</span>
              <span class="pg-ov-score-value">${safetyScore}/100</span>
            </div>
            <div class="pg-ov-health-bar">
              <div class="pg-ov-health-fill" style="width: ${safetyScore}%"></div>
            </div>
            <div class="pg-ov-health-labels">
              <span>Dangerous</span>
              <span>Suspicious</span>
              <span>Safe</span>
            </div>
          </div>

          ${flags.length > 0 ? `
          <div class="pg-ov-reasons">
            <div class="pg-ov-reasons-title">⚠️ Warning indicators:</div>
            ${flags.map((flag) => `<div class="pg-ov-flag">• ${escHtml(flag)}</div>`).join('')}
          </div>
          ` : ''}

          <div class="pg-ov-advice">${config.advice}</div>

          ${alternativesHtml}
        </div>

        <div class="pg-ov-actions">
          <button class="pg-ov-btn pg-ov-btn-back" id="pg-ov-back">
            <span>← Go Back</span>
          </button>
          <button class="pg-ov-btn pg-ov-btn-continue" id="pg-ov-continue">
            <span>Continue Anyway</span>
          </button>
        </div>

        <div class="pg-ov-footer">
          <button class="pg-ov-report-btn" id="pg-ov-report">Report false positive</button>
        </div>
      </div>
    `;

    document.body.prepend(overlay);
    document.body.style.overflow = 'hidden';

    document.getElementById('pg-ov-back').onclick = () => {
      history.back();
    };

    document.getElementById('pg-ov-continue').onclick = () => {
      overlay.remove();
      document.body.style.overflow = '';
      warningOverlayShown = false;
    };

    document.getElementById('pg-ov-report').onclick = () => {
      chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: result.url });
      document.getElementById('pg-ov-report').textContent = '✓ Reported — thank you!';
      document.getElementById('pg-ov-report').disabled = true;
    };
  }

  function scanAndDecorateLinks() {
    if (GOOGLE_SERP_RE.test(location.href)) return;

    document.querySelectorAll('a[href]').forEach((link) => {
      if (extensionSettings.hoverScan) {
        attachLinkHover(link);
      }
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

    if (message.type === 'GET_PAGE_INSIGHTS' || message.type === 'REQUEST_PAGE_INSIGHTS') {
      sendResponse(extractPageInsights());
      return true;
    }

    if (message.type === 'SHOW_WARNING') {
      showDangerPageOverlay(message.result);
      return true;
    }

    if (message.type === 'SCAN_ALL_LINKS') {
      Promise.resolve(scanAllLinksNow()).then((result) => sendResponse(result));
      return true;
    }
  });

  function init() {
    loadExtensionSettings();
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