// ============================================================
// PhishGuard — Live Threat Intelligence  (Rate-Limited)
// utils/threat_intel.js
//
// Strategy: Round-robin across APIs so no single source gets
// hammered. Each API has a hard budget enforced locally:
//
//   Google Safe Browsing  — 10,000 req/day  → max 400/hr tracked
//   VirusTotal            — 500 req/day, 4/min → max 4/min tracked
//   PhishTank             — 1,000 req/hr (with key) → max 900/hr
//
// Hover-link scans NEVER hit the API — local scoring only.
// Full page scans pick ONE API per URL via round-robin, skip
// any API that is currently rate-limited, and fall back to
// local-only if all APIs are exhausted or unconfigured.
//
// All results cached 30 min so the same URL never re-queries.
// ============================================================

const ThreatIntel = (() => {

  // ── Cache ─────────────────────────────────────────────────────
  const CACHE_TTL     = 30 * 60 * 1000; // 30 min
  const MAX_CACHE     = 500;
  const threatCache   = new Map();

  function cacheSet(url, entry) {
    if (threatCache.has(url)) threatCache.delete(url);
    threatCache.set(url, { ...entry, timestamp: Date.now() });
    while (threatCache.size > MAX_CACHE) {
      const oldest = threatCache.keys().next().value;
      if (oldest !== undefined) threatCache.delete(oldest);
    }
  }

  function cacheGet(url) {
    const entry = threatCache.get(url);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > CACHE_TTL) {
      threatCache.delete(url);
      return null;
    }
    return entry;
  }

  // ── Per-API rate-limit buckets ────────────────────────────────
  // Each bucket tracks request timestamps in a sliding window.
  // windowMs  = the rolling window size
  // maxInWindow = max requests allowed in that window
  const rateLimiters = {
    gsb: {
      name: 'Google Safe Browsing',
      windowMs: 60 * 60 * 1000,   // 1 hour window
      maxInWindow: 400,            // conservative: 400/hr of 10k/day
      timestamps: []
    },
    vt: {
      name: 'VirusTotal',
      windowMs: 60 * 1000,         // 1 minute window
      maxInWindow: 3,              // conservative: 3/min of 4/min limit
      timestamps: []
    },
    pt: {
      name: 'PhishTank',
      windowMs: 60 * 60 * 1000,   // 1 hour window
      maxInWindow: 900,            // conservative: 900/hr of 1000/hr limit
      timestamps: []
    }
  };

  // Returns true if this API can accept one more request right now
  function canCall(limiter) {
    const now = Date.now();
    // Drop timestamps outside the window
    limiter.timestamps = limiter.timestamps.filter(
      t => now - t < limiter.windowMs
    );
    return limiter.timestamps.length < limiter.maxInWindow;
  }

  // Record that we just made a request to this API
  function recordCall(limiter) {
    limiter.timestamps.push(Date.now());
  }

  // How many ms until the oldest request falls out of the window
  function msUntilSlot(limiter) {
    if (limiter.timestamps.length === 0) return 0;
    const oldest = limiter.timestamps[0];
    return Math.max(0, limiter.windowMs - (Date.now() - oldest));
  }

  // ── Round-robin state ─────────────────────────────────────────
  // Cycles through: 0 = GSB, 1 = VT, 2 = PT
  let rrIndex = 0;
  const API_KEYS = ['gsb', 'vt', 'pt'];

  // Pick the next API that (a) has a key configured and (b) is not rate-limited.
  // Returns the key string ('gsb'|'vt'|'pt') or null if none available.
  function pickNextApi(keys) {
    const configured = API_KEYS.filter(k => {
      if (k === 'gsb') return !!keys.googleSafeBrowsing;
      if (k === 'vt')  return !!keys.virusTotal;
      if (k === 'pt')  return true; // PhishTank works without a key (lower limit)
      return false;
    });

    if (configured.length === 0) return null;

    // Try each slot starting from rrIndex, wrap around
    for (let i = 0; i < configured.length; i++) {
      const candidate = configured[rrIndex % configured.length];
      rrIndex = (rrIndex + 1) % configured.length;
      if (canCall(rateLimiters[candidate])) {
        return candidate;
      }
    }

    // All configured APIs are rate-limited right now
    return null;
  }

  // ── Storage ───────────────────────────────────────────────────
  function loadApiKeys() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['pg_api_keys'], (result) => {
        resolve(result.pg_api_keys || {});
      });
    });
  }

  function saveApiKeys(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.set({ pg_api_keys: keys }, resolve);
    });
  }

  // ── Individual API callers ────────────────────────────────────

  async function callGSB(urlString, apiKey) {
    const endpoint =
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const body = {
      client: { clientId: 'phishguard-extension', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: [
          'MALWARE', 'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: urlString }]
      }
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) return null;
    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const types = data.matches.map(m => m.threatType);
      return {
        flagged: true,
        verdict: 'DANGEROUS',
        score: 100,
        source: 'Google Safe Browsing',
        reasons: types.map(t => {
          if (t === 'SOCIAL_ENGINEERING') return 'Confirmed phishing site (Google Safe Browsing)';
          if (t === 'MALWARE')            return 'Confirmed malware site (Google Safe Browsing)';
          if (t === 'UNWANTED_SOFTWARE')  return 'Unwanted software (Google Safe Browsing)';
          return `Flagged by Google Safe Browsing: ${t}`;
        })
      };
    }

    return { flagged: false, source: 'Google Safe Browsing' };
  }

  async function callVirusTotal(urlString, apiKey) {
    // VT uses base64url-encoded URL as the resource identifier
    const urlId = btoa(urlString)
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { method: 'GET', headers: { 'x-apikey': apiKey } }
    );

    if (response.status === 404) return { flagged: false, source: 'VirusTotal' };
    if (!response.ok) return null;

    const data = await response.json();
    const s = data?.data?.attributes?.last_analysis_stats;
    if (!s) return null;

    const malicious  = Number(s.malicious  || 0);
    const suspicious = Number(s.suspicious || 0);
    const total = malicious + suspicious +
                  Number(s.harmless || 0) + Number(s.undetected || 0);

    if (malicious >= 3) {
      return {
        flagged: true,
        verdict: 'DANGEROUS',
        score: Math.min(100, 60 + malicious * 5),
        source: 'VirusTotal',
        reasons: [`Flagged malicious by ${malicious}/${total} engines (VirusTotal)`]
      };
    }

    if (malicious >= 1 || suspicious >= 3) {
      return {
        flagged: true,
        verdict: 'SUSPICIOUS',
        score: 45,
        source: 'VirusTotal',
        reasons: [`Flagged by ${malicious + suspicious}/${total} engines (VirusTotal)`]
      };
    }

    return { flagged: false, source: 'VirusTotal' };
  }

  async function callPhishTank(urlString, apiKey) {
    const params = new URLSearchParams({ url: urlString, format: 'json' });
    if (apiKey) params.set('app_key', apiKey);

    const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    if (!response.ok) return null;
    const data = await response.json();
    const result = data.results;
    if (!result) return null;

    if (result.in_database && result.valid) {
      return {
        flagged: true,
        verdict: 'DANGEROUS',
        score: 100,
        source: 'PhishTank',
        reasons: ['Confirmed phishing URL (PhishTank community database)']
      };
    }

    return { flagged: false, source: 'PhishTank' };
  }

  // ── Dispatch to the chosen API ────────────────────────────────
  async function dispatchApi(apiKey, urlString, keys) {
    const limiter = rateLimiters[apiKey];
    recordCall(limiter); // count it before the call so concurrent calls don't double-book

    try {
      if (apiKey === 'gsb') return await callGSB(urlString, keys.googleSafeBrowsing);
      if (apiKey === 'vt')  return await callVirusTotal(urlString, keys.virusTotal);
      if (apiKey === 'pt')  return await callPhishTank(urlString, keys.phishTank);
    } catch {
      return null; // network error — fail silently, local detection takes over
    }

    return null;
  }

  // ── Main lookup ───────────────────────────────────────────────
  // Picks ONE API per call (round-robin, rate-limit aware).
  // Pass hoverMode=true to skip API entirely (local scoring only).
  async function lookup(urlString, { hoverMode = false } = {}) {
    if (!urlString) return null;

    // Always check cache first — same URL never re-queries within TTL
    const cached = cacheGet(urlString);
    if (cached) return cached;

    // Hover scans skip the API to avoid burning quota on every mouse move
    if (hoverMode) return null;

    const keys = await loadApiKeys();
    const chosen = pickNextApi(keys);

    if (!chosen) {
      // All APIs rate-limited or unconfigured — local detection only
      return null;
    }

    const apiResult = await dispatchApi(chosen, urlString, keys);

    if (!apiResult) return null; // call failed

    // Build the unified entry
    const entry = apiResult.flagged
      ? {
          flagged: true,
          verdict: apiResult.verdict,
          score: apiResult.score || (apiResult.verdict === 'DANGEROUS' ? 100 : 45),
          sources: [apiResult.source],
          reasons: apiResult.reasons || [],
          checkedSources: [apiResult.source]
        }
      : {
          flagged: false,
          verdict: 'SAFE',
          score: 0,
          sources: [],
          reasons: [],
          checkedSources: [apiResult.source]
        };

    cacheSet(urlString, entry);
    return entry;
  }

  // ── Rate-limit status (for popup display) ────────────────────
  function getRateLimitStatus() {
    return Object.fromEntries(
      Object.entries(rateLimiters).map(([key, limiter]) => {
        const now = Date.now();
        const active = limiter.timestamps.filter(t => now - t < limiter.windowMs);
        return [key, {
          name: limiter.name,
          used: active.length,
          max: limiter.maxInWindow,
          windowLabel: limiter.windowMs >= 3600000 ? '/ hr' : '/ min',
          available: canCall(limiter),
          msUntilSlot: msUntilSlot(limiter)
        }];
      })
    );
  }

  async function hasAnyKey() {
    const keys = await loadApiKeys();
    return !!(keys.googleSafeBrowsing || keys.phishTank || keys.virusTotal);
  }

  return { lookup, loadApiKeys, saveApiKeys, hasAnyKey, getRateLimitStatus };
})();

if (typeof module !== 'undefined') module.exports = ThreatIntel;
