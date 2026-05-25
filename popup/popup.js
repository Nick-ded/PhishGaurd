// ============================================================
// PhishGuard — Popup Script
// popup/popup.js
// ============================================================

// Import detector (reuse the same logic for inline URL scanning)
// We inline a minimal version here since importScripts isn't available in popup

const TRUSTED_DOMAINS_POPUP = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'wikipedia.org',
  'amazon.com', 'amazon.in', 'flipkart.com', 'paytm.com',
  'phonepe.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
  'anthropic.com', 'microsoft.com', 'apple.com'
]);

function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function quickURLScan(urlString) {
  let score = 0;
  const flags = [];
  let url;
  try { url = new URL(urlString); } catch { return { score: 90, flags: ['Invalid URL'], verdict: 'DANGEROUS' }; }

  const hostname = url.hostname.toLowerCase();
  const baseDomain = getBaseDomain(hostname);

  if (TRUSTED_DOMAINS_POPUP.has(baseDomain)) return { score: 0, flags: [], verdict: 'SAFE', trusted: true };

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { score += 40; flags.push('Raw IP address'); }
  if (hostname.includes('xn--')) { score += 35; flags.push('Punycode domain'); }
  if (url.protocol === 'http:') { score += 20; flags.push('Not HTTPS'); }

  const suspiciousTokens = ['login', 'verify', 'secure', 'kyc', 'otp', 'refund', 'claim', 'winner'];
  const found = suspiciousTokens.filter(t => hostname.includes(t));
  if (found.length > 0) { score += found.length * 10; flags.push(`Suspicious keywords: ${found.join(', ')}`); }

  const tld = '.' + hostname.split('.').pop();
  const badTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click'];
  if (badTLDs.includes(tld)) { score += 25; flags.push(`Suspicious TLD: ${tld}`); }

  const verdict = score >= 60 ? 'DANGEROUS' : score >= 30 ? 'SUSPICIOUS' : 'SAFE';
  return { score: Math.min(score, 100), flags, verdict };
}

// ── DOM refs ──────────────────────────────────────────────────
const scanningState  = document.getElementById('scanningState');
const resultState    = document.getElementById('resultState');
const verdictBadge   = document.getElementById('verdictBadge');
const verdictIcon    = document.getElementById('verdictIcon');
const verdictLabel   = document.getElementById('verdictLabel');
const verdictDomain  = document.getElementById('verdictDomain');
const verdictScore   = document.getElementById('verdictScore');
const flagsSection   = document.getElementById('flagsSection');
const flagsList      = document.getElementById('flagsList');
const cleanState     = document.getElementById('cleanState');
const inlineResult   = document.getElementById('inlineResult');
const urlInput       = document.getElementById('urlInput');
const scanBtn        = document.getElementById('scanBtn');
const settingsBtn    = document.getElementById('settingsBtn');
const settingsPanel  = document.getElementById('settingsPanel');
const settingsClose  = document.getElementById('settingsClose');
const reportLink     = document.getElementById('reportLink');

const statScanned   = document.getElementById('statScanned');
const statSafe      = document.getElementById('statSafe');
const statSuspicious= document.getElementById('statSuspicious');
const statDangerous = document.getElementById('statDangerous');

// ── Verdict display ───────────────────────────────────────────
const VERDICT_CONFIG = {
  SAFE:       { icon: '✓', label: 'SAFE',       cssClass: 'safe'       },
  SUSPICIOUS: { icon: '⚠', label: 'SUSPICIOUS', cssClass: 'suspicious' },
  DANGEROUS:  { icon: '✕', label: 'DANGEROUS',  cssClass: 'dangerous'  }
};

function showVerdict(result) {
  scanningState.style.display = 'none';
  resultState.style.display = 'block';

  const cfg = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.SAFE;
  verdictIcon.textContent  = cfg.icon;
  verdictLabel.textContent = cfg.label;
  verdictBadge.className   = `pg-verdict-badge ${cfg.cssClass}`;

  let domain = '';
  try { domain = new URL(result.url || '').hostname; } catch {}
  verdictDomain.textContent = domain || result.url || '';

  const urlScore  = result.urlScore  || 0;
  const pageScore = result.pageScore || 0;
  verdictScore.textContent = `URL risk: ${urlScore}/100 · Page risk: ${pageScore}/100`;

  // Show flags
  const allFlags = result.flags || [];
  if (allFlags.length > 0 && result.verdict !== 'SAFE') {
    flagsSection.style.display = 'block';
    cleanState.style.display   = 'none';
    flagsList.innerHTML = allFlags.slice(0, 6).map(f => {
      const text = typeof f === 'object' ? f.text : f;
      const type = typeof f === 'object' ? f.type : 'url';
      return `<div class="pg-flag-item pg-flag-${type}">
        <span class="pg-flag-dot">●</span>
        <span>${escHtml(text)}</span>
      </div>`;
    }).join('');
  } else {
    flagsSection.style.display = 'none';
    cleanState.style.display   = result.verdict === 'SAFE' ? 'block' : 'none';
  }
}

function showScanning() {
  scanningState.style.display   = 'flex';
  resultState.style.display     = 'none';
  flagsSection.style.display    = 'none';
  cleanState.style.display      = 'none';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Load current tab verdict ──────────────────────────────────
function loadCurrentTab() {
  showScanning();
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs.length) {
      showVerdict({ verdict: 'SAFE', flags: [], url: '', urlScore: 0, pageScore: 0 });
      return;
    }

    const tab = tabs[0];
    const url = tab.url || '';

    // Ask background for cached result
    chrome.runtime.sendMessage({ type: 'GET_CURRENT_VERDICT' }, (response) => {
      if (response && response.result) {
        showVerdict(response.result);
        if (response.stats) updateStats(response.stats);
      } else {
        // Fallback: quick URL-only scan
        const quickResult = quickURLScan(url);
        showVerdict({ ...quickResult, url, pageScore: 0 });
      }
    });
  });
}

// ── Update stats ──────────────────────────────────────────────
function updateStats(stats) {
  statScanned.textContent    = stats.totalScanned || 0;
  statSafe.textContent       = stats.safe        || 0;
  statSuspicious.textContent = stats.suspicious  || 0;
  statDangerous.textContent  = stats.dangerous   || 0;
}

// Load stats from background
chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
  if (response && response.stats) updateStats(response.stats);
});

// ── Inline URL scan ───────────────────────────────────────────
scanBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (!url) return;

  inlineResult.textContent = 'Scanning…';
  inlineResult.className   = 'pg-inline-result';

  // Ensure URL has protocol
  const fullURL = url.startsWith('http') ? url : 'https://' + url;

  const result = quickURLScan(fullURL);
  const cfg = VERDICT_CONFIG[result.verdict];

  inlineResult.textContent = `${cfg.icon} ${cfg.label}: ${result.flags[0] || 'No major threats found'}`;
  inlineResult.className   = `pg-inline-result pg-inline-${result.verdict.toLowerCase()}`;
});

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanBtn.click();
});

// ── Settings ──────────────────────────────────────────────────
settingsBtn.addEventListener('click', () => {
  settingsPanel.style.display = settingsPanel.style.display === 'none' ? 'block' : 'none';
});
settingsClose.addEventListener('click', () => {
  settingsPanel.style.display = 'none';
  saveSettings();
});

function saveSettings() {
  chrome.storage.local.set({
    pg_settings: {
      hoverScan:   document.getElementById('toggleHover').checked,
      overlay:     document.getElementById('toggleOverlay').checked,
      hindi:       document.getElementById('toggleHindi').checked,
      strict:      document.getElementById('toggleStrict').checked
    }
  });
}

function loadSettings() {
  chrome.storage.local.get(['pg_settings'], (r) => {
    const s = r.pg_settings || {};
    if (s.hoverScan  !== undefined) document.getElementById('toggleHover').checked    = s.hoverScan;
    if (s.overlay    !== undefined) document.getElementById('toggleOverlay').checked   = s.overlay;
    if (s.hindi      !== undefined) document.getElementById('toggleHindi').checked     = s.hindi;
    if (s.strict     !== undefined) document.getElementById('toggleStrict').checked    = s.strict;
  });
}

// ── Report ────────────────────────────────────────────────────
reportLink.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) {
      chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_POSITIVE',
        url: tabs[0].url
      }, () => {
        reportLink.textContent = '✓ Reported!';
        setTimeout(() => { reportLink.textContent = 'Report Issue'; }, 2000);
      });
    }
  });
});

// ── Init ──────────────────────────────────────────────────────
loadSettings();
loadCurrentTab();
