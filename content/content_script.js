// ============================================================
// PhishGuard — Content Script
// content/content_script.js
// ============================================================

(function () {
  'use strict';

  let hoverTooltip = null;
  let hoverTimeout = null;
  let currentPageResult = null;
  let warningOverlayShown = false;

  // ── Extract page data for analysis ──────────────────────────
  function extractPageData() {
    const bodyText = document.body
      ? (document.body.innerText || document.body.textContent || '').slice(0, 5000)
      : '';

    const formFields = [];
    document.querySelectorAll('input').forEach(input => {
      const name = (input.name || input.id || input.placeholder || '').toLowerCase();
      if (name) formFields.push(name);
    });

    return {
      title: document.title || '',
      bodyText,
      forms: formFields,
      hasPasswordField: !!document.querySelector('input[type="password"]'),
      hasOTPField: formFields.some(f => /otp|pin|code/.test(f)),
      url: window.location.href
    };
  }

  // ── Send page data to background for full scan ───────────────
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

  // ── Link hover tooltip ───────────────────────────────────────
  function createTooltip() {
    const div = document.createElement('div');
    div.id = 'phishguard-hover-tooltip';
    div.innerHTML = `
      <div class="pg-tooltip-inner">
        <div class="pg-tooltip-icon"></div>
        <div class="pg-tooltip-content">
          <div class="pg-tooltip-verdict"></div>
          <div class="pg-tooltip-domain"></div>
        </div>
      </div>
    `;
    document.body.appendChild(div);
    return div;
  }

  function showTooltip(e, result, url) {
    if (!hoverTooltip) hoverTooltip = createTooltip();

    const verdict = result.verdict;
    const domain = (() => { try { return new URL(url).hostname; } catch { return url.slice(0, 40); } })();

    const icons = { SAFE: '✓', SUSPICIOUS: '⚠', DANGEROUS: '✕' };
    const labels = { SAFE: 'Safe Link', SUSPICIOUS: 'Suspicious', DANGEROUS: 'Dangerous!' };

    hoverTooltip.className = `pg-verdict-${verdict.toLowerCase()}`;
    hoverTooltip.querySelector('.pg-tooltip-icon').textContent = icons[verdict] || '?';
    hoverTooltip.querySelector('.pg-tooltip-verdict').textContent = labels[verdict] || verdict;
    hoverTooltip.querySelector('.pg-tooltip-domain').textContent = domain;

    // Position near cursor
    const x = Math.min(e.clientX + 15, window.innerWidth - 220);
    const y = e.clientY + 20;
    hoverTooltip.style.left = x + 'px';
    hoverTooltip.style.top = y + 'px';
    hoverTooltip.style.opacity = '1';
    hoverTooltip.style.transform = 'translateY(0)';
    hoverTooltip.style.pointerEvents = 'none';
  }

  function hideTooltip() {
    if (hoverTooltip) {
      hoverTooltip.style.opacity = '0';
      hoverTooltip.style.transform = 'translateY(-4px)';
    }
  }

  // ── Attach hover listeners to all links ──────────────────────
  function attachLinkHover(link) {
    if (link.dataset.pgAttached) return;
    link.dataset.pgAttached = 'true';

    link.addEventListener('mouseenter', (e) => {
      const href = link.href;
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

      clearTimeout(hoverTimeout);
      hoverTimeout = setTimeout(() => {
        chrome.runtime.sendMessage({ type: 'HOVER_LINK', url: href }, (response) => {
          if (response && response.result) {
            showTooltip(e, response.result, href);
          }
        });
      }, 300);
    });

    link.addEventListener('mouseleave', () => {
      clearTimeout(hoverTimeout);
      hideTooltip();
    });

    link.addEventListener('mousemove', (e) => {
      if (hoverTooltip && hoverTooltip.style.opacity === '1') {
        const x = Math.min(e.clientX + 15, window.innerWidth - 220);
        const y = e.clientY + 20;
        hoverTooltip.style.left = x + 'px';
        hoverTooltip.style.top = y + 'px';
      }
    });

    // Warn on click if dangerous
    link.addEventListener('click', (e) => {
      const href = link.href;
      if (!href) return;
      chrome.runtime.sendMessage({ type: 'HOVER_LINK', url: href }, (response) => {
        if (response && response.result && response.result.verdict === 'DANGEROUS') {
          e.preventDefault();
          chrome.runtime.sendMessage({ type: 'BLOCKED_CLICK' });
          showInlineWarning(link, response.result, href);
        }
      });
    });
  }

  // ── Inline click-block warning ────────────────────────────────
  function showInlineWarning(link, result, url) {
    const existing = document.getElementById('pg-click-warning');
    if (existing) existing.remove();

    const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();
    const topFlags = result.flags.slice(0, 3).map(f => typeof f === 'object' ? f.text : f);

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
          ${topFlags.map(f => `<div class="pg-cw-flag">• ${escHtml(f)}</div>`).join('')}
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

  // ── Full page danger overlay ───────────────────────────────────
  function showDangerPageOverlay(result) {
    if (warningOverlayShown) return;
    warningOverlayShown = true;

    const domain = (() => { try { return new URL(result.url).hostname; } catch { return result.url; } })();
    const flags = result.flags.slice(0, 5).map(f => typeof f === 'object' ? f.text : f);

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
          ${flags.map(f => `<div class="pg-ov-flag">🔴 ${escHtml(f)}</div>`).join('')}
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

  // ── XSS-safe HTML escape ─────────────────────────────────────
  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Observe DOM for dynamically added links ───────────────────
  function observeLinks() {
    const observer = new MutationObserver(() => {
      document.querySelectorAll('a[href]').forEach(attachLinkHover);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    document.querySelectorAll('a[href]').forEach(attachLinkHover);
  }

  // ── Message listener ─────────────────────────────────────────
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'REQUEST_PAGE_DATA') {
      sendResponse(extractPageData());
      runPageScan();
      return true;
    }

    if (message.type === 'SHOW_WARNING') {
      showDangerPageOverlay(message.result);
    }
  });

  // ── Init ─────────────────────────────────────────────────────
  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        observeLinks();
        runPageScan();
      });
    } else {
      observeLinks();
      runPageScan();
    }
  }

  init();
})();
