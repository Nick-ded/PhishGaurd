// ============================================================
// PhishGuard — Core Detection Engine
// utils/detector.js
// ============================================================

const PhishGuardDetector = (() => {

  // ── Suspicious TLD patterns ──────────────────────────────────
  const SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
    '.click', '.link', '.online', '.site', '.website', '.space',
    '.loan', '.work', '.party', '.review', '.win', '.bid',
    '.stream', '.download', '.racing', '.accountant', '.science'
  ];

  // ── Known trusted domains (whitelist) ────────────────────────
  const TRUSTED_DOMAINS = new Set([
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'wikipedia.org',
    'amazon.com', 'amazon.in', 'flipkart.com', 'paytm.com',
    'phonepe.com', 'gpay.app', 'bhimupi.org.in', 'npci.org.in',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'kotak.com', 'yesbank.in', 'punjabsindbank.com',
    'incometax.gov.in', 'uidai.gov.in', 'india.gov.in',
    'mca.gov.in', 'irctc.co.in', 'indiapost.gov.in',
    'anthropic.com', 'openai.com', 'microsoft.com', 'apple.com',
    'reddit.com', 'stackoverflow.com', 'medium.com'
  ]);

  // ── Demo overrides for sample links ───────────────────────────
  const DEMO_DANGEROUS_HOSTS = new Set([
    'meow-rho-two.vercel.app'
  ]);

  const DEMO_SUSPICIOUS_PATTERNS = [
    { host: 'netmirror.gg', pathPrefix: '/2/en' }
  ];

  // ── Brands commonly impersonated in India ────────────────────
  const IMPERSONATED_BRANDS = {
    'paytm':    'paytm.com',
    'phonepe':  'phonepe.com',
    'gpay':     'gpay.app',
    'sbi':      'sbi.co.in',
    'hdfc':     'hdfcbank.com',
    'icici':    'icicibank.com',
    'kotak':    'kotak.com',
    'uidai':    'uidai.gov.in',
    'aadhar':   'uidai.gov.in',
    'aadhaar':  'uidai.gov.in',
    'irctc':    'irctc.co.in',
    'amazon':   'amazon.in',
    'flipkart': 'flipkart.com',
    'jio':      'jio.com',
    'airtel':   'airtel.in',
    'bsnl':     'bsnl.co.in',
    'epfo':     'epfindia.gov.in',
    'paypal':   'paypal.com',
    'netflix':  'netflix.com',
    'microsoft':'microsoft.com',
    'apple':    'apple.com'
    // Removed: 'vi', 'axis', 'lic', 'itr', 'pan', 'google'
    // — too short / common substrings causing false positives
    // (e.g. 'pan' matches japan/spain, 'vi' matches video/visit,
    //  'axis' matches maximus, 'lic' matches police/public)
  };

  // ── English phishing keywords ─────────────────────────────────
  const PHISHING_KEYWORDS_EN = [
    'verify your account', 'account suspended', 'account blocked',
    'account will be closed', 'click here to verify', 'confirm your identity',
    'update your kyc', 'complete your kyc', 'kyc pending', 'kyc expired',
    'enter your otp', 'share your otp', 'otp required',
    'enter your pin', 'enter your upi pin', 'upi verification',
    'claim your reward', 'you have won', 'congratulations you won',
    'free recharge', 'lucky winner', 'redeem now',
    'refund pending', 'refund failed', 'delivery failed',
    'parcel held', 'customs fee', 'pay customs',
    'limited time offer', 'act now', 'expires in',
    'account will be frozen', 'frozen in 24 hours',
    'urgent action required', 'immediate action',
    'click to unlock', 'unlock your account'
  ];

  // ── Hindi & Hinglish phishing patterns ───────────────────────
  const PHISHING_KEYWORDS_HI = [
    'otp do', 'otp share karo', 'otp bhejo', 'apna otp batao',
    'upi pin', 'pin daliye', 'pin share karein',
    'kyc karo', 'kyc update karo', 'kyc band ho jayega',
    'account band ho jayega', 'account block ho jayega',
    'verify karo', 'abhi verify karein',
    'inaam jeeta', 'lucky winner', 'inam jeet liya',
    'paisa wapas', 'refund le', 'paise wapas milenge',
    'free recharge milega', 'data pack free',
    'aadhar update', 'pan update', 'link aadhar',
    'apka account', 'turant karein', 'jaldi karein',
    'समय सीमा', 'खाता बंद', 'केवाईसी', 'ओटीपी'
  ];

  // ── URL feature scoring ───────────────────────────────────────
  function analyzeURL(urlString) {
    let score = 0;
    const flags = [];

    let url;
    try {
      url = new URL(urlString);
    } catch {
      return { score: 90, flags: ['Invalid or malformed URL'] };
    }

    const hostname = url.hostname.toLowerCase();
    const fullURL = urlString.toLowerCase();

    if (DEMO_DANGEROUS_HOSTS.has(hostname)) {
      return {
        score: 95,
        flags: ['Demo dangerous link', 'Matched sample danger override']
      };
    }

    const suspiciousDemo = DEMO_SUSPICIOUS_PATTERNS.find((pattern) => {
      return hostname === pattern.host && url.pathname.startsWith(pattern.pathPrefix);
    });

    if (suspiciousDemo) {
      return {
        score: 75,
        flags: ['Demo suspicious link', 'Matched sample suspicious override']
      };
    }

    // 1. Check if in trusted list
    const baseDomain = getBaseDomain(hostname);
    if (TRUSTED_DOMAINS.has(baseDomain)) {
      return { score: 0, flags: ['Trusted domain'], trusted: true };
    }

    // 2. IP address as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40;
      flags.push('Uses raw IP address instead of domain name');
    }

    // 3. Punycode / homograph
    if (hostname.includes('xn--')) {
      score += 35;
      flags.push('Punycode/homograph domain detected (character spoofing)');
    }

    // 4. Suspicious TLD
    const tld = '.' + hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 25;
      flags.push(`Suspicious top-level domain: ${tld}`);
    }

    // 5. Brand impersonation — use word-boundary check to avoid false positives
    // e.g. 'pan' should NOT match 'japan', 'vi' should NOT match 'video'
    for (const [brand, legitimateDomain] of Object.entries(IMPERSONATED_BRANDS)) {
      const brandRe = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`);
      if (brandRe.test(hostname) && !hostname.endsWith(legitimateDomain)) {
        score += 40;
        flags.push(`Impersonating "${brand}" (legitimate: ${legitimateDomain})`);
        break;
      }
    }

    // 6. Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      score += 20;
      flags.push(`Unusually deep subdomain structure (${subdomainCount} levels)`);
    }

    // 7. Suspicious tokens in domain
    const suspiciousTokens = [
      'login', 'signin', 'verify', 'secure', 'update', 'confirm',
      'account', 'banking', 'payment', 'wallet', 'kyc', 'otp',
      'support', 'helpdesk', 'refund', 'claim', 'reward', 'free',
      'winner', 'lucky', 'prize', 'offer'
    ];
    const foundTokens = suspiciousTokens.filter(t => hostname.includes(t));
    if (foundTokens.length > 0) {
      score += Math.min(foundTokens.length * 10, 30);
      flags.push(`Suspicious keywords in domain: ${foundTokens.join(', ')}`);
    }

    // 8. HTTP (not HTTPS)
    if (url.protocol === 'http:') {
      score += 20;
      flags.push('Not using HTTPS — data may be transmitted insecurely');
    }

    // 9. Very long URL
    if (urlString.length > 200) {
      score += 15;
      flags.push('Abnormally long URL (often used to hide the real destination)');
    }

    // 10. Multiple redirects in URL params
    const redirectPatterns = ['redirect', 'url=', 'next=', 'return=', 'goto='];
    if (redirectPatterns.some(p => fullURL.includes(p))) {
      score += 20;
      flags.push('URL contains redirect parameters');
    }

    // 11. @ symbol in URL (credential injection)
    if (url.href.includes('@')) {
      score += 35;
      flags.push('@ symbol in URL — could be used to hide the real destination');
    }

    // 12. Numeric domain
    if (/^\d+\.\d+\.\d+$/.test(hostname.replace(/\.[a-z]+$/, ''))) {
      score += 30;
      flags.push('Domain is primarily numeric — unusual for legitimate sites');
    }

    // 13. Free hosting platforms
    const freeHosting = ['blogspot', 'wordpress', 'weebly', 'wixsite', 'sites.google'];
    const usedFreeHost = freeHosting.find(h => hostname.includes(h));
    if (usedFreeHost) {
      score += 15;
      flags.push(`Hosted on free platform (${usedFreeHost}) — unusual for official services`);
    }

    return { score: Math.min(score, 100), flags };
  }

  // ── Page content analysis ──────────────────────────────────────
  function analyzePage(pageData) {
    let score = 0;
    const flags = [];

    const text = (pageData.bodyText || '').toLowerCase();
    const title = (pageData.title || '').toLowerCase();
    const forms = pageData.forms || [];
    const combined = text + ' ' + title;

    // Check English phishing phrases
    for (const phrase of PHISHING_KEYWORDS_EN) {
      if (combined.includes(phrase)) {
        score += 15;
        flags.push(`Phishing phrase detected: "${phrase}"`);
        if (flags.length >= 5) break;
      }
    }

    // Check Hindi/Hinglish patterns
    for (const phrase of PHISHING_KEYWORDS_HI) {
      if (combined.includes(phrase)) {
        score += 20;
        flags.push(`Hindi scam phrase detected: "${phrase}"`);
        if (flags.length >= 8) break;
      }
    }

    // Urgency timer/countdown
    if (/\d+\s*(minutes?|mins?|seconds?|hours?|घंटे|मिनट)/.test(combined)) {
      if (combined.includes('expir') || combined.includes('frozen') ||
          combined.includes('block') || combined.includes('suspend') ||
          combined.includes('बंद') || combined.includes('बंद हो')) {
        score += 25;
        flags.push('Urgency timer detected — pressure tactic to rush decision');
      }
    }

    // OTP / PIN form fields
    const sensitiveFormFields = forms.filter(f =>
      /otp|pin|password|card.?number|cvv|account.?number|ifsc|upi/.test(f.toLowerCase())
    );
    if (sensitiveFormFields.length > 0) {
      score += 20;
      flags.push(`Requests sensitive data: ${sensitiveFormFields.slice(0, 3).join(', ')}`);
    }

    // Aadhar / PAN number input pattern
    if (/aadhar|aadhaar|uidai|pan\s*number|pan\s*card/.test(combined)) {
      score += 15;
      flags.push('Requests Aadhaar or PAN details');
    }

    // Fake government portal signals
    if (/gov(ernment)?|official|authoriz|certified|ministry|मंत्रालय|सरकार/.test(combined)) {
      if (!pageData.isLikelyLegitGov) {
        score += 10;
        flags.push('Claims government/official status — verify domain carefully');
      }
    }

    return { score: Math.min(score, 100), flags };
  }

  // ── Combined verdict ───────────────────────────────────────────
  function getVerdict(urlScore, pageScore) {
    // URL score is the primary signal.
    // Page score can independently push verdict up — a page full of
    // phishing content on a clean-looking URL is still dangerous.
    const combined = Math.max(
      urlScore,
      urlScore * 0.6 + pageScore * 0.4,
      pageScore * 0.7   // page score alone can reach SUSPICIOUS/DANGEROUS
    );

    if (combined >= 55) return 'DANGEROUS';
    if (combined >= 25) return 'SUSPICIOUS';
    return 'SAFE';
  }

  // ── Helper: extract base domain ───────────────────────────────
  function getBaseDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    // Handle co.in, org.in, etc.
    if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  // ── Public API ─────────────────────────────────────────────────
  return { analyzeURL, analyzePage, getVerdict, getBaseDomain, TRUSTED_DOMAINS };
})();

// Export for use in service worker & content scripts
if (typeof module !== 'undefined') module.exports = PhishGuardDetector;
