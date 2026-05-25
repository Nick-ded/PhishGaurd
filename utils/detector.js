// ============================================================
// PhishGuard — Core Detection Engine
// utils/detector.js
// ============================================================

const PhishGuardDetector = (() => {
  const THRESHOLDS = Object.freeze({
    SAFE: 71,
    SUSPICIOUS: 45
  });

  const SUSPICIOUS_TLDS = [
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
    '.click', '.link', '.online', '.site', '.website', '.space',
    '.loan', '.work', '.party', '.review', '.win', '.bid',
    '.stream', '.download', '.racing', '.accountant', '.science'
  ];

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

  const DEMO_DANGEROUS_HOSTS = new Set([
    'meow-rho-two.vercel.app'
  ]);

  const DEMO_SUSPICIOUS_PATTERNS = [
    { host: 'netmirror.gg', pathPrefix: '/2/en' }
  ];

  const IMPERSONATED_BRANDS = {
    paytm: 'paytm.com',
    phonepe: 'phonepe.com',
    gpay: 'gpay.app',
    sbi: 'sbi.co.in',
    hdfc: 'hdfcbank.com',
    icici: 'icicibank.com',
    axis: 'axisbank.com',
    kotak: 'kotak.com',
    uidai: 'uidai.gov.in',
    aadhar: 'uidai.gov.in',
    irctc: 'irctc.co.in',
    amazon: 'amazon.in',
    flipkart: 'flipkart.com',
    jio: 'jio.com',
    airtel: 'airtel.in',
    vi: 'myvi.in',
    bsnl: 'bsnl.co.in',
    lic: 'licindia.in',
    epfo: 'epfindia.gov.in',
    itr: 'incometax.gov.in',
    pan: 'incometax.gov.in'
  };

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

  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function getBaseDomain(hostname) {
    const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function getVerdict(trustScore) {
    const score = Number(trustScore || 0);
    if (score >= THRESHOLDS.SAFE) return 'SAFE';
    if (score >= THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS';
    return 'DANGEROUS';
  }

  function finalize(rawRiskScore, heuristics, extras) {
    const trustScore = clamp(100 - Math.round(rawRiskScore || 0), 0, 100);
    const verdict = getVerdict(trustScore);
    return {
      ...extras,
      rawRiskScore: clamp(Math.round(rawRiskScore || 0), 0, 100),
      trustScore,
      score: trustScore,
      verdict,
      heuristics: heuristics.slice(),
      flags: heuristics.slice()
    };
  }

  function analyzeURL(urlString) {
    const heuristics = [];
    let rawRiskScore = 0;

    let url;
    try {
      url = new URL(urlString);
    } catch {
      return finalize(95, ['Invalid URL'], { url: urlString });
    }

    const hostname = url.hostname.toLowerCase();
    const fullURL = url.href.toLowerCase();

    if (DEMO_DANGEROUS_HOSTS.has(hostname)) {
      return finalize(95, ['Demo dangerous link', 'Sample danger override'], { url: url.href });
    }

    const suspiciousDemo = DEMO_SUSPICIOUS_PATTERNS.find((pattern) => {
      return hostname === pattern.host && url.pathname.startsWith(pattern.pathPrefix);
    });
    if (suspiciousDemo) {
      return finalize(65, ['Demo suspicious link', 'Sample suspicious override'], { url: url.href });
    }

    const baseDomain = getBaseDomain(hostname);
    if (TRUSTED_DOMAINS.has(baseDomain)) {
      return finalize(0, ['Trusted domain'], { url: url.href, trusted: true });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      rawRiskScore += 40;
      heuristics.push('Raw IP address');
    }

    if (hostname.includes('xn--')) {
      rawRiskScore += 35;
      heuristics.push('Punycode domain');
    }

    const tld = '.' + (hostname.split('.').pop() || '');
    if (SUSPICIOUS_TLDS.includes(tld)) {
      rawRiskScore += 25;
      heuristics.push('Suspicious TLD');
    }

    for (const [brand, legitimateDomain] of Object.entries(IMPERSONATED_BRANDS)) {
      if (hostname.includes(brand) && !hostname.endsWith(legitimateDomain)) {
        rawRiskScore += 40;
        heuristics.push('Brand impersonation');
        break;
      }
    }

    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      rawRiskScore += 20;
      heuristics.push('Deep subdomains');
    }

    const suspiciousTokens = [
      'login', 'signin', 'verify', 'secure', 'update', 'confirm',
      'account', 'banking', 'payment', 'wallet', 'kyc', 'otp',
      'support', 'helpdesk', 'refund', 'claim', 'reward', 'free',
      'winner', 'lucky', 'prize', 'offer'
    ];
    const foundTokens = suspiciousTokens.filter((token) => hostname.includes(token));
    if (foundTokens.length > 0) {
      rawRiskScore += Math.min(foundTokens.length * 10, 30);
      heuristics.push('Suspicious keywords');
    }

    if (url.protocol === 'http:') {
      rawRiskScore += 20;
      heuristics.push('HTTP only');
    }

    if (url.href.length > 200) {
      rawRiskScore += 15;
      heuristics.push('Long URL');
    }

    if (['redirect', 'url=', 'next=', 'return=', 'goto='].some((part) => fullURL.includes(part))) {
      rawRiskScore += 20;
      heuristics.push('Redirect params');
    }

    if (url.href.includes('@')) {
      rawRiskScore += 35;
      heuristics.push('Credential injection');
    }

    if (/^\d+\.\d+\.\d+$/.test(hostname.replace(/\.[a-z]+$/, ''))) {
      rawRiskScore += 30;
      heuristics.push('Numeric domain');
    }

    const freeHosting = ['blogspot', 'wordpress', 'weebly', 'wixsite', 'sites.google'];
    const usedFreeHost = freeHosting.find((value) => hostname.includes(value));
    if (usedFreeHost) {
      rawRiskScore += 15;
      heuristics.push('Free hosting');
    }

    return finalize(rawRiskScore, heuristics, { url: url.href });
  }

  function analyzePage(pageData) {
    const heuristics = [];
    let rawRiskScore = 0;

    const bodyText = String(pageData?.bodyText || pageData?.text || '').toLowerCase();
    const title = String(pageData?.title || '').toLowerCase();
    const forms = Array.isArray(pageData?.forms) ? pageData.forms : [];
    const combined = `${bodyText} ${title}`;

    for (const phrase of PHISHING_KEYWORDS_EN) {
      if (combined.includes(phrase)) {
        rawRiskScore += 15;
        heuristics.push('Phishing phrase');
        if (heuristics.length >= 5) break;
      }
    }

    for (const phrase of PHISHING_KEYWORDS_HI) {
      if (combined.includes(phrase)) {
        rawRiskScore += 20;
        heuristics.push('Hindi scam phrase');
        if (heuristics.length >= 8) break;
      }
    }

    if (/\d+\s*(minutes?|mins?|seconds?|hours?|घंटे|मिनट)/.test(combined)) {
      if (combined.includes('expir') || combined.includes('frozen') || combined.includes('block') || combined.includes('suspend') || combined.includes('बंद') || combined.includes('बंद हो')) {
        rawRiskScore += 25;
        heuristics.push('Urgency timer');
      }
    }

    const sensitiveFormFields = forms.filter((value) => /otp|pin|password|card.?number|cvv|account.?number|ifsc|upi/.test(String(value).toLowerCase()));
    if (sensitiveFormFields.length > 0) {
      rawRiskScore += 20;
      heuristics.push('Sensitive form field');
    }

    if (/aadhar|aadhaar|uidai|pan\s*number|pan\s*card/.test(combined)) {
      rawRiskScore += 15;
      heuristics.push('Aadhaar/PAN request');
    }

    if (/gov(ernment)?|official|authoriz|certified|ministry|मंत्रालय|सरकार/.test(combined)) {
      if (!pageData?.isLikelyLegitGov) {
        rawRiskScore += 10;
        heuristics.push('Official claims');
      }
    }

    return finalize(rawRiskScore, heuristics, { url: pageData?.url || '' });
  }

  return {
    analyzeURL,
    analyzePage,
    getVerdict,
    getBaseDomain,
    TRUSTED_DOMAINS,
    THRESHOLDS
  };
})();

if (typeof module !== 'undefined') module.exports = PhishGuardDetector;
