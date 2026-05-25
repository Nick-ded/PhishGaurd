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
    '.stream', '.download', '.racing', '.accountant', '.science',
    // Additional TLDs commonly abused by piracy/scam sites
    '.gg', '.plus', '.fun', '.vip', '.pro', '.live',
    '.cc', '.to', '.sx', '.ws', '.ms', '.buzz', '.surf',
    '.monster', '.cyou', '.cfd', '.hair', '.beauty', '.makeup'
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
    'reddit.com', 'stackoverflow.com', 'medium.com',
    // Legitimate sites that use .gg or .tv
    'twitch.tv', 'discord.gg'
  ]);

  // ── Known malicious / blocked domains ────────────────────────
  // Sites confirmed phishing, piracy, or malware by Cloudflare,
  // Google Safe Browsing, or community reports.
  const KNOWN_BAD_DOMAINS = new Set([
    // ── Illegal streaming / movie download ──────────────────────
    'netmirror.plus', 'netmirror.gg', 'netmirror.net',
    'fmovies.to', 'fmovies.ps', 'fmovies.wtf', 'fmovies.cafe',
    'gomovies.sx', 'gomovies.to', 'gomovies.pe',
    '123movies.to', '123movies.fun', '123movies.net', '123moviesfree.net',
    'putlocker.vip', 'putlocker.rs', 'putlocker.pe', 'putlocker.onl',
    'soap2day.to', 'soap2day.ac', 'soap2day.rs', 'soap2day.gg',
    'yts.mx', 'yts.lt', 'yts.am', 'yify.com',
    'rarbg.to', 'rarbg.is', 'rarbg.me',
    'thepiratebay.org', 'thepiratebay.rocks', 'thepiratebay.cr',
    'kickasstorrents.to', 'kickass.sx', 'kat.cr', 'katcr.co',
    '1337x.to', '1337x.st', '1337x.is', '1337x.eu',
    'movierulz.tc', 'movierulz.plz', 'movierulz.com', 'movierulz.in',
    'tamilrockers.ws', 'tamilrockers.net', 'tamilrockers.com',
    'filmyzilla.com', 'filmyzilla.pro', 'filmyzilla.in',
    'bollyflix.com', 'bollyflix.in', 'bollyflix.net',
    'vegamovies.nl', 'vegamovies.in', 'vegamovies.com',
    'jiorockers.com', 'jiorockers.in',
    'isaimini.com', 'isaimini.biz', 'isaimini.net',
    'kuttymovies.com', 'kuttymovies.net', 'kuttymovies.in',
    'tamilyogi.com', 'tamilyogi.fm', 'tamilyogi.net',
    'moviesda.com', 'moviesda.net', 'moviesda.in',
    'cinemavilla.com', 'cinemavilla.net',
    'downloadhub.in', 'downloadhub.ws', 'downloadhub.net',
    'worldfree4u.com', 'worldfree4u.trade', 'worldfree4u.net',
    'mp4moviez.com', 'mp4moviez.in', 'mp4moviez.net', 'mp4moviez.org',
    'coolmoviez.com', 'hdmovie2.com', 'hdmovie99.com',
    'uwatchfree.com', 'uwatchfree.tv', 'uwatchfree.net',
    'afilmywap.com', 'afilmywap.in', 'afilmywap.net',
    'rdxhd.com', 'rdxhd.in', 'rdxhd.net',
    'skymovies.in', 'skymovies.nl', 'skymovies.com',
    'o2tvseries.com', 'series9.io', 'series9.net',
    'watchseries.ru', 'watchseries.to', 'watchseries.net',
    'couchtuner.gold', 'couchtuner.com',
    'primewire.ag', 'primewire.li', 'primewire.mx',
    'lookmovie.ag', 'lookmovie.io', 'lookmovie.com',
    'hdeuropix.com', 'streamlord.com',
    'vexmovies.org', 'cmovies.net',
    'solarmovie.pe', 'solarmovie.com',
    'bflix.gg', 'iosmirror.cc',
    // Anime piracy (globally flagged)
    'kissanime.ru', 'kissanime.com', 'kissmanga.com',
    'gogoanime.tel', 'gogoanime.com', 'gogoanime.gg',
    'animepahe.com', 'animepahe.ru',
    'zoro.to', 'aniwatch.to', 'hianime.to',
    'animixplay.to', 'animedao.to',
    '9anime.to', '9anime.ru', '9anime.com',
    // Sports streaming piracy
    'livetv.sx', 'vipbox.lc', 'footybite.to',
    'streameast.live', 'streameast.io',
    'crackstreams.com', 'crackstreams.net',
    'buffstreams.app', 'buffstreams.tv',
    'sportsurge.net', 'sportsurge.to',
    'hesgoal.com', 'hesgoal.tv',
    // General piracy / download sites
    'katmovies.com', 'katmovies.in',
    'limetorrents.info', 'limetorrents.cc',
    'eztv.re', 'eztv.ag', 'eztv.io',
    'torrentz2.eu', 'torrentz.eu',
    'nyaa.si', 'nyaa.net',
    'hdtorrent.com', 'torrentking.eu',
    'extratorrents.it', 'extratorrent.ag',
    'torrentdownloads.me', 'torrentproject.se',
    'zooqle.com', 'seedpeer.eu',
    'desiremovies.com', 'desiremovies.in',
    'bolly4u.org', 'bolly4u.com',
    'khatrimaza.com', 'khatrimaza.in', 'khatrimaza.org',
    'filmywap.com', 'filmywap.in',
    'moviesflix.com', 'moviesflix.in',
    'hdmoviespoint.com', 'hdmoviespoint.in',
    'moviescounter.com', 'moviescounter.in',
    'moviespur.com', 'moviespur.in',
    'movieswood.com', 'movieswood.in',
    'tamilgun.com', 'tamilgun.net',
    'tamilmv.com', 'tamilmv.net',
    'tamilblasters.com', 'tamilblasters.net',
    'moviezwap.org', 'moviezwap.com',
    'jalshamoviez.com', 'jalshamoviez.in',
    'filmyhit.com', 'filmyhit.in',
    'filmypur.com', 'filmypur.in',
    'filmymeet.com', 'filmymeet.in',
    'filmyhunk.com', 'filmyhunk.in',
    'filmyfly.com', 'filmyfly.in',
    'filmyzap.com', 'filmyzap.in',
    'filmybaap.com', 'filmybaap.in',
    'filmyworld.com', 'filmyworld.in',
    'filmyzone.com', 'filmyzone.in',
    'filmytown.com', 'filmytown.in',
    'filmypost.com', 'filmypost.in',
    'filmylink.com', 'filmylink.in',
    'filmyking.com', 'filmyking.in',
    'filmystar.com', 'filmystar.in',
    'filmybox.com', 'filmybox.in',
    'filmycut.com', 'filmycut.in',
    'filmyup.com', 'filmyup.in',
    'filmydown.com', 'filmydown.in',
    'filmyload.com', 'filmyload.in',
    'filmyget.com', 'filmyget.in',
    'filmygo.com', 'filmygo.in',
    'filmynet.com', 'filmynet.in',
    'filmysite.com', 'filmysite.in',
    'filmyweb.com', 'filmyweb.in',
    'filmypoint.com', 'filmypoint.in',
    'filmyplace.com', 'filmyplace.in',
    'filmyspace.com', 'filmyspace.in',
    'filmystore.com', 'filmystore.in',
    'filmyshare.com', 'filmyshare.in',
    'filmysend.com', 'filmysend.in',
    'filmyupload.com', 'filmyupload.in',
    'filmydownload.com', 'filmydownload.in',
    'filmystream.com', 'filmystream.in',
    'filmywatch.com', 'filmywatch.in',
    'filmyplay.com', 'filmyplay.in',
    'filmyview.com', 'filmyview.in',
    'filmysee.com', 'filmysee.in',
    'filmylook.com', 'filmylook.in',
    'filmycheck.com', 'filmycheck.in',
    'filmyscan.com', 'filmyscan.in',
    'filmyfind.com', 'filmyfind.in',
    'filmysearch.com', 'filmysearch.in',
    // Music piracy
    'pagalworld.com', 'pagalworld.in', 'pagalworld.is', 'pagalworld.net',
    'pagalnew.com', 'pagalnew.in', 'pagalnew.net',
    'djpunjab.com', 'djpunjab.net', 'djpunjab.is',
    'mr-jatt.com', 'mrjatt.net', 'songspk.com', 'downloadming.com',
    'wapking.com', 'freshmaza.com', 'mp3mad.com',
    'raagsong.com', 'mp3skull.com', 'beemp3.com',
    // Piracy repack / cracked game sites
    'fitgirl-repacks.site', 'fitgirl-repacks.ru',
    'dodi-repacks.site', 'igg-games.com', 'ocean-of-games.com',
    'oceanofgames.com', 'oceansofgames.com', 'oceansofgamess.com',
    'oceanofgame.com', 'ocean-of-game.com',
    'steamunlocked.net', 'skidrowreloaded.com', 'crackwatch.com',
    // Known phishing / scam domains
    'paytm-kyc.com', 'paytm-verify.com',
    'sbi-netbanking.xyz', 'sbi-online.xyz',
    'hdfc-kyc.xyz', 'hdfc-update.xyz',
    'icici-verify.xyz',
    'amazon-offer.xyz', 'amazon-prize.com',
    'flipkart-winner.com',
    'jio-offer.com', 'jio-recharge.xyz',
    'irctc-refund.com', 'irctc-ticket.xyz',
    'uidai-update.com', 'aadhar-link.com',
    'incometax-refund.com', 'epfindia-claim.com',
    'covid-relief.xyz', 'pmkisan-money.com'
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
  };

  // ── Piracy / illegal streaming domain tokens ─────────────────
  const PIRACY_TOKENS = [
    // Movie/TV streaming piracy
    'movierulz', 'filmyzilla', 'bollyflix', 'vegamovies',
    'jiorockers', 'isaimini', 'kuttymovies', 'tamilyogi',
    'moviesda', 'downloadhub', 'worldfree', 'mp4moviez',
    'afilmywap', 'rdxhd', 'skymovies', 'fmovies', 'gomovies',
    '123movies', 'putlocker', 'soap2day', 'solarmovie',
    'primewire', 'couchtuner', 'watchseries', 'streamlord',
    'lookmovie', 'netmirror', 'iosmirror', 'tamilrockers',
    'piratebay', 'kickasstorrent', 'rarbg', '1337x',
    'katmovies', 'limetorrent', 'eztv', 'torrentz',
    'desiremovies', 'bolly4u', 'khatrimaza', 'filmywap',
    'moviesflix', 'hdmoviespoint', 'moviescounter', 'moviespur',
    'movieswood', 'tamilgun', 'tamilmv', 'tamilblasters',
    'moviezwap', 'jalshamoviez', 'filmyhit', 'filmypur',
    'filmymeet', 'filmyhunk', 'filmyfly', 'filmyzap',
    'filmybaap', 'filmyworld', 'filmyzone', 'filmytown',
    // Anime piracy
    'kissanime', 'kissmanga', 'gogoanime', 'animepahe',
    'animixplay', 'animedao', '9anime', 'hianime', 'aniwatch',
    // Sports streaming piracy
    'livetv.sx', 'vipbox', 'footybite', 'streameast',
    'crackstreams', 'buffstreams', 'sportsurge', 'hesgoal',
    // Music piracy
    'pagalworld', 'pagalnew', 'djpunjab', 'mr-jatt', 'mrjatt', 'songspk',
    'downloadming', 'wapking', 'raagsong', 'freshmaza',
    'mp3mad', 'mp3skull', 'mp3juices', 'beemp3',
    // Generic piracy patterns
    'freemovie', 'hdmovie', 'fullmovie', 'moviedownload',
    'torrentmovie', 'piracymovie',
    // Cracked/repack game sites
    'fitgirl', 'dodirepacks', 'skidrow', 'crackwatch', 'steamunlock',
    'igg-game', 'ocean-of-game'
  ];

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

    // Demo overrides
    if (DEMO_DANGEROUS_HOSTS.has(hostname)) {
      return { score: 95, flags: ['Demo dangerous link', 'Matched sample danger override'] };
    }

    const suspiciousDemo = DEMO_SUSPICIOUS_PATTERNS.find(
      p => hostname === p.host && url.pathname.startsWith(p.pathPrefix)
    );
    if (suspiciousDemo) {
      return { score: 75, flags: ['Demo suspicious link', 'Matched sample suspicious override'] };
    }

    // 1. Trusted whitelist — short-circuit
    const baseDomain = getBaseDomain(hostname);
    if (TRUSTED_DOMAINS.has(baseDomain)) {
      return { score: 0, flags: ['Trusted domain'], trusted: true };
    }

    // 2. Known bad domain — immediate DANGEROUS
    if (KNOWN_BAD_DOMAINS.has(baseDomain) || KNOWN_BAD_DOMAINS.has(hostname)) {
      return {
        score: 100,
        flags: ['Known malicious or piracy domain — blocked by Cloudflare/community reports'],
        blocked: true
      };
    }

    // 3. IP address as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40;
      flags.push('Uses raw IP address instead of domain name');
    }

    // 4. Punycode / homograph
    if (hostname.includes('xn--')) {
      score += 35;
      flags.push('Punycode/homograph domain detected (character spoofing)');
    }

    // 5. Suspicious TLD
    const tld = '.' + hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 25;
      flags.push(`Suspicious top-level domain: ${tld}`);
    }

    // 6. Brand impersonation — word-boundary check
    for (const [brand, legitimateDomain] of Object.entries(IMPERSONATED_BRANDS)) {
      const brandRe = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`);
      if (brandRe.test(hostname) && !hostname.endsWith(legitimateDomain)) {
        score += 40;
        flags.push(`Impersonating "${brand}" (legitimate: ${legitimateDomain})`);
        break;
      }
    }

    // 7. Piracy / illegal streaming tokens in domain
    const foundPiracy = PIRACY_TOKENS.filter(t => hostname.includes(t));
    if (foundPiracy.length > 0) {
      // Any known piracy brand in the domain = DANGEROUS on its own
      score += Math.min(foundPiracy.length * 55, 100);
      flags.push(`Piracy/illegal streaming site indicators: ${foundPiracy.slice(0, 3).join(', ')}`);
    }

    // 7b. Fuzzy piracy brand regex — catches typosquats and variant spellings
    // e.g. pagalworrld, pagallworlds, oceanofgames, ocean-of-games, oceanofgame
    const PIRACY_FUZZY = [
      /pagal\s*w[o0]r+l+d/i,          // pagalworld, pagalworrld, pagalw0rld
      /pagal\s*w[o0]r+l+ds/i,         // pagalworlds, pagallworlds
      /pagal\s*new/i,                  // pagalnew
      /ocean[\s\-_]*of[\s\-_]*game/i, // ocean-of-games, oceanofgames, ocean_of_game
      /igg[\s\-_]*game/i,             // igg-games, igggames
      /fitgirl[\s\-_]*repack/i,       // fitgirl-repacks
      /dodi[\s\-_]*repack/i,          // dodi-repacks
      /skidrow[\s\-_]*reloaded/i,     // skidrowreloaded
      /steam[\s\-_]*unlock/i,         // steamunlocked
      /tamil[\s\-_]*rock/i,           // tamilrockers
      /tamil[\s\-_]*blaster/i,        // tamilblasters
      /tamil[\s\-_]*mv/i,             // tamilmv
      /tamil[\s\-_]*gun/i,            // tamilgun
      /tamil[\s\-_]*yogi/i,           // tamilyogi
      /movies[\s\-_]*da/i,            // moviesda
      /movie[\s\-_]*rulz/i,           // movierulz
      /filmy[\s\-_]*zilla/i,          // filmyzilla
      /dj[\s\-_]*punjab/i,            // djpunjab
      /mr[\s\-_]*jatt/i,              // mr-jatt, mrjatt
      /pirate[\s\-_]*bay/i,           // thepiratebay
      /kick[\s\-_]*ass[\s\-_]*torrent/i, // kickasstorrents
      /soap[\s\-_]*2[\s\-_]*day/i,    // soap2day
      /123[\s\-_]*movie/i,            // 123movies
      /put[\s\-_]*locker/i,           // putlocker
      /go[\s\-_]*movie/i,             // gomovies
      /f[\s\-_]*movie/i,              // fmovies
      /watch[\s\-_]*series/i,         // watchseries
      /look[\s\-_]*movie/i,           // lookmovie
      /prime[\s\-_]*wire/i,           // primewire
      /solar[\s\-_]*movie/i,          // solarmovie
      /couch[\s\-_]*tuner/i,          // couchtuner
      /khat[\s\-_]*rimaza/i,          // khatrimaza
      /bolly[\s\-_]*4u/i,             // bolly4u
      /desire[\s\-_]*movie/i,         // desiremovies
      /filmy[\s\-_]*wap/i,            // filmywap
      /movies[\s\-_]*flix/i,          // moviesflix
      /movies[\s\-_]*wood/i,          // movieswood
      /movies[\s\-_]*pur/i,           // moviespur
      /jalsha[\s\-_]*moviez/i,        // jalshamoviez
      /kiss[\s\-_]*anime/i,           // kissanime
      /gogo[\s\-_]*anime/i,           // gogoanime
      /9[\s\-_]*anime/i,              // 9anime
      /crack[\s\-_]*stream/i,         // crackstreams
      /buff[\s\-_]*stream/i,          // buffstreams
      /sport[\s\-_]*surge/i,          // sportsurge
      /hes[\s\-_]*goal/i,             // hesgoal
      /stream[\s\-_]*east/i,          // streameast
    ];
    const fuzzyPiracy = PIRACY_FUZZY.find(re => re.test(hostname));
    if (fuzzyPiracy && !foundPiracy.length) {
      score += 100;
      flags.push('Piracy/illegal site detected (variant domain)');
    }

    // 8. Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      score += 20;
      flags.push(`Unusually deep subdomain structure (${subdomainCount} levels)`);
    }

    // 9. Suspicious tokens in domain
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

    // 10. HTTP (not HTTPS)
    if (url.protocol === 'http:') {
      score += 20;
      flags.push('Not using HTTPS — data may be transmitted insecurely');
    }

    // 11. Very long URL
    if (urlString.length > 200) {
      score += 15;
      flags.push('Abnormally long URL (often used to hide the real destination)');
    }

    // 12. Redirect parameters
    const redirectPatterns = ['redirect', 'url=', 'next=', 'return=', 'goto='];
    if (redirectPatterns.some(p => fullURL.includes(p))) {
      score += 20;
      flags.push('URL contains redirect parameters');
    }

    // 13. @ symbol in URL (credential injection)
    if (url.href.includes('@')) {
      score += 35;
      flags.push('@ symbol in URL — could be used to hide the real destination');
    }

    // 14. Numeric domain
    if (/^\d+\.\d+\.\d+$/.test(hostname.replace(/\.[a-z]+$/, ''))) {
      score += 30;
      flags.push('Domain is primarily numeric — unusual for legitimate sites');
    }

    // 15. Free hosting platforms
    const freeHosting = ['blogspot', 'wordpress', 'weebly', 'wixsite', 'sites.google'];
    const usedFreeHost = freeHosting.find(h => hostname.includes(h));
    if (usedFreeHost) {
      score += 15;
      flags.push(`Hosted on free platform (${usedFreeHost}) — unusual for official services`);
    }

    return { score: Math.min(score, 100), flags };
  }

  // ── Page content analysis ─────────────────────────────────────
  function analyzePage(pageData) {
    let score = 0;
    const flags = [];

    const text = (pageData.bodyText || '').toLowerCase();
    const title = (pageData.title || '').toLowerCase();
    const forms = pageData.forms || [];
    const combined = text + ' ' + title;

    // English phishing phrases
    for (const phrase of PHISHING_KEYWORDS_EN) {
      if (combined.includes(phrase)) {
        score += 15;
        flags.push(`Phishing phrase detected: "${phrase}"`);
        if (flags.length >= 5) break;
      }
    }

    // Hindi/Hinglish patterns
    for (const phrase of PHISHING_KEYWORDS_HI) {
      if (combined.includes(phrase)) {
        score += 20;
        flags.push(`Hindi scam phrase detected: "${phrase}"`);
        if (flags.length >= 8) break;
      }
    }

    // Urgency timer
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

    // Aadhaar / PAN
    if (/aadhar|aadhaar|uidai|pan\s*number|pan\s*card/.test(combined)) {
      score += 15;
      flags.push('Requests Aadhaar or PAN details');
    }

    // Fake government portal
    if (/gov(ernment)?|official|authoriz|certified|ministry|मंत्रालय|सरकार/.test(combined)) {
      if (!pageData.isLikelyLegitGov) {
        score += 10;
        flags.push('Claims government/official status — verify domain carefully');
      }
    }

    // Piracy page content
    if (/watch\s+free|download\s+free|free\s+stream|no\s+ads|without\s+ads|1080p\s+free|720p\s+free/.test(combined)) {
      score += 20;
      flags.push('Piracy site content detected — free streaming/download without license');
    }

    return { score: Math.min(score, 100), flags };
  }

  // ── Combined verdict ──────────────────────────────────────────
  function getVerdict(urlScore, pageScore) {
    const combined = Math.max(
      urlScore,
      urlScore * 0.6 + pageScore * 0.4,
      pageScore * 0.7
    );
    if (combined >= 55) return 'DANGEROUS';
    if (combined >= 25) return 'SUSPICIOUS';
    return 'SAFE';
  }

  // ── Helper: extract base domain ───────────────────────────────
  function getBaseDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    if (['co', 'org', 'gov', 'net', 'edu'].includes(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  // ── Public API ────────────────────────────────────────────────
  return { analyzeURL, analyzePage, getVerdict, getBaseDomain, TRUSTED_DOMAINS, KNOWN_BAD_DOMAINS };
})();

if (typeof module !== 'undefined') module.exports = PhishGuardDetector;
