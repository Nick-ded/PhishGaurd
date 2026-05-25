# PhishGuard Behavioral Prompt
## User-Centric Safety Strategy for Newbie Internet Users

**Created:** 2026-05-25  
**Version:** 1.0  
**Target Audience:** Students, newbie internet users  
**Philosophy:** Don't just warn—redirect to safer alternatives

---

## Core Strategy

PhishGuard's primary goal is **protecting newbie users from long-term machine damage** (malware, ransomware) rather than just data leaks. Newbie users often ignore warnings regardless of severity, so the extension must be **preventative, not just alertive**.

### Key Principle
**When a dangerous site is detected, provide a safer alternative path instead of just blocking.**

---

## Warning Hierarchy (By Risk Level)

### 🔴 **DANGEROUS** (Malware / Ransomware Risk)
- **Current behavior:** Show warning overlay, block navigation
- **Target:** Piracy sites, ransomware distributors, phishing redirects
- **Why block heavily:** Machine infection could cause permanent damage
- **Example threats:**
  - Illegal streaming/torrent sites (malware-laden)
  - Fake antivirus/system optimization software
  - Phishing kits targeting financial credentials
  - Drive-by download sites

**Action:** Block with strong warning + suggest legal alternatives (Netflix, Disney+, etc.)

### 🟡 **SUSPICIOUS** (Social Engineering / Low-Severity Risk)
- **Current behavior:** Show tooltip, inline badges on SERP
- **Target:** Domains mimicking legitimate services, questionable practices
- **Why warn gently:** May not be immediate threat, but user should verify legitimacy
- **Example threats:**
  - Domain impersonation (paytm-kyc.com vs paytm.com)
  - Free hosting exploits (suspicious free .tk domains)
  - Ad-heavy sites with tracking

**Action:** Warn on hover, let user decide but highlight red flags

### 🟢 **SAFE** (Verified & Trusted)
- **Current behavior:** Show tick mark, no friction
- **Target:** Established platforms with strong reputations
- **Example:** YouTube, PayPal, SBI, Amazon

**Action:** No interference—user clicks freely

---

## Feature Priorities (No Major Changes)

### What NOT to change:
- ✋ Existing scoring algorithm (works fine)
- ✋ Popup dashboard layout
- ✋ Database/blocklist structure
- ✋ ML boost layer

### What CAN be enhanced (minimal changes):
1. **DANGEROUS verdict messaging:** Include suggestion for safer alternative in warning text
2. **Link context:** When blocking a link, show what it was trying to do (e.g., "Trying to access a movie site? Try Netflix instead")
3. **Settings toggle:** Optional "Safe Mode" for first-time users that auto-blocks DANGEROUS and shows alternatives

---

## User Risk Perception Reframing

### Problem:
Newbie users don't understand the difference between:
- "Your data might leak" (easy to ignore if they have nothing to hide)
- "Your computer will get infected with ransomware" (impossible to ignore, high urgency)

### Solution:
Frame threats in terms of **machine damage**, not data theft:

❌ *Bad:* "This site might steal your password"  
✅ *Good:* "This site contains malware that could encrypt your files and lock you out"

❌ *Bad:* "Suspicious domain detected"  
✅ *Good:* "This looks like a fake bank login. Real [Bank] never asks for passwords here. Go to the official bank app instead"

---

## Default Behavior for Each Verdict

### When `DANGEROUS` is detected:
```
1. Show blocking overlay (non-negotiable)
2. Explain why in simple terms (malware risk, not just "bad site")
3. Suggest 1-2 safe alternatives based on context:
   - Piracy site → Netflix, Prime Video, YouTube, Hotstar
   - Fake bank → Official mobile app, official website from Google Search
   - Phishing → "Contact your bank directly using their official number"
4. Allow user to proceed (they can click "I understand the risk")
```

### When `SUSPICIOUS` is detected:
```
1. Show tooltip on hover (not intrusive)
2. Flag the specific issue: "Impersonating Paytm" / "Unusual domain"
3. Show legitimate alternative: "Official: paytm.com"
4. Let user decide—no forced block
```

### When `SAFE` is detected:
```
1. No interference
2. Silently log scan for analytics
3. Show trust indicator (optional checkmark)
```

---

## Messages to Avoid (Confusing for Newbies)

- ❌ "TLS certificate invalid" (too technical)
- ❌ "IP address in hostname" (why should I care?)
- ❌ "Redirect parameters detected" (doesn't explain the risk)

Instead, translate to user impact:

- ✅ "This site doesn't use secure encryption"
- ✅ "This looks like a fake setup to steal data"
- ✅ "This site is trying to hide where it's sending you"

---

## What's NOT the responsibility of PhishGuard

- 🔄 Network monitoring (VPN security, WiFi sniffing)
- 🔐 Password management (that's a password manager's job)
- 📧 Email phishing (that's Gmail/Outlook's job)
- 🧹 Malware cleanup (that's antivirus's job)

**PhishGuard is the last line of defense before the user clicks a bad link.**

---

## Future Enhancements (Post-1.2.0)

These ideas align with the strategy but are NOT urgent:

1. **Alternative suggestions database:** Map dangerous site categories to safe alternatives
   - Format: `{ category: "streaming", safe: ["netflix.com", "youtube.com"] }`
   - Used in warning overlay

2. **Newbie mode:** Checkbox in settings → stricter blocking, simpler UI
   - Blocks SUSPICIOUS sites (not just DANGEROUS)
   - Hides technical flags, shows human translations

3. **Malware-specific detection:** Partner with VirusTotal for real-time malware intel
   - Flag binaries, exploits, trojans separately from phishing

4. **Onboarding:** First-time extension install → tutorial for target user
   - Teach the difference between "data leak risk" and "machine infection risk"

---

## Metrics to Track (for success)

- How many users click "Proceed anyway" on DANGEROUS verdicts? (lower = better)
- How many users click "Report false positive" on SUSPICIOUS? (track for accuracy)
- User retention after first month (goal: >40% of installs still active)
- Satisfaction survey: "How confident are you that you won't get malware?" (goal: +3 before/after)

---

## Decision Framework

**When deciding if a feature is aligned with this prompt, ask:**

1. Does it help newbie users make safer clicks? ✅
2. Does it communicate risk in terms of **machine damage**, not just "bad"? ✅
3. Does it provide a **safer alternative** instead of just blocking? ✅
4. Can it be built without major UI/UX overhaul? ✅

If all four are YES, it's aligned with this prompt.
