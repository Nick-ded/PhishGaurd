
# PhishGuard

PhishGuard is a Chrome Extension Manifest V3 project for detecting phishing, scam, and suspicious links in real time. It scans the current page, evaluates individual links, shows verdicts in a popup dashboard, and can surface page-level warning signals such as redirects, ad markers, and suspicious form patterns.

## What It Does

- Scores the active page with a trust-based verdict: `SAFE`, `SUSPICIOUS`, or `DANGEROUS`.
- Scans links on the page and shows per-link verdicts, scores, and signal tags.
- Highlights suspicious results with hover tooltips and SERP badges.
- Shows page-level counters in the popup for links, ads, and suspicious signals.
- Supports optional ML boosting through a Hugging Face token stored locally in `chrome.storage.local`.
- Includes a demo page for testing safe, suspicious, and dangerous examples.

## Project Structure

- [manifest.json](manifest.json) - Extension manifest and permissions.
- [background/service_worker.js](background/service_worker.js) - Central message router, cache, and scan orchestration.
- [content/content_script.js](content/content_script.js) - Page scanning, hover tooltips, click blocking, and SERP annotations.
- [content/content_style.css](content/content_style.css) - Styles for injected tooltips, badges, and overlays.
- [popup/popup.html](popup/popup.html) - Popup dashboard markup.
- [popup/popup.css](popup/popup.css) - Popup dashboard styling.
- [popup/popup.js](popup/popup.js) - Popup logic and live data rendering.
- [utils/detector.js](utils/detector.js) - Heuristic scoring and verdict generation.
- [utils/ml_scorer.js](utils/ml_scorer.js) - Optional Hugging Face DistilBERT boost layer.
- [demo/index.html](demo/index.html) - Local demo page for testing behavior.
- [icons/](icons/) - Extension icons.

## How It Works

1. The content script scans the active page and collects real DOM data such as links, ad markers, redirects, and form indicators.
2. The background service worker evaluates URLs and pages, caches verdicts, and answers popup and hover requests.
3. The popup queries the current tab, renders the verdict card, updates the score bar, and lists the top scanned links with real signal tags.
4. Optional ML boosting can be applied when a Hugging Face API token is available.

## Verdict Thresholds

PhishGuard uses a trust score from `0` to `100`:

- `71-100` = `SAFE`
- `45-70` = `SUSPICIOUS`
- `0-44` = `DANGEROUS`

## Installation

1. Open Chrome and go to `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the project folder: `d:\guar dai\PhishGaurd`.

## Usage

- Open any webpage and click the PhishGuard extension icon.
- Review the verdict, trust score, page counters, and page signal chips.
- Hover over links to see quick verdict tooltips.
- On Google results pages, suspicious links may receive inline badges.
- On dangerous pages, the content script can show a blocking warning overlay.

## Optional ML Boost

If you want the extension to use the Hugging Face DistilBERT boost path, save an API token in the popup settings. Without a token, the extension still works using heuristic scoring.

## Demo Page

Use [demo/index.html](demo/index.html) to test the extension against sample safe, suspicious, and dangerous links.

## Notes

- The extension is designed to use real page data rather than mock values.
- The popup and content script communicate through `chrome.runtime.sendMessage` and `chrome.tabs.sendMessage`.
- Current behavior and thresholds are driven by the detector and service worker, not by hardcoded popup labels.

