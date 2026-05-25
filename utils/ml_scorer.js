'use strict';

const HF_ENDPOINT = 'https://api-inference.huggingface.co/models/distilbert-base-uncased-finetuned-sst-2-english';
const CACHE = new Map();
const TTL = 10 * 60 * 1000;

async function mlBoost(url, pageText, hfToken) {
  if (!hfToken) return 0;

  const cacheKey = String(url || '');
  const cached = CACHE.get(cacheKey);
  if (cached && Date.now() - cached.ts < TTL) return cached.score;

  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    return 0;
  }

  const input = `${hostname} ${(pageText || '').slice(0, 300)}`.trim();
  if (!input) return 0;

  try {
    const response = await fetch(HF_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${hfToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ inputs: input }),
      signal: typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
        ? AbortSignal.timeout(4000)
        : undefined
    });

    if (!response.ok) return 0;

    const data = await response.json();
    const flat = Array.isArray(data?.[0]) ? data[0] : data;
    const positive = Array.isArray(flat)
      ? flat.find((item) => item && item.label === 'POSITIVE')?.score ?? 0.5
      : 0.5;

    const boost = Math.round((positive - 0.5) * 30);
    CACHE.set(cacheKey, { score: boost, ts: Date.now() });
    return boost;
  } catch {
    return 0;
  }
}

if (typeof self !== 'undefined') {
  self.mlBoost = mlBoost;
}

if (typeof module !== 'undefined') {
  module.exports = { mlBoost };
}
