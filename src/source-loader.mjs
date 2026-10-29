import { parseFreeSubscription } from './free-converter.mjs';
import { SOURCES } from './free-sources.mjs';

const MAX_BYTES = 4 * 1024 * 1024;
const MAX_FEEDS = 6;
const MAX_DAILY_NODES = 500;
const ARTICLE_PATHS = {
  mibei: /^\/\d+\.html$/,
  hiddifynext: /^\/free-nodes\/[^/]+\.htm$/,
  freeclashnode: /^\/free-node\/[^/]+\.htm$/,
  v2raydog: /^\/freenode\/\d{4}-\d{1,2}-\d{1,2}\/$/,
  cfmem: /^\/\d{4}\/\d{2}\/[^/]+\.html$/,
};

export function decodeHtml(text) {
  return String(text).replace(/&(?:amp|quot|apos|lt|gt|#\d+|#x[0-9a-f]+);/gi, entity => {
    const named = { '&amp;': '&', '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>' };
    if (named[entity.toLowerCase()]) return named[entity.toLowerCase()];
    const hex = /^&#x/i.test(entity), n = parseInt(entity.slice(hex ? 3 : 2, -1), hex ? 16 : 10);
    return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '';
  });
}
function content(html) {
  return html.replace(/<!--[^]*?-->/g, '').replace(/<(script|style)\b[^>]*>[^]*?<\/\1\s*>/gi, '');
}
function safeUrl(input, base) {
  try {
    const u = new URL(decodeHtml(input), base);
    if (u.protocol !== 'https:' || u.username || u.password || u.port || u.href.length > 2048) return null;
    u.hash = ''; return u;
  } catch { return null; }
}
function links(html, base) {
  const found = [], text = content(html);
  for (const m of text.matchAll(/\b(?:href|data-copy|data-clipboard-text)\s*=\s*["']([^"']+)["']/gi)) {
    const u = safeUrl(m[1], base); if (u) found.push(u);
  }
  for (const m of text.matchAll(/https:\/\/[^\s<>"'`]+/gi)) {
    const u = safeUrl(m[0], base); if (u) found.push(u);
  }
  return [...new Map(found.map(u => [u.href, u])).values()];
}
function articleOrder(url) {
  const d = url.pathname.match(/(20\d{2})[-/]?(\d{2})[-/]?(\d{2})/);
  if (d) return Number(d[1] + d[2] + d[3]);
  return Number(url.pathname.match(/^\/(\d+)\.html$/)?.[1] || 0);
}
export function discoverArticles(source, html) {
  const base = new URL(source.url), pattern = ARTICLE_PATHS[source.kind];
  if (!pattern) return [];
  return links(html, source.url).filter(u => u.origin === base.origin && !u.search && pattern.test(u.pathname))
    .sort((a, b) => articleOrder(b) - articleOrder(a)).slice(0, 2).map(u => u.href);
}

export function discoverFeeds(source, html, pageUrl = source.url) {
  const kind = source.kind, found = links(html, pageUrl);
  let feeds;
  if (kind === 'freev2') {
    // Only the site's public subscription copy button, never donation/advert links.
    const copies = [...content(html).matchAll(/data-clipboard-text\s*=\s*["']([^"']+)["']/gi)].map(m => safeUrl(m[1], pageUrl));
    feeds = copies.filter(u => u && /^(?:[a-z0-9-]+\.)?503403\.xyz$/.test(u.hostname));
  } else if (kind === 'cfmem') {
    feeds = found.filter(u => u.hostname === 'nodebuf.com' && /^\/node-sub\/[a-f0-9]{32,128}\/v2ray$/.test(u.pathname));
    // Older posts expose one preview link for each format; select V2Ray only.
    for (const m of content(html).matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([^]*?)<\/a>/gi)) {
      const u = safeUrl(m[1], pageUrl);
      if (u?.hostname === 'nodebuf.com' && /^\/files\/public\/[a-z0-9]+\/preview$/.test(u.pathname) && /v2ray/i.test(m[2].replace(/<[^>]*>/g, ''))) feeds.push(u);
    }
  } else {
    feeds = found.filter(u => {
      if (u.search) return false;
      if (kind === 'mibei') return u.hostname === 'aa.mibei77.com' && /^\/\d{6}\/[^/]+\.txt$/.test(u.pathname);
      if (kind === 'hiddifynext') return u.hostname === 'hiddify-next-node.github.io' && /^\/uploads\/\d{4}\/\d{2}\/[^/]+\.txt$/.test(u.pathname);
      if (kind === 'freeclashnode') return u.hostname === 'node.freeclashnode.com' && /^\/uploads\/\d{4}\/\d{2}\/[^/]+\.txt$/.test(u.pathname);
      if (kind === 'v2raydog') return u.hostname === 'nodesub.v2raydog.com' && /^\/\d{4}\/\d{2}\/v2raydog-\d{8}\.txt$/.test(u.pathname);
      if (kind === 'endgfw') return u.hostname === 'raw.githubusercontent.com' && u.pathname === '/hello-world-1989/cn-news/main/end-gfw-free';
      return false;
    });
  }
  return [...new Set(feeds.map(u => u.href))].slice(0, MAX_FEEDS);
}

export async function readSourceText(response, maxBytes = MAX_BYTES) {
  if (Number(response.headers.get('Content-Length') || 0) > maxBytes) {
    await response.body?.cancel(); throw new Error('Source exceeds size limit');
  }
  if (!response.body) throw new Error('Empty source response');
  const reader = response.body.getReader(), parts = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw new Error('Source exceeds size limit'); }
    parts.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** Authenticated checker supplies native URIs only, never proxy objects/routes. */
export function parseSourceSupplements(input = []) {
  if (!Array.isArray(input) || input.length > SOURCES.filter(s => s.kind).length) throw new Error('Invalid source supplements');
  const parsed = new Map();
  for (const item of input) {
    const source = SOURCES.find(s => s.kind && s.id === item?.sourceId);
    if (!source || parsed.has(source.id) || Object.keys(item).some(k => !['sourceId','subscription','articleUrl','feedCount','fetchedFeedCount'].includes(k))) throw new Error('Invalid source supplements');
    if (typeof item.subscription !== 'string' || item.subscription.length > 1024 * 1024) throw new Error('Invalid supplemental subscription');
    const result = parseFreeSubscription(item.subscription, { sourceId: source.id, sourceName: source.name, limit: MAX_DAILY_NODES });
    if (!result.nodes.length) throw new Error('No supported supplemental nodes');
    const article = safeUrl(item.articleUrl || source.url, source.url);
    if (!article || article.origin !== new URL(source.url).origin || article.search) throw new Error('Invalid supplemental article');
    for (const key of ['feedCount','fetchedFeedCount']) if (item[key] !== undefined && (!Number.isInteger(item[key]) || item[key] < 1 || item[key] > MAX_FEEDS)) throw new Error('Invalid supplemental feed count');
    if (item.fetchedFeedCount > item.feedCount) throw new Error('Invalid supplemental feed count');
    parsed.set(source.id, { ...result, source, articleUrl: article.href, feedCount: item.feedCount ?? 1, fetchedFeedCount: item.fetchedFeedCount ?? 1, fetchedBy: 'github-actions' });
  }
  return parsed;
}

/** Fixed publisher -> latest post -> all native URI feeds in that post. */
export async function loadFreeSource(source, fetcher = fetch) {
  const deadline = AbortSignal.timeout(45000);
  const get = async url => {
    const r = await fetcher(url, { headers: { Accept: 'text/plain,text/html;q=0.9,application/octet-stream;q=0.8', 'User-Agent': 'Free-Subscription/3.0' }, redirect: 'manual', signal: deadline });
    if (!r.ok) { await r.body?.cancel(); throw new Error(`HTTP ${r.status}`); }
    return readSourceText(r);
  };
  const options = { sourceId: source.id, sourceName: source.name, limit: source.kind ? MAX_DAILY_NODES : 80 };
  const landing = await get(source.url);
  if (!source.kind) {
    const parsed = parseFreeSubscription(landing, options);
    if (!parsed.nodes.length) throw new Error('No supported nodes');
    return { ...parsed, source };
  }
  const articles = ARTICLE_PATHS[source.kind] ? discoverArticles(source, landing) : [source.url];
  if (!articles.length) throw new Error('No daily article found');
  for (const articleUrl of articles) {
    try {
      const article = articleUrl === source.url ? landing : await get(articleUrl);
      const feedUrls = discoverFeeds(source, article, articleUrl);
      if (!feedUrls.length) continue;
      const results = await Promise.allSettled(feedUrls.map(async url => parseFreeSubscription(await get(url), options)));
      const valid = results.filter(r => r.status === 'fulfilled' && r.value.nodes.length).map(r => r.value);
      if (!valid.length) continue;
      const nodes = [], seen = new Set();
      for (const result of valid) for (const node of result.nodes) {
        if (!seen.has(node.id) && nodes.length < MAX_DAILY_NODES) { seen.add(node.id); nodes.push(node); }
      }
      const sourceCount = valid.reduce((n, r) => n + r.sourceCount, 0);
      return { source, nodes, sourceCount, skipped: sourceCount - nodes.length,
        articleUrl, feedCount: feedUrls.length, fetchedFeedCount: valid.length,
        warnings: [...valid.flatMap(r => r.warnings), ...(valid.length < feedUrls.length ? ['Some daily feeds unavailable or unsupported'] : [])].slice(0, 30) };
    } catch { /* Try one preceding daily post if the newest is unavailable. */ }
  }
  throw new Error('Daily subscription unavailable or invalid');
}
