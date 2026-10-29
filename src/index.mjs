import { SOURCES, mergeFreeSources, MAX_CANDIDATES } from './free-sources.mjs';
import { loadFreeSource, parseSourceSupplements } from './source-loader.mjs';
import { renderLoginPage, renderDashboard } from './ui.mjs';
import { HealthReportError, candidateSummary, makeHealthySnapshot, healthView, publicStatus } from './health-snapshot.mjs';

const MAX_BYTES = 4 * 1024 * 1024;
const SESSION_TTL = 12 * 60 * 60;
const COOKIE_NAME = '__Host-vpngate_session';
const loginFailures = new Map();
let cachedRaw = null;
let cachedSnapshot = null;

async function snapshot(store) {
  const raw = await store.get('snapshot');
  if (raw === null) return null;
  if (raw !== cachedRaw) { cachedSnapshot = JSON.parse(raw); cachedRaw = raw; }
  return cachedSnapshot;
}

const commonHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'private, no-store',
};

function response(body, status = 200, type = 'application/json; charset=utf-8', extra = {}) {
  return new Response(body, { status, headers: { ...commonHeaders, 'Content-Type': type, ...extra } });
}
function json(body, status = 200) { return response(JSON.stringify(body), status); }

// Compare fixed-length digests rather than leaking the first differing character.
async function equalSecret(provided, secret) {
  if (!secret) return false;
  if (!provided || provided.length > 512) return false;
  const encoder = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(provided)),
    crypto.subtle.digest('SHA-256', encoder.encode(secret)),
  ]);
  let delta = 0;
  const av = new Uint8Array(a), bv = new Uint8Array(b);
  for (let i = 0; i < av.length; i++) delta |= av[i] ^ bv[i];
  return delta === 0;
}

async function authorized(request, secret, allowQuery = true) {
  const bearer = request.headers.get('Authorization')?.match(/^Bearer (.+)$/i)?.[1];
  const provided = bearer || (allowQuery ? new URL(request.url).searchParams.get('token') : null);
  return equalSecret(provided, secret);
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randomToken(length = 18) { return base64url(crypto.getRandomValues(new Uint8Array(length))); }
async function signingKey(env) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(`login-session-v1:${env.ADMIN_TOKEN}:${env.LOGIN_PASSWORD}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function createSession(env) {
  const payload = `${Math.floor(Date.now() / 1000) + SESSION_TTL}.${randomToken()}`;
  const signature = await crypto.subtle.sign('HMAC', await signingKey(env), new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(signature))}`;
}
async function validSession(request, env) {
  if (!env.ADMIN_TOKEN || !env.LOGIN_PASSWORD) return false;
  const cookie = request.headers.get('Cookie')?.split(';').map(item => item.trim()).find(item => item.startsWith(`${COOKIE_NAME}=`))?.slice(COOKIE_NAME.length + 1);
  if (!cookie || cookie.length > 256 || !/^\d{10}\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$/.test(cookie)) return false;
  const [expires, random, signature] = cookie.split('.');
  const now = Math.floor(Date.now() / 1000);
  if (Number(expires) <= now || Number(expires) > now + SESSION_TTL + 60) return false;
  try {
    const bytes = Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/') + '='), c => c.charCodeAt(0));
    return crypto.subtle.verify('HMAC', await signingKey(env), bytes, new TextEncoder().encode(`${expires}.${random}`));
  } catch { return false; }
}
function sessionCookie(value, maxAge = SESSION_TTL) {
  return `${COOKIE_NAME}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}
function redirect(location, headers = {}) { return response(null, 303, 'text/plain; charset=utf-8', { Location: location, ...headers }); }
function html(body, nonce, status = 200) {
  return response(body, status, 'text/html; charset=utf-8', {
    // Native same-origin form POSTs need their Origin header preserved.
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
}

async function readLimitedText(upstream, maxBytes = MAX_BYTES) {
  if (Number(upstream.headers.get('Content-Length') || 0) > maxBytes) throw new Error('Source exceeds size limit');
  if (!upstream.body) throw new Error('Empty source response');
  const reader = upstream.body.getReader();
  let size = 0;
  const parts = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw new Error('Source exceeds size limit'); }
    parts.push(value);
  }
  const buffer = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { buffer.set(part, offset); offset += part.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
}

export async function refresh(env, fetcher = fetch, supplementInput = []) {
  const startedAt = new Date().toISOString();
  const supplements = parseSourceSupplements(supplementInput);
  try {
    // Bound discovery requests as well as response sizes; only fixed adapters
    // can select fetch destinations. Leave room for KV operations in this run.
    let requests = 0;
    const boundedFetch = (...args) => {
      if (++requests > 45) throw new Error('Source request budget exhausted');
      return fetcher(...args);
    };
    const fetched = await Promise.allSettled(SOURCES.map(async source => {
      try { return await loadFreeSource(source, boundedFetch); }
      catch (error) {
        if (supplements.has(source.id)) return supplements.get(source.id);
        throw error;
      }
    }));
    const successful = fetched.filter(r => r.status === 'fulfilled').map(r => r.value);
    const sources = fetched.map((r, i) => ({
      ...SOURCES[i], success: r.status === 'fulfilled',
      nodeCount: r.status === 'fulfilled' ? r.value.nodes.length : 0,
      sourceCount: r.status === 'fulfilled' ? r.value.sourceCount : 0,
      ...(r.status === 'fulfilled' && r.value.articleUrl ? { articleUrl: r.value.articleUrl, feedCount: r.value.feedCount, fetchedFeedCount: r.value.fetchedFeedCount } : {}),
      ...(r.status === 'fulfilled' && r.value.fetchedBy ? { fetchedBy: r.value.fetchedBy } : {}),
      ...(r.status === 'rejected' ? { error: /^HTTP \d+$/.test(r.reason?.message) ? r.reason.message : 'Source unavailable or invalid' } : {}),
    }));
    if (!successful.length) throw new Error('All free sources unavailable or invalid; previous snapshot retained');
    const nodes = mergeFreeSources(successful, MAX_CANDIDATES);
    if (!nodes.length) throw new Error('No supported public nodes; previous snapshot retained');
    const candidate = {
      generationId: randomToken(), createdAt: new Date().toISOString(), nodes,
      sourceStatus: sources, sourceCount: successful.reduce((n, r) => n + r.sourceCount, 0),
      skipped: successful.reduce((n, r) => n + r.skipped, 0),
      warnings: successful.flatMap(r => r.warnings.map(w => `${r.source.id}: ${w}`)).slice(0, 30),
    };
    const serialized = JSON.stringify(candidate);
    // Keep each generation immutable so a scheduled refresh cannot invalidate
    // an in-flight check. Raw candidates are accessible only to the checker.
    await env.STORE.put(`candidate:${candidate.generationId}`, serialized, { expirationTtl: 4 * 60 * 60 });
    await env.STORE.put('candidates', serialized, { expirationTtl: 4 * 60 * 60 });
    await env.STORE.put('last-attempt', JSON.stringify({ at: startedAt, success: true, phase: 'candidates', generationId: candidate.generationId })).catch(() => {});
    return candidateSummary(candidate);
  } catch (error) {
    const message = String(error?.message || 'Refresh failed').slice(0, 300);
    await env.STORE.put('last-attempt', JSON.stringify({ at: startedAt, success: false, message })).catch(() => {});
    throw new Error(message);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/healthz' && request.method === 'GET') {
      return json({ ok: true, service: 'vpngate-subscription', trafficRelay: false });
    }
    if (url.pathname === '/login' && request.method === 'GET') {
      if (await validSession(request, env)) return redirect('/');
      const nonce = randomToken();
      return html(renderLoginPage({ nonce }), nonce);
    }
    if (url.pathname === '/login' && request.method === 'POST') {
      if (request.headers.get('Origin') && request.headers.get('Origin') !== url.origin) return json({ error: 'Invalid origin' }, 403);
      if (!env.LOGIN_PASSWORD || !env.ADMIN_TOKEN) return json({ error: 'Login is not configured' }, 503);
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const failure = loginFailures.get(ip);
      if (failure && failure.until > Date.now() && failure.count >= 10) return json({ error: 'Too many attempts. Please retry later.' }, 429);
      let password;
      try { password = new URLSearchParams(await readLimitedText(request, 2048)).get('password'); }
      catch { return json({ error: 'Invalid login request' }, 400); }
      if (!await equalSecret(password, env.LOGIN_PASSWORD)) {
        if (loginFailures.size > 500) loginFailures.clear();
        const previous = failure?.until > Date.now() ? failure.count : 0;
        loginFailures.set(ip, { count: previous + 1, until: Date.now() + 10 * 60 * 1000 });
        const nonce = randomToken();
        return html(renderLoginPage({ error: true, nonce }), nonce, 401);
      }
      loginFailures.delete(ip);
      return redirect('/', { 'Set-Cookie': sessionCookie(await createSession(env)) });
    }
    if (url.pathname === '/logout' && request.method === 'POST') {
      if (request.headers.get('Origin') && request.headers.get('Origin') !== url.origin) return json({ error: 'Invalid origin' }, 403);
      return redirect('/login', { 'Set-Cookie': sessionCookie('', 0) });
    }
    if (url.pathname === '/' && request.method === 'GET') {
      if (!await validSession(request, env)) return redirect('/login');
      const nonce = randomToken();
      const [current, candidate, lastAttempt] = await Promise.all([snapshot(env.STORE), env.STORE.get('candidates', 'json'), env.STORE.get('last-attempt', 'json')]);
      const status = publicStatus(current, candidate);
      const link = pathname => { const target = new URL(pathname, url.origin); target.searchParams.set('token', env.SUB_TOKEN); return target.href; };
      return html(renderDashboard({
        nonce, baseUrl: url.origin, subscriptionUrl: link('/sub/mihomo.yaml'),
        karingUrl: link('/sub/karing.json'),
        v2raynUrl: link('/sub/v2rayn.txt'),
        providerUrl: link('/sub/provider.yaml'), statusUrl: link('/api/status'),
        nodeCount: status.nodeCount, updatedAt: status.updatedAt,
        lastAttempt, health: status.health, candidateStatus: status.candidateStatus,
        sources: status.sources?.filter(source => source.success) ?? [],
        protocols: Object.keys(status.protocols ?? {}),
      }), nonce);
    }
    if (url.pathname === '/admin/refresh') {
      if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
      if (!await authorized(request, env.ADMIN_TOKEN, false)) return json({ error: 'Unauthorized' }, 401);
      let supplements;
      try {
        const text = request.body ? await readLimitedText(request) : '';
        const input = text.trim() ? JSON.parse(text) : {};
        if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).some(k => k !== 'supplements')) throw new Error('Invalid refresh request');
        supplements = input.supplements ?? [];
        parseSourceSupplements(supplements);
      } catch { return json({ error: 'Invalid source supplements' }, 400); }
      try { return json(await refresh(env, fetch, supplements)); }
      catch (error) { return json({ error: error.message, previousSnapshotRetained: true }, 502); }
    }
    if (url.pathname === '/admin/candidates') {
      if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
      if (!await authorized(request, env.ADMIN_TOKEN, false)) return json({ error: 'Unauthorized' }, 401);
      const generationId = url.searchParams.get('generationId');
      if (generationId !== null && !/^[A-Za-z0-9_-]{16,64}$/.test(generationId)) return json({ error: 'Invalid candidate generation' }, 400);
      const candidate = await env.STORE.get(generationId === null ? 'candidates' : `candidate:${generationId}`, 'json');
      if (!candidate) return json({ error: 'No candidate generation available', code: 'NoCandidates' }, 503);
      return json(candidate);
    }
    if (url.pathname === '/admin/check-results') {
      if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
      if (!await authorized(request, env.ADMIN_TOKEN, false)) return json({ error: 'Unauthorized' }, 401);
      let report;
      try { report = JSON.parse(await readLimitedText(request, 256 * 1024)); }
      catch (error) { return json({ error: error.message === 'Source exceeds size limit' ? 'Health report exceeds size limit' : 'Invalid health report JSON' }, error.message === 'Source exceeds size limit' ? 413 : 400); }
      if (typeof report?.generationId !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(report.generationId)) return json({ error: 'Invalid candidate generation' }, 400);
      try {
        const [candidate, current] = await Promise.all([env.STORE.get(`candidate:${report.generationId}`, 'json'), snapshot(env.STORE)]);
        const next = makeHealthySnapshot(report, candidate, current);
        // One atomic value publishes all formats and their matching health data.
        await env.STORE.put('snapshot', JSON.stringify(next));
        return json({ ok: true, generationId: report.generationId, nodeCount: next.status.nodeCount, health: healthView(next), trafficRelay: false });
      } catch (error) {
        return json({ error: error instanceof HealthReportError ? error.message : 'Unable to publish health snapshot', previousSnapshotRetained: true }, error instanceof HealthReportError ? error.status : 502);
      }
    }
    const routes = {
      '/sub/mihomo.yaml': ['mihomo', 'text/yaml; charset=utf-8', 'vpngate-mihomo.yaml'],
      '/sub/v2rayn.yaml': ['mihomo', 'text/yaml; charset=utf-8', 'vpngate-v2rayn.yaml'],
      '/sub/v2rayn.txt': ['uris', 'text/plain; charset=utf-8', 'free-v2rayn.txt'],
      '/sub/karing.json': ['karing', 'application/json; charset=utf-8', 'vpngate-karing.json'],
      '/sub/provider.yaml': ['provider', 'text/yaml; charset=utf-8', 'vpngate-provider.yaml'],
      '/api/nodes': ['nodes', 'application/json; charset=utf-8'],
      '/api/status': ['status', 'application/json; charset=utf-8'],
    };
    const ovpnMatch = url.pathname.match(/^\/ovpn\/([a-zA-Z0-9_-]+)\.ovpn$/);
    if (!routes[url.pathname] && !ovpnMatch) return json({ error: 'Not found' }, 404);
    if (!['GET', 'HEAD'].includes(request.method)) return json({ error: 'Method not allowed' }, 405);
    if (!await authorized(request, env.SUB_TOKEN)) return json({ error: 'Unauthorized' }, 401);
    const current = await snapshot(env.STORE);
    if (url.pathname === '/api/status') {
      const [candidate, lastAttempt] = await Promise.all([env.STORE.get('candidates', 'json'), env.STORE.get('last-attempt', 'json')]);
      const status = { ...publicStatus(current, candidate), lastAttempt };
      return request.method === 'HEAD' ? response(null, 200) : json(status);
    }
    const health = healthView(current);
    if (!health.available) {
      const codes = { pending: 'HealthCheckRequired', expired: 'HealthCheckExpired', empty: 'NoHealthyNodes' };
      const messages = { pending: 'Awaiting a complete connectivity check', expired: 'Connectivity check expired; awaiting a new report', empty: 'No candidate passed the latest connectivity check' };
      return response(request.method === 'HEAD' ? null : JSON.stringify({ error: messages[health.state], code: codes[health.state], health, nodeCount: 0 }), 503, 'application/json; charset=utf-8', { 'Retry-After': '300' });
    }
    if (ovpnMatch) {
      const profile = current.profiles?.find(node => node.id === ovpnMatch[1]);
      if (!profile) return json({ error: 'Profile not found' }, 404);
      return response(request.method === 'HEAD' ? null : profile.ovpn, 200, 'application/x-openvpn-profile', {
        'Content-Disposition': `attachment; filename="${profile.id}.ovpn"`,
      });
    }
    const [key, type, filename] = routes[url.pathname];
    if (['karing', 'uris'].includes(key) && !current[key]) return json({ error: 'Subscription format is not ready; please retry after the next successful refresh' }, 503);
    const body = typeof current[key] === 'string' ? current[key] : JSON.stringify(current[key]);
    return response(request.method === 'HEAD' ? null : body, 200, type, filename ? {
      'Content-Disposition': `attachment; filename="${filename}"`,
      'profile-update-interval': '1',
      'profile-title': key === 'uris' ? 'Free Nodes v2rayN' : key === 'karing' ? 'Free Nodes Karing' : 'Free Nodes Mihomo',
    } : {});
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refresh(env).catch(error => console.error('Free subscription refresh failed:', error.message)));
  },
};
