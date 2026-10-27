import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

export const TARGETS = ['https://1.1.1.1/cdn-cgi/trace', 'https://www.google.com/generate_204'];
const TYPES = new Set(['ss', 'vmess', 'vless', 'trojan', 'hysteria2']);
const children = new Set();
const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer(); server.once('error', reject);
  server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
});

export function verifyProbe(target, exitCode, stdout) {
  const split = stdout.lastIndexOf('\n__PROBE__');
  if (split < 0 || exitCode !== 0) return { passed: false };
  const body = stdout.slice(0, split);
  const [code, seconds, tls] = stdout.slice(split + 10).trim().split('\t').map(Number);
  const latencyMs = Math.round(seconds * 1000);
  const validTime = Number.isFinite(latencyMs) && latencyMs >= 0 && latencyMs <= 30000;
  const expected = target === TARGETS[0] ? code === 200 && /^ip=\S+$/m.test(body) : target === TARGETS[1] && code === 204 && !body.trim();
  return { passed: Boolean(tls === 0 && validTime && expected), latencyMs };
}

function probe(port, target, activeChildren) {
  return new Promise((resolve, reject) => {
    // -q ignores the runner/user curlrc; explicit proxy and empty noproxy prohibit direct bypass.
    const child = spawn(process.platform === 'win32' ? 'curl.exe' : 'curl', [
      '-q', '--silent', '--show-error', '--proxy', `http://127.0.0.1:${port}`, '--noproxy', '',
      '--connect-timeout', '8', '--max-time', '12', '--max-filesize', '16384',
      '--write-out', '\n__PROBE__%{http_code}\t%{time_total}\t%{ssl_verify_result}', target,
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    children.add(child); activeChildren.add(child); let stdout = ''; let timer; let settled = false;
    const done = (result, error) => {
      if (settled) return; settled = true;
      clearTimeout(timer); children.delete(child); activeChildren.delete(child);
      if (error) reject(error); else resolve(result);
    };
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 32768) child.kill(); });
    child.on('error', () => done(null, new Error('HTTPS probe executable failed to start')));
    child.on('close', code => done(verifyProbe(target, code, stdout)));
    timer = setTimeout(() => child.kill(), 16000);
  });
}

function validateConfig(corePath, coreArgs, directory, filename, activeChildren) {
  return new Promise((resolve, reject) => {
    // A parser may include node credentials in its diagnostic output; discard both streams.
    const child = spawn(corePath, [...coreArgs, '-t', '-d', directory, '-f', filename], { windowsHide: true, stdio: 'ignore' });
    children.add(child); activeChildren.add(child);
    let timer; let timedOut = false; let settled = false;
    const done = (valid, error) => {
      if (settled) return; settled = true;
      clearTimeout(timer); children.delete(child); activeChildren.delete(child);
      if (error) reject(error); else resolve(valid);
    };
    child.once('error', () => done(false, new Error('Mihomo configuration checker failed to start')));
    child.once('close', (code, signal) => {
      if (timedOut) return done(false, new Error('Mihomo configuration check timed out'));
      if (signal || code === null) return done(false, new Error('Mihomo configuration checker stopped unexpectedly'));
      done(code === 0);
    });
    timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 15000);
  });
}

async function stopChild(child) {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill();
    await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(3000)]);
  }
  children.delete(child);
}

export function checkerConfig(nodes, ports, controller, secret) {
  if (!nodes.length || nodes.length > 120 || nodes.length !== ports.length) throw new Error('Invalid candidate count');
  if (new Set(nodes.map(n => n.id)).size !== nodes.length || new Set(nodes.map(n => n.name)).size !== nodes.length) throw new Error('Duplicate candidate');
  for (const n of nodes) {
    if (!/^free-[a-f0-9]{16}$/.test(n.id) || !TYPES.has(n.proxy?.type) || n.proxy.name !== n.name || n.proxy['dialer-proxy']) throw new Error('Invalid candidate proxy');
  }
  return {
    'allow-lan': false, 'bind-address': '127.0.0.1', mode: 'rule', 'log-level': 'silent', ipv6: false,
    'external-controller': `127.0.0.1:${controller}`, secret, tun: { enable: false },
    // Every listener points directly to one node. No DIRECT or fallback group is available.
    listeners: nodes.map((n, i) => ({ name: `probe-${i}`, type: 'mixed', listen: '127.0.0.1', port: ports[i], udp: false, proxy: n.name })),
    proxies: nodes.map(n => n.proxy), 'proxy-groups': [], rules: ['MATCH,REJECT'],
    dns: { enable: true, ipv6: false, 'enhanced-mode': 'redir-host',
      'default-nameserver': ['1.1.1.1', '8.8.8.8'],
      'proxy-server-nameserver': ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
      nameserver: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'] },
  };
}

export async function checkCandidates(candidate, { corePath, coreArgs = [], checker = 'github-actions', concurrency = 8, onProgress = () => {} }) {
  if (!corePath) throw new Error('MIHOMO_PATH is required');
  if (!Array.isArray(coreArgs) || coreArgs.some(value => typeof value !== 'string')) throw new Error('Invalid Mihomo arguments');
  if (!['github-actions', 'local-windows'].includes(checker)) throw new Error('Invalid checker identity');
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 32) throw new Error('Invalid checker concurrency');
  const nodes = candidate.nodes;
  if (!Array.isArray(nodes) || !nodes.length || nodes.length > 120) throw new Error('Invalid candidate count');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'free-node-check-'));
  let core; const activeChildren = new Set(); const startedAt = new Date().toISOString();
  try {
    const ports = []; for (let i = 0; i < nodes.length + 1; i++) { let p; do { p = await freePort(); } while (ports.includes(p)); ports.push(p); }
    const controller = ports.pop(), secret = crypto.randomBytes(24).toString('hex');
    const filename = path.join(directory, 'config.json');
    await fs.writeFile(filename, JSON.stringify(checkerConfig(nodes, ports, controller, secret)), { mode: 0o600 });
    let validIndices = nodes.map((_, i) => i);
    const results = new Array(nodes.length);
    if (!await validateConfig(corePath, coreArgs, directory, filename, activeChildren)) {
      validIndices = [];
      // Isolate rejected proxies instead of letting one malformed cipher/transport stop all candidates.
      for (let i = 0; i < nodes.length; i++) {
        const single = path.join(directory, 'single.json');
        await fs.writeFile(single, JSON.stringify(checkerConfig([nodes[i]], [ports[i]], controller, secret)), { mode: 0o600 });
        if (await validateConfig(corePath, coreArgs, directory, single, activeChildren)) validIndices.push(i);
        else results[i] = { id: nodes[i].id, passed: false };
      }
      if (!validIndices.length) throw new Error('Mihomo rejected every candidate configuration; no health report was created');
      await fs.writeFile(filename, JSON.stringify(checkerConfig(validIndices.map(i => nodes[i]), validIndices.map(i => ports[i]), controller, secret)), { mode: 0o600 });
      if (!await validateConfig(corePath, coreArgs, directory, filename, activeChildren)) throw new Error('Mihomo rejected the remaining batch configuration; no health report was created');
    }
    core = spawn(corePath, [...coreArgs, '-d', directory, '-f', filename], { windowsHide: true, stdio: 'ignore' });
    children.add(core); activeChildren.add(core); let startError; core.on('error', e => { startError = e; });
    const versionUrl = `http://127.0.0.1:${controller}/version`;
    const versionRequest = async timeout => {
      const response = await fetch(versionUrl, { headers: { Authorization: `Bearer ${secret}` }, signal: AbortSignal.timeout(timeout) });
      await response.arrayBuffer();
      if (!response.ok) throw new Error('Controller unavailable');
    };
    const assertCoreAlive = async () => {
      const exited = () => startError || core.exitCode !== null || core.signalCode !== null;
      if (exited()) throw new Error('Mihomo stopped during checks; no health report was created');
      try { await versionRequest(2000); }
      catch { throw new Error('Mihomo controller became unavailable during checks; no health report was created'); }
      if (exited()) throw new Error('Mihomo stopped during checks; no health report was created');
    };
    let ready = false;
    for (let i = 0; i < 60; i++) {
      if (startError || core.exitCode !== null || core.signalCode !== null) throw new Error('Mihomo failed to start');
      try { await versionRequest(500); ready = true; break; } catch {}
      await sleep(150);
    }
    if (!ready) throw new Error('Mihomo startup timed out');
    let next = 0, completed = nodes.length - validIndices.length, checkError;
    if (completed) onProgress({ completed, total: nodes.length, passed: 0, invalidConfig: completed });
    const workers = Array.from({ length: Math.min(concurrency, validIndices.length) }, async () => {
      while (!checkError && next < validIndices.length) {
        const i = validIndices[next++], checks = [];
        for (const target of TARGETS) {
          await assertCoreAlive();
          const result = await probe(ports[i], target, activeChildren);
          await assertCoreAlive();
          if (checkError) return;
          checks.push(result); if (!result.passed) break;
        }
        const passed = checks.length === TARGETS.length && checks.every(r => r.passed);
        results[i] = { id: nodes[i].id, passed, ...(passed ? { latencyMs: Math.max(...checks.map(r => r.latencyMs)) } : {}) };
        completed++; if (completed % 10 === 0 || completed === nodes.length) onProgress({ completed, total: nodes.length, passed: results.filter(r => r?.passed).length });
      }
    });
    try { await Promise.all(workers); }
    catch (error) {
      checkError = error;
      for (const child of activeChildren) if (child !== core) child.kill();
      await Promise.allSettled(workers);
      throw error;
    }
    await assertCoreAlive();
    return { generationId: candidate.generationId, startedAt, finishedAt: new Date().toISOString(), checker, testTargets: TARGETS, results };
  } finally {
    await Promise.all([...activeChildren].map(stopChild));
    await fs.rm(directory, { recursive: true, force: true });
  }
}

export async function fetchCandidateGeneration(request, generationId, { attempts = 15, delayMs = 5000 } = {}) {
  if (typeof generationId !== 'string' || !generationId || generationId.length > 200) throw new Error('Invalid candidate generation ID');
  const route = `/admin/candidates?generationId=${encodeURIComponent(generationId)}`;
  for (let i = 0; i < attempts; i++) {
    try {
      const candidate = await request(route);
      if (candidate?.generationId === generationId) return candidate;
    } catch (error) {
      // Immutable KV generations may need time to reach the checker region. Authentication failures do not.
      if (error.status !== 503) throw error;
    }
    if (i + 1 < attempts) await sleep(delayMs);
  }
  throw new Error('Candidate generation has not propagated; retry next run');
}

async function main() {
  const origin = new URL(process.env.SUBSCRIPTION_ORIGIN || '');
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('Invalid SUBSCRIPTION_ORIGIN');
  const token = process.env.SUBSCRIPTION_ADMIN_TOKEN;
  if (!token) throw new Error('SUBSCRIPTION_ADMIN_TOKEN is required');
  const request = async (route, body) => {
    const r = await fetch(new URL(route, origin), { method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(90000) });
    if (!r.ok) {
      const error = new Error(`Worker request ${route} failed (HTTP ${r.status})`);
      error.status = r.status;
      throw error;
    }
    return r.json();
  };
  const generation = await request('/admin/refresh', {});
  const candidate = await fetchCandidateGeneration(request, generation.generationId);
  const report = await checkCandidates(candidate, { corePath: process.env.MIHOMO_PATH, onProgress: p => console.log(JSON.stringify(p)) });
  const result = await request('/admin/check-results', report);
  console.log(JSON.stringify({ published: true, checked: report.results.length, passed: report.results.filter(r => r.passed).length, checkedAt: report.finishedAt, expiresAt: result.health?.expiresAt }));
  if (process.env.GITHUB_STEP_SUMMARY) await fs.appendFile(process.env.GITHUB_STEP_SUMMARY, `Checked ${report.results.length}; HTTPS passed ${report.results.filter(r => r.passed).length}. Finished: ${report.finishedAt}.\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { for (const child of children) child.kill(); process.exit(1); });
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
