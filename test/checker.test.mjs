import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { TARGETS, verifyProbe, checkerConfig, checkCandidates, fetchCandidateGeneration } from '../checker/check.mjs';
test('probe requires successful TLS, expected HTTPS status and trace content', () => {
  assert.equal(verifyProbe(TARGETS[0], 0, 'ip=8.8.8.8\n\n__PROBE__200\t0.123\t0').passed, true);
  assert.equal(verifyProbe(TARGETS[1], 0, '\n__PROBE__204\t0.123\t0').passed, true);
  for (const [code, output] of [[60, 'ip=8.8.8.8\n__PROBE__200\t.1\t0'], [0, 'ip=8.8.8.8\n__PROBE__200\t.1\t60'], [0, '<html>login</html>\n__PROBE__200\t.1\t0'], [0, 'ip=8.8.8.8\n__PROBE__302\t.1\t0']]) assert.equal(verifyProbe(TARGETS[0], code, output).passed, false);
  assert.equal(verifyProbe(TARGETS[1], 0, 'portal\n__PROBE__200\t.1\t0').passed, false);
});
test('checker listeners force individual nodes with no direct fallback', () => {
  const nodes = [{ id: 'free-1234567890abcdef', name: 'node', proxy: { name: 'node', type: 'ss', server: '1.1.1.1', port: 443 } }];
  const config = checkerConfig(nodes, [19001], 19002, 'test');
  assert.equal(config.listeners[0].proxy, 'node');
  assert.equal(config.listeners[0].listen, '127.0.0.1');
  assert.deepEqual(config.rules, ['MATCH,REJECT']);
  assert.equal(config.tun.enable, false);
  assert.throws(() => checkerConfig([{ ...nodes[0], proxy: { name: 'node', type: 'direct' } }], [1], 2, ''));
  assert.throws(() => checkerConfig([nodes[0], nodes[0]], [1, 2], 3, ''));
});

// A local CLI fixture exercises process validation/liveness without external proxy traffic.
const fakeCore = String.raw`
import fs from 'node:fs/promises';
import http from 'node:http';
const args = process.argv.slice(2);
const arg = flag => args[args.indexOf(flag) + 1];
const config = JSON.parse(await fs.readFile(arg('-f'), 'utf8'));
const phase = args.includes('-t') ? 'validate' : 'runtime';
await fs.appendFile(arg('--fixture-log'), JSON.stringify({phase, names:config.proxies.map(p=>p.name), proxyCount:config.proxies.length, listenerCount:config.listeners.length})+'\n');
if (phase === 'validate') {
  if(config.proxies.some(p => p.cipher === 'impossible-cipher')) {
    console.error('Synthetic credential diagnostic that must never be forwarded');
    process.exit(1);
  }
  process.exit(0);
}
const listen = (server, port) => new Promise((resolve,reject) => {server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
for(const listener of config.listeners) {
  const server = http.createServer((req,res)=>{res.writeHead(502);res.end();});
  server.on('connect',(req,socket)=>{
    if(arg('--fixture-mode')==='crash') {setTimeout(()=>process.exit(23),30);return;}
    socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
  });
  await listen(server,listener.port);
}
const api=http.createServer((req,res)=>{
  if(req.headers.authorization !== 'Bearer '+config.secret) {res.writeHead(401);res.end();return;}
  res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({version:'fixture',meta:true}));
});
await listen(api,Number(config['external-controller'].split(':').at(-1)));
`;

async function fixture(t, mode = 'normal') {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'free-checker-fixture-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const executable = path.join(directory, 'core.mjs'), log = path.join(directory, 'calls.jsonl');
  await fs.writeFile(executable, fakeCore, { mode: 0o600 });
  return { directory, log, options: { corePath: process.execPath, coreArgs: [executable, '--fixture-log', log, '--fixture-mode', mode], checker: 'local-windows', concurrency: 1 } };
}

const candidateNode = (suffix, name, cipher = 'aes-128-gcm') => ({
  id: `free-1234567890abcde${suffix}`, name,
  proxy: { name, type: 'ss', server: '1.1.1.1', port: 443, cipher, password: 'synthetic-test-password' },
});

test('one rejected proxy is isolated and remaining nodes are still checked', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  const nodes = [candidateNode('1', 'valid'), candidateNode('2', 'bad', 'impossible-cipher')];
  const progress = [];
  const report = await checkCandidates({ generationId: 'test-generation', nodes }, { ...f.options, onProgress: p => progress.push(p) });
  assert.equal(report.results.length, 2);
  assert.deepEqual(report.results[1], { id: nodes[1].id, passed: false });
  // The fixture deliberately rejects external CONNECT requests, so valid syntax alone cannot pass.
  assert.deepEqual(report.results[0], { id: nodes[0].id, passed: false });
  const calls = (await fs.readFile(f.log, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(calls.filter(c => c.phase === 'validate').map(c => c.names), [['valid', 'bad'], ['valid'], ['bad'], ['valid']]);
  assert.deepEqual(calls.filter(c => c.phase === 'runtime').map(c => [c.names, c.proxyCount, c.listenerCount]), [[['valid'], 1, 1]]);
  assert.ok(progress.some(p => p.invalidConfig === 1));
  assert.equal(progress.at(-1).completed, nodes.length);
});

test('all rejected configurations abort instead of returning an all-failed health report', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  await assert.rejects(checkCandidates({ generationId: 'all-invalid', nodes: [candidateNode('1', 'bad', 'impossible-cipher')] }, f.options), /rejected every candidate configuration/);
  const calls = (await fs.readFile(f.log, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(calls.every(c => c.phase === 'validate'));
});

test('a core that crashes during the HTTPS probe aborts the report', { timeout: 15000 }, async t => {
  const f = await fixture(t, 'crash');
  await assert.rejects(checkCandidates({ generationId: 'crash', nodes: [candidateNode('1', 'valid')] }, f.options), /Mihomo (?:stopped|controller became unavailable) during checks/);
  const calls = (await fs.readFile(f.log, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(calls.filter(c => c.phase === 'runtime').length, 1);
});

test('missing core is an infrastructure error and cannot produce a health report', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  await assert.rejects(checkCandidates({ generationId: 'missing', nodes: [candidateNode('1', 'valid')] }, { ...f.options, corePath: path.join(f.directory, 'missing-core-executable') }), /configuration checker failed to start/);
});

test('candidate fetch addresses one immutable generation and retries only temporary propagation failures', async () => {
  const generationId = 'generation/test?exact';
  const routes = [];
  const candidate = await fetchCandidateGeneration(async route => {
    routes.push(route);
    if (routes.length < 3) throw Object.assign(new Error('not propagated'), { status: 503 });
    return { generationId, nodes: [] };
  }, generationId, { attempts: 3, delayMs: 0 });
  assert.equal(candidate.generationId, generationId);
  assert.deepEqual(routes, new Array(3).fill('/admin/candidates?generationId=generation%2Ftest%3Fexact'));
  let calls = 0;
  await assert.rejects(fetchCandidateGeneration(async () => {
    calls++; throw Object.assign(new Error('Unauthorized'), { status: 401 });
  }, generationId, { attempts: 3, delayMs: 0 }), error => error.status === 401);
  assert.equal(calls, 1);
});

test('a wrong or still unavailable candidate generation is never accepted', async () => {
  let calls = 0;
  await assert.rejects(fetchCandidateGeneration(async () => {
    calls++;
    if (calls === 1) return { generationId: 'different-generation' };
    throw Object.assign(new Error('not propagated'), { status: 503 });
  }, 'expected-generation', { attempts: 2, delayMs: 0 }), /has not propagated/);
  assert.equal(calls, 2);
});
