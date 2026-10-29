import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { refresh } from '../src/index.mjs';
import { SOURCES, mergeFreeSources } from '../src/free-sources.mjs';
import { buildFreeMihomo, renderFreeMihomo, GROUP_NAME, AUTO_NAME, TEST_URL } from '../src/free-config.mjs';
import { parseFreeSubscription, renderFreeKaring, renderUriSubscription } from '../src/free-converter.mjs';
import { BLOCKED_ENDPOINTS, isBlockedNode } from '../src/block-policy.mjs';
import { makeHealthySnapshot, CHECK_TARGETS, HEALTH_TTL_MS } from '../src/health-snapshot.mjs';

function environment(initial = {}, failKey = null) {
  const values = new Map(Object.entries(initial));
  const writes = new Map();
  let reads = 0;
  return {
    SUB_TOKEN: 'subscription-test-key', ADMIN_TOKEN: 'admin-test-key', LOGIN_PASSWORD: 'test-login-password', values, writes,
    STORE: {
      async get(key, type) {
        reads++;
        const value = values.get(key) ?? null;
        return value !== null && type === 'json' ? JSON.parse(value) : value;
      },
      async put(key, value, options) {
        if (key === failKey) throw new Error('Storage write failed');
        values.set(key, value); writes.set(key, options);
      },
    },
    readCount: () => reads,
  };
}
const publicNode = 'vless://12345678-1234-4234-8234-123456789abc@node.example.com:443?security=tls&type=ws&host=node.example.com&sni=node.example.com&path=%2Ftest#JP';
const secondNode = 'trojan://test-public-password@other.example.com:443?sni=other.example.com#US';
const deniedEndpoint=BLOCKED_ENDPOINTS.find(n=>n.protocol==='vless'&&!n.server.includes(':'));
const deniedNode=parseFreeSubscription(`vless://12345678-1234-4234-8234-123456789abc@${deniedEndpoint.server}:${deniedEndpoint.port}?security=tls&sni=fixture.example.com#JP`,{sourceId:'fixture',sourceName:'Fixture'}).nodes[0];
const seedTime = Date.now();
const seedCandidate = {
  generationId: 'fixture-generation-0001', createdAt: new Date(seedTime - 120000).toISOString(),
  nodes: parseFreeSubscription(publicNode).nodes, sourceStatus: SOURCES.map(s => ({ ...s, success: true, nodeCount: 1, sourceCount: 1 })),
  sourceCount: 1, skipped: 0, warnings: [],
};
const current = JSON.stringify(makeHealthySnapshot({
  generationId: seedCandidate.generationId, startedAt: new Date(seedTime - 90000).toISOString(), finishedAt: new Date(seedTime - 60000).toISOString(),
  results: seedCandidate.nodes.map(n => ({ id:n.id,passed:true,latencyMs:100 })), checker:'github-actions', testTargets:[...CHECK_TARGETS],
},seedCandidate,null,seedTime));
const auth = { Authorization:'Bearer admin-test-key','Content-Type':'application/json' };
const subscriptionRoutes=['/sub/mihomo.yaml','/sub/provider.yaml','/sub/karing.json','/sub/v2rayn.txt','/sub/v2rayn.yaml','/api/nodes'];
const subRequest=(path,method='GET')=>new Request(`https://example.test${path}?token=subscription-test-key`,{method});
const postReport=(env,report)=>worker.fetch(new Request('https://example.test/admin/check-results',{method:'POST',headers:auth,body:JSON.stringify(report)}),env);
function reportFor(candidate, passes=candidate.nodes.map(n=>n.id),time=Date.now()) {
  return { generationId:candidate.generationId,startedAt:new Date(time-100).toISOString(),finishedAt:new Date(time).toISOString(),checker:'github-actions',testTargets:[...CHECK_TARGETS],results:candidate.nodes.map(n=>({id:n.id,passed:passes.includes(n.id),latencyMs:passes.includes(n.id)?123:null})) };
}
async function prepare(env, text=publicNode+'\n'+secondNode) {
  await refresh(env,async()=>new Response(text));return JSON.parse(env.values.get('candidates'));
}

test('unauthorized users cannot read any protected resource or trigger refresh', async () => {
  const env = environment({ snapshot: current });
  for (const route of ['/sub/mihomo.yaml', '/sub/v2rayn.yaml', '/sub/v2rayn.txt', '/sub/karing.json', '/sub/provider.yaml', '/api/status', '/api/nodes', '/ovpn/vpn-test.ovpn']) {
    const result = await worker.fetch(new Request(`https://example.test${route}`), env);
    assert.equal(result.status, 401);
  }
  const admin = await worker.fetch(new Request('https://example.test/admin/refresh?token=admin-test-key', { method: 'POST' }), env);
  assert.equal(admin.status, 401);
  for(const [route,method] of [['/admin/candidates','GET'],['/admin/check-results','POST']]){
    assert.equal((await worker.fetch(new Request(`https://example.test${route}?token=admin-test-key`,{method}),env)).status,401);
  }
  assert.equal(env.readCount(), 0);
});

test('subscription token reads config but cannot act as admin', async () => {
  const env = environment({ snapshot: current });
  const result = await worker.fetch(new Request('https://example.test/sub/mihomo.yaml?token=subscription-test-key'), env);
  assert.equal(result.status, 200);
  assert.match(result.headers.get('Content-Type'), /yaml/);
  assert.equal(result.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(await result.text(), JSON.parse(current).mihomo);
  const admin = await worker.fetch(new Request('https://example.test/admin/refresh', { method: 'POST', headers: { Authorization: 'Bearer subscription-test-key' } }), env);
  assert.equal(admin.status, 401);
});

test('an upstream failure preserves the exact previous complete snapshot', async () => {
  const env = environment({ snapshot: current });
  await assert.rejects(refresh(env, async (url, options) => {
    assert.equal(options.redirect, 'manual');
    return new Response('Unavailable', { status: 503 });
  }), /All free sources unavailable/);
  assert.equal(env.values.get('snapshot'), current);
  assert.equal(JSON.parse(env.values.get('last-attempt')).success, false);
});

test('invalid upstream data cannot replace the previous snapshot', async () => {
  const env = environment({ snapshot: current });
  await assert.rejects(refresh(env, async () => new Response('<html>not a CSV</html>')));
  assert.equal(env.values.get('snapshot'), current);
});

test('HEAD responses preserve access controls and old OpenVPN profiles are no longer published', async () => {
  const env = environment({ snapshot: current });
  const head = await worker.fetch(new Request('https://example.test/sub/mihomo.yaml?token=subscription-test-key', { method: 'HEAD' }), env);
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  const profile = await worker.fetch(new Request('https://example.test/ovpn/vpn-test.ovpn', { headers: { Authorization: 'Bearer subscription-test-key' } }), env);
  assert.equal(profile.status, 404);
});

test('empty storage reports unavailable without issuing upstream requests', async () => {
  const env = environment();
  const result = await worker.fetch(new Request('https://example.test/sub/mihomo.yaml?token=subscription-test-key'), env);
  assert.equal(result.status, 503);
});

test('arbitrary URLs and proxy paths are not forwarded', async () => {
  const env = environment({ snapshot: current });
  const result = await worker.fetch(new Request('https://example.test/proxy?url=https://example.org'), env);
  assert.equal(result.status, 404);
  assert.equal(env.readCount(), 0);
});

test('the public login page never contains subscription keys or links', async () => {
  const env = environment({ snapshot: current });
  const home = await worker.fetch(new Request('https://example.test/'), env);
  assert.equal(home.status, 303);
  assert.equal(home.headers.get('Location'), '/login');
  const login = await worker.fetch(new Request('https://example.test/login'), env);
  assert.equal(login.status, 200);
  assert.equal(login.headers.get('Referrer-Policy'), 'same-origin');
  const html = await login.text();
  assert.match(html, /type="password"/);
  assert.match(html, /<meta name="referrer" content="same-origin">/);
  assert.ok(!html.includes(env.SUB_TOKEN));
  assert.ok(!html.includes(env.LOGIN_PASSWORD));
});

test('correct password creates a signed secure session and reveals copyable links', async () => {
  const env = environment({ snapshot: current });
  const login = await worker.fetch(new Request('https://example.test/login', {
    method: 'POST', headers: { Origin: 'https://example.test', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ password: env.LOGIN_PASSWORD }),
  }), env);
  assert.equal(login.status, 303);
  const setCookie = login.headers.get('Set-Cookie');
  assert.match(setCookie, /__Host-vpngate_session=/);
  assert.match(setCookie, /Secure; HttpOnly; SameSite=Strict/);
  const cookie = setCookie.split(';')[0];
  const dashboard = await worker.fetch(new Request('https://example.test/', { headers: { Cookie: cookie } }), env);
  assert.equal(dashboard.status, 200);
  const html = await dashboard.text();
  assert.ok(html.includes(`/sub/mihomo.yaml?token=${env.SUB_TOKEN}`));
  assert.ok(html.includes(`/sub/provider.yaml?token=${env.SUB_TOKEN}`));
  assert.ok(html.includes(`/sub/karing.json?token=${env.SUB_TOKEN}`));
  assert.ok(html.includes(`/sub/v2rayn.txt?token=${env.SUB_TOKEN}`));
  assert.match(html, /Base64/);
  assert.doesNotMatch(html, /OpenVPN/);
  assert.ok(!html.includes(env.LOGIN_PASSWORD));
  assert.match(dashboard.headers.get('Content-Security-Policy'), /script-src 'nonce-/);
  assert.equal(dashboard.headers.get('Referrer-Policy'), 'same-origin');
  assert.match(html, /<meta name="referrer" content="same-origin">/);
  const loginAgain = await worker.fetch(new Request('https://example.test/login', { headers: { Cookie: cookie } }), env);
  assert.equal(loginAgain.status, 303);
  assert.equal(loginAgain.headers.get('Location'), '/');
});

test('wrong passwords, forged cookies and foreign-origin login requests are rejected', async () => {
  const env = environment({ snapshot: current });
  const wrong = await worker.fetch(new Request('https://example.test/login', {
    method: 'POST', body: new URLSearchParams({ password: 'wrong' }),
  }), env);
  assert.equal(wrong.status, 401);
  assert.equal(wrong.headers.get('Set-Cookie'), null);
  const forged = await worker.fetch(new Request('https://example.test/', {
    headers: { Cookie: `__Host-vpngate_session=${Math.floor(Date.now() / 1000) + 1000}.${'a'.repeat(24)}.${'b'.repeat(43)}` },
  }), env);
  assert.equal(forged.status, 303);
  assert.equal(forged.headers.get('Location'), '/login');
  const csrf = await worker.fetch(new Request('https://example.test/login', {
    method: 'POST', headers: { Origin: 'https://other.test' },
    body: new URLSearchParams({ password: env.LOGIN_PASSWORD }),
  }), env);
  assert.equal(csrf.status, 403);
  const nullOrigin = await worker.fetch(new Request('https://example.test/login', {
    method: 'POST', headers: { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' },
    body: new URLSearchParams({ password: env.LOGIN_PASSWORD }),
  }), env);
  assert.equal(nullOrigin.status, 403);
});

test('logout clears the browser session and redirects to login', async () => {
  const env = environment({ snapshot: current });
  const result = await worker.fetch(new Request('https://example.test/logout', { method: 'POST' }), env);
  assert.equal(result.status, 303);
  assert.equal(result.headers.get('Location'), '/login');
  assert.match(result.headers.get('Set-Cookie'), /Max-Age=0/);
});

test('Karing receives checked native outbounds and missing formats are unavailable', async () => {
  const env = environment({ snapshot: current });
  const result = await worker.fetch(new Request('https://example.test/sub/karing.json?token=subscription-test-key'), env);
  assert.equal(result.status, 200);
  assert.match(result.headers.get('Content-Type'), /application\/json/);
  assert.equal((await result.json()).outbounds[0].type, 'vless');
  const older = JSON.parse(current);
  delete older.karing;
  const oldEnv = environment({ snapshot: JSON.stringify(older) });
  const pending = await worker.fetch(new Request('https://example.test/sub/karing.json?token=subscription-test-key'), oldEnv);
  assert.equal(pending.status, 503);
});

test('v2rayN gets the complete Mihomo config with matching download metadata', async () => {
  const env = environment({ snapshot: current });
  const result = await worker.fetch(new Request('https://example.test/sub/v2rayn.yaml?token=subscription-test-key'), env);
  assert.equal(result.status, 200);
  assert.match(result.headers.get('Content-Type'), /yaml/);
  assert.match(result.headers.get('Content-Disposition'), /vpngate-v2rayn.yaml/);
  assert.equal(result.headers.get('profile-title'), 'Free Nodes Mihomo');
  assert.equal(await result.text(), JSON.parse(current).mihomo);
});

test('refresh fetches fixed publishers and creates immutable candidates without publishing unchecked nodes', async () => {
  const env = environment({ snapshot: current });
  const called = [];
  const status = await refresh(env, async (url, options) => {
    called.push(url); assert.equal(options.redirect, 'manual');
    const source = SOURCES.find(s => s.url === url);
    const feeds = {
      mibei:'https://aa.mibei77.com/202610/test.txt',
      hiddifynext:'https://hiddify-next-node.github.io/uploads/2026/10/test.txt',
      freeclashnode:'https://node.freeclashnode.com/uploads/2026/10/test.txt',
      endgfw:'https://raw.githubusercontent.com/hello-world-1989/cn-news/main/end-gfw-free',
      v2raydog:'https://nodesub.v2raydog.com/2026/10/v2raydog-20261029.txt',
      cfmem:'https://nodebuf.com/node-sub/'+ 'a'.repeat(64) +'/v2ray',
      freev2:'https://test.503403.xyz/',
    };
    if(source?.kind) {
      const articles = {mibei:'/784.html',hiddifynext:'/free-nodes/2026-10-29-node.htm',freeclashnode:'/free-node/2026-10-29-node.htm',v2raydog:'/freenode/2026-10-29/',cfmem:'/2026/10/20261029-node.html'};
      return new Response(articles[source.kind] ? `<a href='${articles[source.kind]}'>latest</a>` : `<button data-clipboard-text='${feeds[source.kind]}'>copy</button><code>${feeds[source.kind]}</code>`);
    }
    const kind=url.includes('/784.html')?'mibei':url.includes('/free-nodes/')?'hiddifynext':url.includes('/free-node/')?'freeclashnode':url.includes('/freenode/')?'v2raydog':url.endsWith('20261029-node.html')?'cfmem':null;
    if(kind) return new Response(`<code>${feeds[kind]}</code>`);
    return new Response(btoa(publicNode));
  });
  assert.ok(SOURCES.every(s=>called.includes(s.url)));
  assert.ok(called.length<=45);
  assert.equal(status.candidateCount, 1); // Identical endpoints shared by sources deduplicate.
  assert.equal(status.trafficRelay, false);
  assert.equal(status.sourceStatus.filter(s => s.success).length, SOURCES.length);
  assert.equal(env.values.get('snapshot'),current);
  assert.ok(!JSON.stringify(status).includes('12345678-1234-4234-8234-123456789abc'));
  const candidate=JSON.parse(env.values.get('candidates'));
  assert.deepEqual(JSON.parse(env.values.get(`candidate:${status.generationId}`)),candidate);
  assert.equal(env.writes.get(`candidate:${status.generationId}`).expirationTtl,14400);
  assert.equal(env.writes.get('candidates').expirationTtl,14400);
  assert.equal(candidate.nodes[0].proxy.type,'vless');
});

test('one failed source does not prevent valid sources replacing the generation', async () => {
  const env = environment({ snapshot: current });
  const status = await refresh(env, async url => url === SOURCES[0].url ? new Response('bad', { status: 503 }) : new Response(publicNode));
  assert.equal(status.candidateCount, 1);
  assert.equal(status.sourceStatus[0].success, false);
  assert.equal(status.sourceStatus[0].error, 'HTTP 503');
  assert.equal(JSON.parse(env.values.get('last-attempt')).success, true);
});

test('failed daily fetches can use authenticated checker URI supplements without publishing unchecked data', async () => {
  const env=environment({snapshot:current});
  const result=await refresh(env,async url=>url===SOURCES[0].url?new Response(publicNode):new Response('',{status:503}),[{sourceId:'freev2',subscription:secondNode,articleUrl:'https://b.freev2.net/'}]);
  assert.equal(result.candidateCount,2);
  assert.equal(result.sourceStatus.find(s=>s.id==='freev2').fetchedBy,'github-actions');
  assert.equal(env.values.get('snapshot'),current);
  assert.equal(JSON.parse(env.values.get('candidates')).nodes.find(n=>n.sourceId==='freev2').protocol,'trojan');
});

test('FreeV2 transient failures reuse recent source data without extending its lifetime or bypassing checks', async () => {
  const at=new Date(Date.now()-60000).toISOString();
  const cache={at,sourceId:'freev2',subscription:secondNode,articleUrl:'https://b.freev2.net/',feedCount:1,fetchedFeedCount:1};
  const env=environment({snapshot:current,'daily-source:freev2':JSON.stringify(cache)});
  const fetcher=async url=>url===SOURCES[0].url?new Response(publicNode):new Response('',{status:503});
  const result=await refresh(env,fetcher);
  assert.equal(result.sourceStatus.find(s=>s.id==='freev2').fetchedBy,'recent-source-cache');
  assert.equal(env.values.get('daily-source:freev2'),JSON.stringify(cache));
  assert.equal(env.values.get('snapshot'),current);
  cache.at=new Date(Date.now()-7200001).toISOString();env.values.set('daily-source:freev2',JSON.stringify(cache));
  const expired=await refresh(env,fetcher);
  assert.equal(expired.sourceStatus.find(s=>s.id==='freev2').success,false);
});

test('supplemental source ingestion is admin-only and rejects proxy objects and unknown request fields', async () => {
  const env=environment({snapshot:current});
  for (const input of [{supplements:[{sourceId:'freev2',proxy:{type:'direct'}}]},{url:'https://evil.example/'}]) {
    const result=await worker.fetch(new Request('https://example.test/admin/refresh',{method:'POST',headers:auth,body:JSON.stringify(input)}),env);
    assert.equal(result.status,400);
  }
  const unauth=await worker.fetch(new Request('https://example.test/admin/refresh',{method:'POST',body:'{}'}),env);
  assert.equal(unauth.status,401);assert.equal(env.values.get('snapshot'),current);
});

test('failed atomic snapshot writes retain the complete previous generation', async () => {
  const env = environment({ snapshot: current }, 'snapshot');
  const candidate=await prepare(env);
  const result=await postReport(env,reportFor(candidate));
  assert.equal(result.status,502);
  assert.equal(env.values.get('snapshot'), current);
});

test('source balancing and local automatic tests never add a traffic relay', () => {
  const node = id => ({ id, proxy: { name: id, type: 'vless' } });
  const merged = mergeFreeSources([{ nodes: [node('a'), node('b'), node('c')] }, { nodes: [node('a'), node('x')] }, { nodes: [node('y')] }], 4);
  assert.deepEqual(merged.map(n => n.id), ['a','y','b','x']);
  const config = buildFreeMihomo(merged);
  assert.equal(config['proxy-groups'][0].name, GROUP_NAME);
  assert.equal(config['proxy-groups'][0].proxies[0], AUTO_NAME);
  assert.equal(config['proxy-groups'][1].url, TEST_URL);
  assert.equal(config['proxy-groups'][1].type, 'url-test');
  assert.deepEqual(config.rules, [`MATCH,${GROUP_NAME}`]);
  assert.deepEqual(buildFreeMihomo(merged, { providerOnly: true }), { proxies: merged.map(n => n.proxy) });
});

test('checker candidates and result publication require the administrator bearer token', async () => {
  const env=environment();const candidate=await prepare(env);
  const endpoint='https://example.test/admin/candidates';
  assert.equal((await worker.fetch(new Request(endpoint,{headers:{Authorization:'Bearer subscription-test-key'}}),env)).status,401);
  const response=await worker.fetch(new Request(endpoint,{headers:auth}),env);
  assert.equal(response.status,200);assert.equal(response.headers.get('Cache-Control'),'private, no-store');
  assert.deepEqual(await response.json(),candidate);
  const bad=await worker.fetch(new Request('https://example.test/admin/check-results',{method:'POST',headers:{Authorization:'Bearer subscription-test-key'},body:JSON.stringify(reportFor(candidate))}),env);
  assert.equal(bad.status,401);assert.equal(env.values.has('snapshot'),false);
  assert.equal((await worker.fetch(new Request(endpoint,{method:'POST',headers:auth}),env)).status,405);
  assert.equal((await worker.fetch(new Request('https://example.test/admin/check-results',{headers:auth}),env)).status,405);
});

test('a complete health report publishes only passed candidates in every format', async () => {
  const env=environment({snapshot:current});const candidate=await prepare(env);
  assert.equal(candidate.nodes.length,2);
  const allowed=candidate.nodes[1], blocked=candidate.nodes[0];
  const response=await postReport(env,reportFor(candidate,[allowed.id]));
  assert.equal(response.status,200);const published=await response.json();
  assert.equal(published.nodeCount,1);assert.equal(published.health.checker,'github-actions');
  assert.equal(published.health.checkedCount,2);assert.equal(published.health.passedCount,1);assert.equal(published.health.failedCount,1);
  assert.equal(Date.parse(published.health.expiresAt)-Date.parse(published.health.checkedAt),HEALTH_TTL_MS);
  const snap=JSON.parse(env.values.get('snapshot'));
  assert.deepEqual(snap.nodes.nodes.map(n=>n.id),[allowed.id]);assert.equal(snap.nodes.nodes[0].latencyMs,123);
  for(const field of ['mihomo','provider']) {assert.ok(snap[field].includes(allowed.name));assert.ok(!snap[field].includes(blocked.name));}
  assert.deepEqual(JSON.parse(snap.karing).outbounds.map(n=>n.tag),[allowed.name]);
  assert.equal(atob(snap.uris.trim()).trim(),allowed.uri);
  for(const route of subscriptionRoutes) assert.equal((await worker.fetch(subRequest(route),env)).status,200,route);
  const status=await (await worker.fetch(subRequest('/api/status'),env)).json();
  assert.equal(status.available,true);assert.equal(status.clientConnectivityTested,true);assert.equal(status.nodeCount,1);
  assert.equal(status.candidateStatus.candidateCount,2);
});

test('an in-flight old generation cannot republish blocked endpoints even when its checks pass', async () => {
  const env=environment({snapshot:current});
  const candidate={...seedCandidate,generationId:'blocked-old-generation-01',nodes:[...seedCandidate.nodes,deniedNode]};
  env.values.set(`candidate:${candidate.generationId}`,JSON.stringify(candidate));
  const result=await postReport(env,reportFor(candidate));
  assert.equal(result.status,200);
  const snap=JSON.parse(env.values.get('snapshot'));
  assert.equal(snap.health.checkedCount,2);assert.equal(snap.health.passedCount,1);
  assert.equal(snap.health.failedCount,1);assert.equal(snap.health.policyBlockedCount,1);
  assert.ok(!parseFreeSubscription(snap.uris).nodes.some(isBlockedNode));
});

function legacyBlockedSnapshot(onlyBlocked=false) {
  const snap=JSON.parse(current), nodes=onlyBlocked?[deniedNode]:[...seedCandidate.nodes,deniedNode];
  snap.health={...snap.health,checkedCount:nodes.length,passedCount:nodes.length,failedCount:0};
  snap.status={...snap.status,health:snap.health,nodeCount:nodes.length,karingNodeCount:nodes.length};
  snap.uris=renderUriSubscription(nodes);snap.karing=renderFreeKaring(nodes);
  snap.mihomo=renderFreeMihomo(nodes);snap.provider=renderFreeMihomo(nodes,{providerOnly:true});
  snap.nodes={updatedAt:snap.health.checkedAt,nodes:nodes.map(({id,name,country,countryLong,ip,protocol,sourceId})=>({id,name,country,countryLong,ip,protocol,sourceId}))};
  return snap;
}

test('new policy removes cached endpoints from every format without resetting real check timestamps', async () => {
  const legacy=legacyBlockedSnapshot(), env=environment({snapshot:JSON.stringify(legacy)});
  const status=await (await worker.fetch(subRequest('/api/status'),env)).json();
  assert.equal(status.nodeCount,1);assert.equal(status.health.policyBlockedCount,1);
  assert.equal(status.health.checkedAt,legacy.health.checkedAt);assert.equal(status.health.expiresAt,legacy.health.expiresAt);
  const native=await (await worker.fetch(subRequest('/sub/v2rayn.txt'),env)).text();
  assert.equal(parseFreeSubscription(native).nodes.length,1);assert.ok(!parseFreeSubscription(native).nodes.some(isBlockedNode));
  const karing=await (await worker.fetch(subRequest('/sub/karing.json'),env)).json();
  assert.equal(karing.outbounds.length,1);assert.ok(!karing.outbounds.some(outbound=>isBlockedNode({outbound})));
  for(const route of ['/sub/mihomo.yaml','/sub/provider.yaml','/sub/v2rayn.yaml']) {
    const text=await (await worker.fetch(subRequest(route),env)).text();assert.ok(!text.includes(deniedNode.name));
  }
  const metadata=await (await worker.fetch(subRequest('/api/nodes'),env)).json();assert.equal(metadata.nodes.length,1);
  assert.equal(env.values.get('snapshot'),JSON.stringify(legacy),'read filtering must not overwrite a concurrent checked snapshot');
});

test('a cache consisting only of blocked nodes becomes empty and expired checks remain expired', async () => {
  const legacy=legacyBlockedSnapshot(true), env=environment({snapshot:JSON.stringify(legacy)});
  for(const route of subscriptionRoutes) assert.equal((await worker.fetch(subRequest(route),env)).status,503);
  const checked=Date.now()-HEALTH_TTL_MS-1000;
  legacy.health={...legacy.health,checkedAt:new Date(checked).toISOString(),expiresAt:new Date(checked+HEALTH_TTL_MS).toISOString()};legacy.status.health=legacy.health;
  env.values.set('snapshot',JSON.stringify(legacy));
  const status=await (await worker.fetch(subRequest('/api/status'),env)).json();
  assert.equal(status.health.state,'expired');assert.equal(status.health.checkedAt,legacy.health.checkedAt);
});

test('zero passing nodes replace the old snapshot and all subscription routes fail closed', async () => {
  const env=environment({snapshot:current});const candidate=await prepare(env);
  assert.equal((await postReport(env,reportFor(candidate,[]))).status,200);
  const snap=JSON.parse(env.values.get('snapshot'));
  assert.equal(snap.mihomo,null);assert.equal(snap.karing,null);assert.equal(snap.uris,null);assert.deepEqual(snap.nodes.nodes,[]);
  for(const route of subscriptionRoutes){
    const response=await worker.fetch(subRequest(route),env);assert.equal(response.status,503,route);
    assert.equal((await response.json()).code,'NoHealthyNodes');
  }
  const status=await (await worker.fetch(subRequest('/api/status'),env)).json();
  assert.equal(status.nodeCount,0);assert.equal(status.health.state,'empty');assert.equal(status.health.failedCount,2);
  const head=await worker.fetch(subRequest('/sub/mihomo.yaml','HEAD'),env);assert.equal(head.status,503);assert.equal(await head.text(),'');
});

test('old untested snapshots and empty storage cannot expose credentials through any subscription', async () => {
  const untested=JSON.parse(current);delete untested.health;delete untested.status.health;
  for(const initial of [{},{snapshot:JSON.stringify(untested)}]){
    const env=environment(initial);
    for(const route of [...subscriptionRoutes,'/ovpn/vpn-test.ovpn']){
      const response=await worker.fetch(subRequest(route),env);assert.equal(response.status,503,route);
      const text=await response.text();assert.ok(!text.includes('12345678-1234-4234-8234-123456789abc'));
      assert.equal(JSON.parse(text).code,'HealthCheckRequired');
    }
    const response=await worker.fetch(subRequest('/api/status'),env);assert.equal(response.status,200);
    const status=await response.json();assert.equal(status.nodeCount,0);assert.equal(status.health.state,'pending');assert.equal(status.health.available,false);
  }
});

test('health expiry is enforced at read time while status remains available', async () => {
  const old=JSON.parse(current);const checked=Date.now()-HEALTH_TTL_MS-1000;
  old.health.checkedAt=new Date(checked).toISOString();old.health.expiresAt=new Date(checked+HEALTH_TTL_MS).toISOString();old.status.health=old.health;
  const env=environment({snapshot:JSON.stringify(old)});
  for(const route of subscriptionRoutes){
    const response=await worker.fetch(subRequest(route),env);assert.equal(response.status,503,route);assert.equal((await response.json()).code,'HealthCheckExpired');
  }
  const response=await worker.fetch(subRequest('/api/status'),env);assert.equal(response.status,200);
  const status=await response.json();assert.equal(status.nodeCount,0);assert.equal(status.karingNodeCount,0);assert.equal(status.health.stale,true);assert.equal(status.available,false);
});

test('partial, duplicate, forged, stale and unsupported check reports cannot replace health', async () => {
  const env=environment({snapshot:current});const candidate=await prepare(env);
  const mutations=[
    r=>{r.results.pop();},
    r=>{r.results[1]={...r.results[0]};},
    r=>{r.results[0].id='free-unknown';},
    r=>{r.results[0].passed='true';},
    r=>{delete r.results[0].latencyMs;},
    r=>{r.results[0].latencyMs=60001;},
    r=>{r.results[0].latencyMs=-1;},
    r=>{r.results[0].latencyMs=null;},
    r=>{r.results[0].proxy={server:'attacker.example.com'};},
    r=>{r.checker='unknown-checker';},
    r=>{r.testTargets=['http://example.com/'];},
    r=>{r.testTargets=[CHECK_TARGETS[0],CHECK_TARGETS[0]];},
    r=>{r.finishedAt=new Date(Date.now()+120000).toISOString();},
    r=>{r.startedAt=new Date(Date.now()-31*60000).toISOString();},
    r=>{r.startedAt=new Date(Date.parse(candidate.createdAt)-61000).toISOString();},
    r=>{r.startedAt=new Date(Date.now()+30000).toISOString();},
    r=>{r.startedAt='2026';},
    r=>{r.extra='arbitrary';},
  ];
  for(const mutate of mutations){const report=reportFor(candidate);mutate(report);const response=await postReport(env,report);assert.equal(response.status,400,JSON.stringify(report));assert.equal(env.values.get('snapshot'),current);}
  const absent=reportFor(candidate);absent.generationId='unknown-generation-0001';
  assert.equal((await postReport(env,absent)).status,409);assert.equal(env.values.get('snapshot'),current);
});

test('malformed and oversized reports are bounded before publication', async () => {
  const env=environment({snapshot:current});
  const malformed=await worker.fetch(new Request('https://example.test/admin/check-results',{method:'POST',headers:auth,body:'not json'}),env);
  assert.equal(malformed.status,400);
  const oversized=await worker.fetch(new Request('https://example.test/admin/check-results',{method:'POST',headers:auth,body:JSON.stringify({padding:'x'.repeat(256*1024)})}),env);
  assert.equal(oversized.status,413);assert.equal(env.values.get('snapshot'),current);
});

test('a refreshed candidate pointer does not invalidate an in-flight immutable generation', async () => {
  const env=environment({snapshot:current});const first=await prepare(env);const second=await prepare(env,secondNode);
  assert.notEqual(first.generationId,second.generationId);
  const selected=await worker.fetch(new Request(`https://example.test/admin/candidates?generationId=${first.generationId}`,{headers:auth}),env);
  assert.equal(selected.status,200);assert.deepEqual(await selected.json(),first);
  const report=reportFor(first);report.checker='local-windows';
  assert.equal((await postReport(env,report)).status,200);
  assert.equal(JSON.parse(env.values.get('snapshot')).health.generationId,first.generationId);
  const latest=await worker.fetch(new Request('https://example.test/admin/candidates',{headers:auth}),env);
  assert.equal((await latest.json()).generationId,second.generationId);
});

test('explicit candidate generation lookup validates identifiers and never falls back to current', async () => {
  const env=environment();await prepare(env);
  for(const id of ['', 'short', 'x'.repeat(65), '../snapshot', 'bad:'.repeat(5)]){
    const response=await worker.fetch(new Request(`https://example.test/admin/candidates?generationId=${encodeURIComponent(id)}`,{headers:auth}),env);
    assert.equal(response.status,400);
  }
  const response=await worker.fetch(new Request('https://example.test/admin/candidates?generationId=unavailable-generation-0001',{headers:auth}),env);
  assert.equal(response.status,503);assert.equal((await response.json()).code,'NoCandidates');
  const unauthorized=await worker.fetch(new Request('https://example.test/admin/candidates?generationId=unavailable-generation-0001&token=administrator-test-key'),env);
  assert.equal(unauthorized.status,401);
});

test('older completed reports and older generations cannot overwrite newer published health', async () => {
  const env=environment({snapshot:current});const first=await prepare(env);const second=await prepare(env,secondNode);
  const now=Date.now();first.createdAt=new Date(now-2000).toISOString();second.createdAt=new Date(now-1000).toISOString();
  env.values.set(`candidate:${first.generationId}`,JSON.stringify(first));env.values.set(`candidate:${second.generationId}`,JSON.stringify(second));
  const newest=reportFor(second,[second.nodes[0].id],now);
  assert.equal((await postReport(env,newest)).status,200);const published=env.values.get('snapshot');
  assert.equal((await postReport(env,reportFor(second,[],now-1))).status,409);
  assert.equal((await postReport(env,reportFor(first,[],now+1))).status,409);
  assert.equal((await postReport(env,newest)).status,409);
  assert.equal(env.values.get('snapshot'),published);
});
