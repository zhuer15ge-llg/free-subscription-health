import test from 'node:test';
import assert from 'node:assert/strict';
import { SOURCES } from '../src/free-sources.mjs';
import { decodeHtml, discoverArticles, discoverFeeds, readSourceText, loadFreeSource, parseSourceSupplements } from '../src/source-loader.mjs';
const source = id => SOURCES.find(s => s.id === id);
const uri = host => `vless://11111111-2222-4333-8444-555555555555@${host}:443?security=tls&sni=${host}#JP`;

test('daily articles use the newest dated URL and ignore sidebar order, fragments, foreign sites and scripts', () => {
  const html = `<a href='/free-node/2026-10-27-node.htm'>old</a><a href='/free-node/2026-10-29-node.htm#x'>new</a><a href='https://evil.example/free-node/2029-10-29-node.htm'>ad</a><script>"https://www.freeclashnode.com/free-node/2030-10-29-node.htm"</script>`;
  assert.deepEqual(discoverArticles(source('freeclashnode'), html), ['https://www.freeclashnode.com/free-node/2026-10-29-node.htm','https://www.freeclashnode.com/free-node/2026-10-27-node.htm']);
  assert.deepEqual(discoverArticles(source('mibei'), '<a href="/780.html">old</a><a href="/784.html">new</a>'), ['https://www.mibei77.com/784.html','https://www.mibei77.com/780.html']);
  assert.deepEqual(discoverArticles(source('freeclashnode'), '<a href="/free-node/2026-10-31-node.htm">old</a><a href="/free-node/2026-11-1-node.htm">new</a>'), ['https://www.freeclashnode.com/free-node/2026-11-1-node.htm','https://www.freeclashnode.com/free-node/2026-10-31-node.htm']);
  assert.deepEqual(discoverArticles(source('cfmem'), '<a href="/2026/10/20261028-node.html">old</a><a href="/2026/10/20261029-node.html">new</a>'), ['https://www.cfmem.com/2026/10/20261029-node.html','https://www.cfmem.com/2026/10/20261028-node.html']);
});

test('all native feeds in daily articles are selected; YAML, advertising, credentials and foreign fetch destinations are excluded', () => {
  const root = 'https://node.freeclashnode.com/uploads/2026/10/';
  const html = `<p>${root}0-20261029.txt</p><a href='${root}1-20261029.txt'>second</a><a href='${root}1-20261029.yaml'>yaml</a><a href='https://evil.example/f.txt'>ad</a><a href='https://u:p@node.freeclashnode.com/uploads/2026/10/a.txt'>auth</a>`;
  assert.deepEqual(discoverFeeds(source('freeclashnode'),html), [root+'1-20261029.txt',root+'0-20261029.txt']);
  assert.equal(decodeHtml('a&amp;b&#46;c&#x2f;d'), 'a&b.c/d');
  assert.deepEqual(discoverFeeds(source('freev2'), `<button data-clipboard-text='https://today.503403.xyz'>copy</button><button data-clipboard-text='http://127.0.0.1/'>bad</button><button data-clipboard-text='https://evil.example'>ad</button>`),['https://today.503403.xyz/']);
});

test('publisher-specific layouts cover the remaining daily sources', () => {
  for (const [id,url] of [
    ['mibei','https://aa.mibei77.com/202610/10.2964baver.txt'],
    ['hiddifynext','https://hiddify-next-node.github.io/uploads/2026/10/0-20261029.txt'],
    ['endgfw','https://raw.githubusercontent.com/hello-world-1989/cn-news/main/end-gfw-free'],
    ['v2raydog','https://nodesub.v2raydog.com/2026/10/v2raydog-20261029.txt'],
    ['cfmem','https://nodebuf.com/node-sub/'+ 'a'.repeat(64) +'/v2ray'],
  ]) assert.deepEqual(discoverFeeds(source(id), `<button data-copy='${url}'><code>${url}</code></button>`),[url]);
  const preview='https://nodebuf.com/files/public/cmvrcltd8049wy95wfm6889aq/preview';
  assert.deepEqual(discoverFeeds(source('cfmem'),`<a href='https://nodebuf.com/files/public/other/preview'>Clash</a><a href='${preview}'>V2Ray 订阅</a>`),[preview]);
});

test('daily loader fetches all same-day TXT feeds, deduplicates and tolerates one unavailable file', async () => {
  const s=source('hiddifynext'), article=s.url+'free-nodes/2026-10-29-node.htm';
  const feeds=[0,1,2].map(n=>s.url+`uploads/2026/10/${n}-20261029.txt`), calls=[];
  const result=await loadFreeSource(s,async(url,options)=>{
    calls.push(url); assert.equal(options.redirect,'manual'); assert.ok(options.signal);
    if(url===s.url) return new Response(`<a href='${article}'>latest</a>`);
    if(url===article) return new Response(feeds.map(u=>`<code>${u}</code>`).join(''));
    if(url===feeds[0]) return new Response(uri('one.example.com'));
    if(url===feeds[1]) return new Response(btoa(uri('one.example.com')+'\n'+uri('two.example.com')));
    return new Response('unavailable',{status:503});
  });
  assert.equal(result.nodes.length,2); assert.equal(result.fetchedFeedCount,2); assert.equal(result.feedCount,3);
  assert.equal(result.articleUrl,article); assert.equal(calls.length,5);
  assert.ok(result.warnings.includes('Some daily feeds unavailable or unsupported'));
});

test('a failed latest article can use the previous post without following arbitrary redirects', async () => {
  const s=source('mibei');
  const result=await loadFreeSource(s,async url=>{
    if(url===s.url) return new Response('<a href="/782.html">old</a><a href="/784.html">new</a>');
    if(url.endsWith('/784.html')) return new Response('',{status:302,headers:{Location:'https://evil.example'}});
    if(url.endsWith('/782.html')) return new Response('<code>https://aa.mibei77.com/202610/old.txt</code>');
    assert.equal(url,'https://aa.mibei77.com/202610/old.txt'); return new Response(uri('fallback.example.com'));
  });
  assert.equal(result.articleUrl,'https://www.mibei77.com/782.html'); assert.equal(result.nodes.length,1);
});

test('bounded readers cancel oversized advertised and streamed source bodies', async () => {
  await assert.rejects(readSourceText(new Response('oversized',{headers:{'Content-Length':'999'}}),4),/size limit/);
  await assert.rejects(readSourceText(new Response('oversized'),4),/size limit/);
});

test('checker supplements accept only known daily publishers and reparse native URIs', () => {
  const good={sourceId:'freev2',subscription:btoa(uri('supplement.example.com')),articleUrl:'https://b.freev2.net/',feedCount:1,fetchedFeedCount:1};
  const parsed=parseSourceSupplements([good]).get('freev2');
  assert.equal(parsed.nodes.length,1);assert.equal(parsed.nodes[0].sourceId,'freev2');assert.equal(parsed.fetchedBy,'github-actions');
  for (const input of [[{...good,sourceId:'arbitrary'}],[good,good],[{...good,articleUrl:'https://evil.example/'}],[{...good,proxy:{type:'direct'}}],[{...good,subscription:'not node data'}],[{...good,feedCount:7}]]) assert.throws(()=>parseSourceSupplements(input));
});
