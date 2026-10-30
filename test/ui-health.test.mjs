import test from 'node:test';
import assert from 'node:assert/strict';
import { renderDashboard } from '../src/ui.mjs';

const now=Date.now(), hour=60*60*1000, iso=time=>new Date(time).toISOString();
const options={
  baseUrl:'https://subscription.example.com',
  subscriptionUrl:'https://subscription.example.com/sub/mihomo.yaml?token=fixture',
  karingUrl:'https://subscription.example.com/sub/karing.json?token=fixture',
  v2raynUrl:'https://subscription.example.com/sub/v2rayn.txt?token=fixture',
  providerUrl:'https://subscription.example.com/sub/provider.yaml?token=fixture',
  statusUrl:'https://subscription.example.com/api/status?token=fixture',
  nodeCount:2,updatedAt:iso(now-hour),sources:[{name:'Fixture',homepage:'https://publisher.example.com'}],
};
const fresh={enabled:true,state:'healthy',fresh:true,stale:false,available:true,checkedAt:iso(now-hour),expiresAt:iso(now+hour),staleUntil:iso(now+23*hour),checkedCount:3,passedCount:2,failedCount:1};
const buttons=html=>[...html.matchAll(/<button\b[^>]*data-copy-target="[^"]+"[^>]*>/g)].map(m=>m[0]);
function assertCopy(html,enabled){const found=buttons(html);assert.equal(found.length,4);assert.ok(found.every(b=>b.includes(' disabled')===!enabled));}

test('fresh checked subscriptions retain normal status and enabled copy buttons',()=>{
  const html=renderDashboard({...options,health:fresh});
  assertCopy(html,true);
  assert.match(html,/class="status-pill"><span class="dot"><\/span>检测通过/);
  assert.match(html,/class="health-card"/);
  assert.match(html,/订阅仅下发有效期内通过检测的 2 个节点/);
  assert.ok(!html.includes('检测延迟，使用上次通过节点'));
});

test('available stale subscriptions stay copyable with amber status and original dates',()=>{
  const health={...fresh,state:'stale',fresh:false,stale:true,checkedAt:iso(now-3*hour),expiresAt:iso(now-hour),staleUntil:iso(now+21*hour)};
  const html=renderDashboard({...options,updatedAt:health.checkedAt,health,lastAttempt:{success:false}});
  assertCopy(html,true);
  assert.match(html,/class="status-pill waiting"><span class="dot"><\/span>检测延迟，使用上次通过节点/);
  assert.match(html,/class="health-card waiting"/);
  assert.match(html,/当前连通性尚未重新确认/);
  assert.match(html,/延迟期间最晚提供至 · 北京时间/);
  for(const date of [health.checkedAt,health.expiresAt,health.staleUntil]) assert.ok(html.includes(`datetime="${date}"`));
  assert.ok(!html.includes('自动连通性检测 · 检测通过'));
  assert.ok(!html.includes('订阅仅下发有效期内通过检测的'));
  assert.match(html,/定时任务可能延迟/);
  assert.match(html,/目前暂时提供上次通过检测的节点，并保留原检测时间/);
});

test('hard-expired subscriptions disable copies and explain that distribution is paused',()=>{
  const health={...fresh,state:'expired',fresh:false,stale:true,available:false,checkedAt:iso(now-25*hour),expiresAt:iso(now-23*hour),staleUntil:iso(now-hour)};
  const html=renderDashboard({...options,nodeCount:0,health});
  assertCopy(html,false);
  assert.match(html,/检测结果已过期/);
  assert.match(html,/旧节点已停止下发/);
  assert.match(html,/class="status-pill waiting"/);
});

test('pending and latest-zero snapshots cannot expose enabled subscription copies',()=>{
  const pending=renderDashboard({...options,nodeCount:0,health:{enabled:true,state:'pending',available:false,checkedAt:null,passedCount:0}});
  assertCopy(pending,false);assert.match(pending,/等待首次检测/);
  const empty=renderDashboard({...options,nodeCount:0,health:{...fresh,state:'empty',available:false,passedCount:0,failedCount:3}});
  assertCopy(empty,false);assert.match(empty,/暂无可用订阅/);assert.match(empty,/订阅已暂停提供/);
});

test('stale flags cannot enable copying after the hard deadline or with no nodes',()=>{
  const health={...fresh,state:'stale',stale:true,fresh:false,checkedAt:iso(now-25*hour),expiresAt:iso(now-23*hour),staleUntil:iso(now-hour)};
  assertCopy(renderDashboard({...options,health}),false);
  assertCopy(renderDashboard({...options,nodeCount:0,health:{...health,staleUntil:iso(now+hour),passedCount:0}}),false);
});
