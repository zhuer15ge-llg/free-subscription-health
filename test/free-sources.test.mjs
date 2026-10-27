import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFreeSubscription } from '../src/free-converter.mjs';
import { mergeFreeSources } from '../src/free-sources.mjs';

const uuid = '11111111-2222-4333-8444-555555555555';
const trojan = host => `trojan://test-password@${host}:443?security=tls&type=ws&path=%2Fproxy&sni=tls.example.com#JP`;
const vless = `vless://${uuid}@vless.example.com:443?security=tls&type=tcp&sni=tls.example.com#JP`;

test('Igareck Trojan pause preserves other source Trojan and Igareck VLESS nodes', () => {
  const igareck = parseFreeSubscription(`${trojan('igareck.example.com')}\n${vless}`, { sourceId: 'igareck', sourceName: 'Igareck' });
  const other = parseFreeSubscription(trojan('other.example.com'), { sourceId: 'pawdroid', sourceName: 'Pawdroid' });
  assert.equal(igareck.nodes.length, 2);
  assert.equal(other.nodes.length, 1);

  const merged = mergeFreeSources([igareck, other]);
  assert.deepEqual(merged.map(node => [node.sourceId, node.protocol]), [
    ['pawdroid', 'trojan'], ['igareck', 'vless'],
  ]);
  assert.equal(igareck.nodes.length, 2, 'merging must not mutate the parsed source');
});

test('paused nodes consume neither the quota nor the deduplication identity of another source', () => {
  const paused = parseFreeSubscription(trojan('shared.example.com'), { sourceId: 'igareck' }).nodes[0];
  const shared = parseFreeSubscription(trojan('shared.example.com'), { sourceId: 'pawdroid' }).nodes[0];
  assert.equal(paused.id, shared.id);
  const otherTypes = ['ss', 'vmess', 'vless', 'hysteria2'].map(protocol => ({ id: `igareck-${protocol}`, sourceId: 'igareck', protocol }));
  const result = mergeFreeSources([
    { nodes: [paused, ...otherTypes] },
    { nodes: [shared, { ...shared }] },
  ], 5);
  assert.deepEqual(result, [shared, ...otherTypes]);
  assert.equal(new Set(result.map(node => node.id)).size, 5);
});
