import test from 'node:test';
import assert from 'node:assert/strict';
import { BLOCKED_NODE_IDS, BLOCKED_ENDPOINTS, isBlockedNode } from '../src/block-policy.mjs';

const endpointKey = ({ protocol, server, port }) => `${protocol}|${server.toLowerCase()}|${port}`;
const endpoints = new Set(BLOCKED_ENDPOINTS.map(endpointKey));
const unlistedId = 'free-0000000000000000';
const nodeFor = endpoint => ({
  id: unlistedId,
  name: 'renamed node',
  sourceId: 'another-publisher',
  protocol: endpoint.protocol,
  proxy: { server: endpoint.server, port: endpoint.port },
});

test('user-reported blacklist contains the expected unique configurations and endpoints', () => {
  assert.equal(BLOCKED_NODE_IDS.length, 285);
  assert.equal(new Set(BLOCKED_NODE_IDS).size, 285);
  assert.equal(BLOCKED_ENDPOINTS.length, 258);
  assert.equal(endpoints.size, 258);
  assert.ok(!BLOCKED_NODE_IDS.includes(unlistedId));
  for (const endpoint of BLOCKED_ENDPOINTS) {
    assert.ok(['ss', 'vmess', 'vless', 'trojan', 'hysteria2'].includes(endpoint.protocol));
    assert.equal(typeof endpoint.server, 'string');
    assert.ok(endpoint.server.length > 0);
    assert.ok(Number.isInteger(endpoint.port) && endpoint.port >= 1 && endpoint.port <= 65535);
  }
});

test('every reported endpoint stays blocked when its source, name and configuration identity change', () => {
  for (const endpoint of BLOCKED_ENDPOINTS) {
    assert.equal(isBlockedNode(nodeFor(endpoint)), true, endpointKey(endpoint));
    assert.equal(isBlockedNode({ ...nodeFor(endpoint), name: 'second label', sourceId: 'third-publisher' }), true, endpointKey(endpoint));
  }
});

test('metadata endpoints are blocked without full connection objects', () => {
  for (const endpoint of BLOCKED_ENDPOINTS) {
    assert.equal(isBlockedNode({ id: unlistedId, protocol: endpoint.protocol, ip: endpoint.server, port: endpoint.port }), true, endpointKey(endpoint));
  }
});

test('a known reported configuration remains blocked without an endpoint', () => {
  for (const id of BLOCKED_NODE_IDS) assert.equal(isBlockedNode({ id }), true, id);
});

test('precise endpoint blocks preserve unlisted ports, protocols and hosts', () => {
  const original = BLOCKED_ENDPOINTS[0];
  const portVariant = { ...original, port: 1 };
  while (endpoints.has(endpointKey(portVariant))) portVariant.port++;
  assert.ok(portVariant.port <= 65535);
  assert.equal(isBlockedNode(nodeFor(portVariant)), false);

  const protocolVariant = ['ss', 'vmess', 'vless', 'trojan', 'hysteria2']
    .map(protocol => ({ ...original, protocol }))
    .find(endpoint => endpoint.protocol !== original.protocol && !endpoints.has(endpointKey(endpoint)));
  assert.ok(protocolVariant, 'a protocol not separately listed exists for the selected address');
  assert.equal(isBlockedNode(nodeFor(protocolVariant)), false);

  const hostVariant = { ...original, server: 'unlisted-block-policy.example.com' };
  assert.ok(!endpoints.has(endpointKey(hostVariant)));
  assert.equal(isBlockedNode(nodeFor(hostVariant)), false);
});
