import test from 'node:test';
import assert from 'node:assert/strict';
import { buildKaring, renderKaring } from '../src/karing.mjs';

// Syntactic fixtures only. Actual certificate parsing is the native core's job.
const CA = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----\n';
const KEY = '-----BEGIN RSA PRIVATE KEY-----\nTUlJQg==\n-----END RSA PRIVATE KEY-----\n';
const CONTROL = '-----BEGIN OpenVPN Static key V1-----\n' + 'a'.repeat(512) + '\n-----END OpenVPN Static key V1-----\n';
function node(changes = {}, raw = '# original profile has no compression directive\n') {
  return {
    id: 'vg-fixture', name: 'JP fixture', ovpn: raw,
    proxy: {
      name: 'JP fixture', type: 'openvpn', server: '203.0.113.7', port: 443, proto: 'tcp', dev: 'tun',
      ca: CA, cert: CA, key: KEY, cipher: 'AES-128-CBC', 'data-ciphers': ['AES-128-CBC'], auth: 'SHA1',
      'comp-lzo': 'no', 'remote-dns-resolve': true, dns: ['1.1.1.1'], udp: true, ...changes,
    },
  };
}
function endpoint(input = node()) { return JSON.parse(renderKaring([input])).endpoints[0]; }

test('native OpenVPN endpoint schema uses endpoints and snake_case keys', () => {
  const config = JSON.parse(renderKaring([node()]));
  const item = config.endpoints[0];
  assert.equal(item.type, 'openvpn-client');
  assert.equal(item.tag, 'JP fixture');
  assert.equal(item.mode, 'tls');
  assert.equal(item.server, '203.0.113.7');
  assert.equal(item.server_port, 443);
  assert.equal(item.network, 'tcp');
  assert.equal(item.system, false);
  assert.equal('port' in item, false);
  assert.equal('proto' in item, false);
  assert.equal('cipher' in item, false); // Forbidden in sing-box TLS mode.
  assert.deepEqual(item.data_ciphers, ['AES-128-CBC']);
  assert.equal(item.data_ciphers_fallback, 'AES-128-CBC');
  assert.equal(item.auth, 'SHA1');
});

test('preserves CA and client certificate/key, without weakening verification', () => {
  const item = endpoint();
  assert.deepEqual(item.tls.certificate, [CA]);
  assert.deepEqual(item.tls.client_certificate, [CA]);
  assert.deepEqual(item.tls.client_key, [KEY]);
  assert.equal(item.tls.remote_certificate_tls, 'server');
  for (const key of ['enabled', 'insecure', 'server_name', 'certificate_path', 'client_key_path']) assert.equal(key in item.tls, false);
});

test('node subscription selects the endpoint importer without an outbounds branch', () => {
  const config = JSON.parse(renderKaring([node(), node({ name: 'US fixture', server: '203.0.113.8' })]));
  assert.deepEqual(Object.keys(config), ['endpoints']);
  assert.deepEqual(config.endpoints.map(item => item.tag), ['JP fixture', 'US fixture']);
  assert.equal('outbounds' in config, false);
  assert.equal('route' in config, false);
  assert.ok(config.endpoints.every(item => item.type === 'openvpn-client' && item.server && item.server_port));
});

test('preserves per-node TCP/UDP and explicit negotiation/fallback lists', () => {
  const item = endpoint(node({ proto: 'udp', port: 1194, 'data-ciphers': ['AES-256-GCM', 'AES-128-GCM'], 'data-ciphers-fallback': 'AES-256-CBC', auth: 'SHA256' }));
  assert.equal(item.network, 'udp');
  assert.equal(item.server_port, 1194);
  assert.deepEqual(item.data_ciphers, ['AES-256-GCM', 'AES-128-GCM']);
  assert.equal(item.data_ciphers_fallback, 'AES-256-CBC');
  assert.equal(item.auth, 'SHA256');
  const input = node();
  delete input.proxy['data-ciphers'];
  assert.deepEqual(endpoint(input).data_ciphers, ['AES-128-CBC']);
});

test('maps tls-auth wrapping and directions instead of generic TLS fields', () => {
  for (const [input, expected] of [['0', 'server'], ['1', 'client']]) {
    const item = endpoint(node({ 'tls-auth': CONTROL, 'key-direction': input }));
    assert.deepEqual(item.tls.control_wrap, { type: 'tls_auth', key: [CONTROL], direction: expected });
    assert.equal('key_direction' in item, false);
    assert.equal('tls-auth' in item, false);
  }
  assert.deepEqual(endpoint(node({ 'tls-auth': CONTROL })).tls.control_wrap, { type: 'tls_auth', key: [CONTROL] });
  for (const name of ['tls-crypt', 'tls-crypt-v2']) assert.deepEqual(endpoint(node({ [name]: CONTROL })).tls.control_wrap, { type: name.replaceAll('-', '_'), key: [CONTROL] });
});

test('absent comp-lzo stays disabled; explicit no retains noncompressed framing', () => {
  const absent = endpoint();
  assert.equal('compression_lzo' in absent, false);
  assert.equal(absent.allow_compression, 'no');
  const explicit = endpoint(node({}, 'comp-lzo no\n'));
  assert.equal(explicit.compression_lzo, 'no');
  assert.equal(explicit.allow_compression, 'no');
});

test('skips symmetric compression and unmappable key transition settings', () => {
  const result = buildKaring([
    node({ name: 'LZO yes', 'comp-lzo': 'yes' }, 'comp-lzo yes\n'),
    node({ name: 'LZO adaptive', 'comp-lzo': 'adaptive' }, 'comp-lzo adaptive\n'),
    node({ name: 'Transition', 'tran-window': 60 }),
    node(),
  ]);
  assert.equal(result.nodeCount, 1);
  assert.equal(result.skipped, 3);
  assert.equal(result.warnings.length, 3);
  assert.match(result.warnings.join('\n'), /LZO|tran-window/);
});

test('maps positive timeouts and explicit zero ping-restart correctly', () => {
  const item = endpoint(node({ ping: 10, 'ping-restart': 60, 'handshake-timeout': 30, mtu: 1400 }));
  assert.equal(item.ping_interval, '10s');
  assert.equal(item.ping_restart, '60s');
  assert.equal(item.handshake_window, '30s');
  assert.equal(item.mtu, 1400);
  const zero = endpoint(node({ 'ping-restart': 0 }));
  assert.equal(zero.ping_restart_disabled, true);
  assert.equal('ping_restart' in zero, false);
});

test('preserves provided username/password mode and requires client material', () => {
  const input = node({ username: 'fixture-user', password: 'fixture-pass' });
  delete input.proxy.cert; delete input.proxy.key;
  const item = endpoint(input);
  assert.equal(item.username, 'fixture-user');
  assert.equal(item.password, 'fixture-pass');
  assert.equal('client_key' in item.tls, false);
  delete input.proxy.username;
  assert.throws(() => renderKaring([input]), /authentication/);
});

test('rejects malformed or unsupported options without including secrets in warnings', () => {
  const secret = 'DO_NOT_LOG_THIS_MATERIAL';
  const result = buildKaring([
    node({ name: 'Bad key', key: secret }),
    node({ name: 'Bad cipher', cipher: secret }),
    node({ name: 'Unknown field', 'skip-cert-verify': true }),
    node({ name: 'Bad transport', proto: 'tcp-server' }),
    node({ name: 'Bad auth', auth: secret }),
    node({ name: 'Bad TLS direction', 'tls-auth': CONTROL, 'key-direction': secret }),
    node(),
  ]);
  assert.equal(result.nodeCount, 1);
  assert.equal(result.skipped, 6);
  assert.equal(result.warnings.length, 6);
  assert.equal(result.warnings.join('\n').includes(secret), false);
});

test('valid JSON quoting, duplicate handling, and empty-feed errors', () => {
  const input = node({ name: 'JP: "test"' });
  assert.equal(endpoint(input).tag, 'JP: "test"');
  const result = buildKaring([input, input]);
  assert.equal(result.nodeCount, 1);
  assert.equal(result.skipped, 1);
  assert.match(result.warnings[0], /Duplicate/);
  assert.throws(() => renderKaring([]), /empty/);
  assert.throws(() => renderKaring([node({ cert: '' })]), /No Karing-compatible/);
});
