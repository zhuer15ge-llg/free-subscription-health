import test from 'node:test';
import assert from 'node:assert/strict';
import { parseVpnGateCsv, renderMihomo } from '../src/converter.mjs';

// Deliberately nonfunctional PEM-shaped fixtures. These only test conversion;
// Mihomo remains responsible for actual certificate/key parsing and validation.
const CA = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';
const KEY = '-----BEGIN PRIVATE KEY-----\nTUlJQg==\n-----END PRIVATE KEY-----';
const STATIC = '-----BEGIN OpenVPN Static key V1-----\n' + 'a'.repeat(512) + '\n-----END OpenVPN Static key V1-----';
const HEADER = ['HostName', 'IP', 'Score', 'Ping', 'Speed', 'CountryLong', 'CountryShort', 'NumVpnSessions', 'Uptime', 'TotalUsers', 'TotalTraffic', 'LogType', 'Operator', 'Message', 'OpenVPN_ConfigData_Base64'];
const field = value => /[,"\r\n]/.test(String(value)) ? '"' + String(value).replaceAll('"', '""') + '"' : String(value);
function ovpn(extra = '', options = {}) {
  return `# sample public configuration\ndev tun\nproto tcp\nremote ${options.host ?? '203.0.113.7'} 443\ncipher AES-128-CBC\ndata-ciphers AES-128-CBC:AES-256-GCM\nauth SHA1\nclient\nnobind\npersist-key\npersist-tun\nresolv-retry infinite\nverb 3\n${extra}\n<ca>\n${CA}\n</ca>\n<cert>\n${CA}\n</cert>\n<key>\n${KEY}\n</key>\n`;
}
function row(profile = ovpn(), values = {}) {
  return HEADER.map(name => ({ HostName: 'test-vpn', IP: '203.0.113.7', Score: '100', Ping: '20', Speed: '20000000', CountryLong: 'Japan', CountryShort: 'JP', NumVpnSessions: '5', Uptime: '60000', TotalUsers: '20', TotalTraffic: '123', LogType: '2weeks', Operator: 'Public volunteer', Message: '', OpenVPN_ConfigData_Base64: Buffer.from(profile).toString('base64'), ...values })[name]);
}
function csv(rows, ending = '\r\n') {
  return '\uFEFF*vpn_servers' + ending + '#' + HEADER.join(',') + ending + rows.map(values => values.map(field).join(',')).join(ending) + ending + '*' + ending;
}
function parse(profile, options) { return parseVpnGateCsv(csv([row(profile)]), options); }

test('converts native OpenVPN fields and preserves upstream inline material', () => {
  const result = parse(ovpn());
  assert.equal(result.sourceCount, 1);
  assert.equal(result.skipped, 0);
  assert.deepEqual(result.warnings, []);
  const node = result.nodes[0];
  assert.equal(node.country, 'JP');
  assert.equal(node.proxy.type, 'openvpn');
  assert.equal(node.proxy.server, '203.0.113.7');
  assert.equal(node.proxy.port, 443);
  assert.equal(node.proxy.proto, 'tcp');
  assert.equal(node.proxy.ca, CA + '\n');
  assert.equal(node.proxy.cert, CA + '\n');
  assert.equal(node.proxy.key, KEY + '\n');
  assert.equal(node.proxy.auth, 'SHA1');
  assert.equal(node.proxy.cipher, 'AES-128-CBC');
  assert.deepEqual(node.proxy['data-ciphers'], ['AES-128-CBC', 'AES-256-GCM']);
  assert.equal(node.proxy['comp-lzo'], 'no');
  assert.equal(node.proxy['remote-dns-resolve'], true);
  assert.equal(node.ovpn, ovpn());
  assert.match(node.id, /^vg-[a-f\d]{16}$/);
  assert.equal('skip-cert-verify' in node.proxy, false);
});

test('CSV quoting handles commas, escaped quotes, CRLF and embedded newlines', () => {
  const message = 'Line one, with a "quote"\r\nLine two';
  const result = parseVpnGateCsv(csv([row(ovpn(), { Operator: message, CountryLong: 'Japan, "JP"\nEast' })]));
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].countryLong, 'Japan, "JP" East');
});

test('CSV supports quoted final empty fields and rejects structural corruption', () => {
  assert.throws(() => parseVpnGateCsv(csv([row()]).replace('#HostName', '#Unknown')), /header/);
  assert.throws(() => parseVpnGateCsv(csv([row()]).replace('test-vpn,', 'test"vpn,')), /unexpected quote/);
  assert.throws(() => parseVpnGateCsv('#' + HEADER.join(',') + '\n"unclosed'), /unterminated/);
  assert.throws(() => parseVpnGateCsv('#' + HEADER.join(',') + '\n"closed"junk'), /closing quote/);
  const result = parseVpnGateCsv(csv([row()]).replace(/[^,\r\n]+\r\n\*\r\n$/, '""\r\n*\r\n'));
  assert.equal(result.nodes.length, 0);
  assert.match(result.warnings[0], /base64/);
});

test('sorts by score before decoding, limits output, deduplicates endpoints', () => {
  const result = parseVpnGateCsv(csv([
    row(ovpn('', { host: '203.0.113.8' }), { Score: '5' }),
    row(ovpn(), { Score: '500' }),
    row(ovpn(), { Score: '300' }),
    row(ovpn('', { host: 'vpn.example.com' }), { Score: '100' }),
  ]), { limit: 2 });
  assert.equal(result.sourceCount, 4);
  assert.equal(result.skipped, 2);
  assert.equal(result.nodes.length, 2);
  assert.deepEqual(result.nodes.map(node => node.score), [500, 100]);
  assert.match(result.warnings.join('\n'), /Duplicate/);
  assert.match(result.warnings.join('\n'), /limit/);
});

test('skips broken base64, invalid UTF-8 and incomplete metadata', () => {
  const result = parseVpnGateCsv(csv([
    row(ovpn(), { OpenVPN_ConfigData_Base64: '!invalid' }),
    row(ovpn(), { OpenVPN_ConfigData_Base64: '/w==' }),
    row(ovpn(), { IP: 'https://example.com/' }),
    row(ovpn(), { IP: '999.999.0.1' }),
    row(ovpn()),
  ]));
  assert.equal(result.nodes.length, 1);
  assert.equal(result.skipped, 4);
  assert.equal(result.warnings.length, 4);
});

test('decodes UTF-8 profile comments without corrupting the original download', () => {
  const profile = '# 公共志愿者\n' + ovpn();
  assert.equal(parse(profile).nodes[0].ovpn, profile);
});

test('accepts quoted remote, per-remote protocol and first applicable alternative', () => {
  const profile = ovpn().replace('remote 203.0.113.7 443', 'remote invalid/host 443\nremote "vpn.example.com" 1194 udp\nremote 203.0.113.9 443 tcp-client');
  const result = parse(profile);
  assert.equal(result.nodes[0].proxy.server, 'vpn.example.com');
  assert.equal(result.nodes[0].proxy.proto, 'udp');
  assert.equal(result.nodes[0].proxy.port, 1194);
  assert.match(result.warnings.join('\n'), /first supported remote/);
});

test('rejects invalid remotes, unsupported transport, tap and malformed quoting', () => {
  for (const profile of [
    ovpn().replace('203.0.113.7 443', '203.0.113.7 65536'),
    ovpn().replace('proto tcp', 'proto tcp-server'),
    ovpn().replace('dev tun', 'dev tap'),
    ovpn().replace('remote 203.0.113.7 443', 'remote "unclosed 443'),
  ]) assert.equal(parse(profile).nodes.length, 0);
});

test('rejects scripts, file references, routes and unmappable peer verification', () => {
  for (const extra of ['up /tmp/script', 'script-security 2', 'ca /tmp/ca.pem', 'remote-cert-tls server', 'verify-x509-name server name', 'tls-verify command', 'route 0.0.0.0 0.0.0.0', 'http-proxy example.com 3128']) {
    const result = parse(ovpn(extra));
    assert.equal(result.nodes.length, 0, extra);
    assert.match(result.warnings.join('\n'), /Unsupported|External/);
  }
});

test('fails closed for unknown inline blocks and malformed or duplicate certificate material', () => {
  for (const profile of [
    ovpn('<connection>\nremote 203.0.113.8 443\n</connection>'),
    ovpn().replace(CA, 'not-a-certificate'),
    ovpn().replace('</ca>', ''),
    ovpn(`<ca>\n${CA}\n</ca>`),
    ovpn().replace(/<key>[\s\S]*?<\/key>/, ''),
  ]) assert.equal(parse(profile).nodes.length, 0);
});

test('preserves supported TLS control keys, directions and compression settings', () => {
  const result = parse(ovpn(`<tls-auth>\n${STATIC}\n</tls-auth>\nkey-direction 1\ncomp-lzo adaptive\nping 17\nping-restart 90\ntran-window 0\nhand-window 45\ntun-mtu 1400`));
  const proxy = result.nodes[0].proxy;
  assert.equal(proxy['tls-auth'], STATIC + '\n');
  assert.equal(proxy['key-direction'], '1');
  assert.equal(proxy['comp-lzo'], 'adaptive');
  assert.equal(proxy.ping, 17);
  assert.equal(proxy['ping-restart'], 90);
  assert.equal(proxy['tran-window'], 0);
  assert.equal(proxy['handshake-timeout'], 45);
  assert.equal(proxy.mtu, 1400);
  assert.equal(parse(ovpn(`<tls-auth>\n${STATIC}\n</tls-auth>\n<tls-crypt>\n${STATIC}\n</tls-crypt>`)).nodes.length, 0);
  assert.equal(parse(ovpn('key-direction 1')).nodes.length, 0);
});

test('adds handshake and keepalive defaults without changing the original OpenVPN download', () => {
  const profile = ovpn();
  const { nodes } = parse(profile);
  const proxy = nodes[0].proxy;
  assert.equal(proxy['handshake-timeout'], 30);
  assert.equal(proxy.ping, 10);
  assert.equal(proxy['ping-restart'], 60);
  assert.equal(nodes[0].ovpn, profile);
  for (const providerOnly of [false, true]) {
    const output = renderMihomo(nodes, { providerOnly });
    assert.match(output, /"handshake-timeout": 30/);
    assert.match(output, /"ping": 10/);
    assert.match(output, /"ping-restart": 60/);
  }
});

test('preserves explicitly disabled handshake and keepalive settings', () => {
  const proxy = parse(ovpn('hand-window 0\nping 0\nping-restart 0')).nodes[0].proxy;
  assert.equal(proxy['handshake-timeout'], 0);
  assert.equal(proxy.ping, 0);
  assert.equal(proxy['ping-restart'], 0);
});

test('never silently replaces unsupported crypto or compression', () => {
  for (const profile of [
    ovpn().replace('cipher AES-128-CBC', 'cipher BF-CBC'),
    ovpn().replace('auth SHA1', 'auth none'),
    ovpn().replace('data-ciphers AES-128-CBC:AES-256-GCM', 'data-ciphers AES-128-CBC:BF-CBC'),
    ovpn('compress lz4'),
    ovpn().replace('cipher AES-128-CBC\n', ''),
  ]) assert.equal(parse(profile).nodes.length, 0);
});

test('uses OpenVPN SHA1 default instead of changing to Mihomo SHA256 default', () => {
  assert.equal(parse(ovpn().replace('auth SHA1\n', '')).nodes[0].proxy.auth, 'SHA1');
});

test('requires actual supplied credentials for auth-user-pass and rejects combined modes', () => {
  assert.equal(parse(ovpn('auth-user-pass')).nodes.length, 0);
  assert.equal(parse(ovpn('auth-user-pass /etc/credentials')).nodes.length, 0);
  assert.equal(parse(ovpn('<auth-user-pass>\nvpn\nvpn\n</auth-user-pass>')).nodes.length, 0);
  const profile = ovpn('auth-user-pass [inline]\n<auth-user-pass>\nfixture-user\nfixture-pass\n</auth-user-pass>').replace(/<cert>[\s\S]*?<\/cert>\n/, '').replace(/<key>[\s\S]*?<\/key>\n/, '');
  const proxy = parse(profile).nodes[0].proxy;
  assert.equal(proxy.username, 'fixture-user');
  assert.equal(proxy.password, 'fixture-pass');
  assert.equal(proxy.cert, undefined);
});

test('YAML strings escape injection and full config has no direct fallback', () => {
  const nodes = parse(ovpn()).nodes;
  const name = 'JP: "x"\nproxy-groups: [DIRECT]';
  nodes[0].proxy.name = name;
  const result = renderMihomo(nodes);
  assert.ok(result.includes('"name": ' + JSON.stringify(name)));
  assert.ok(result.includes('"rules":\n  - "MATCH,VPN Gate"'));
  assert.equal(result.includes('\nproxy-groups: [DIRECT]'), false);
  assert.equal(result.includes('- "DIRECT"'), false);
  assert.match(result, /"mixed-port": 7890/);
  assert.match(result, /"allow-lan": false/);
  assert.match(result, /dns-query#VPN Gate/);
  const provider = renderMihomo(nodes, { providerOnly: true });
  assert.ok(provider.includes('"proxies":'));
  assert.equal(provider.includes('"mixed-port"'), false);
  assert.equal(provider.includes('"rules"'), false);
});

test('output errors for empty nodes, duplicate/reserved names and unreasonable limits', () => {
  const nodes = parse(ovpn()).nodes;
  assert.throws(() => renderMihomo([]), /empty/);
  assert.throws(() => renderMihomo([nodes[0], nodes[0]]), /unique/);
  assert.throws(() => renderMihomo([{ proxy: { name: 'DIRECT' } }]), /reserved/);
  for (const limit of [0, -1, 201, 1.5, '10', Infinity]) assert.throws(() => parse(ovpn(), { limit }), /limit/);
});

test('warnings are bounded and IDs stay stable across changing scores', () => {
  const many = parseVpnGateCsv(csv(Array.from({ length: 150 }, () => row(ovpn('up rejected')))));
  assert.equal(many.sourceCount, 150);
  assert.equal(many.skipped, 150);
  assert.equal(many.warnings.length, 100);
  const a = parseVpnGateCsv(csv([row(ovpn(), { Score: 10 })])).nodes[0];
  const b = parseVpnGateCsv(csv([row(ovpn(), { Score: 999 })])).nodes[0];
  assert.equal(a.id, b.id);
  assert.equal(a.name, b.name);
});
