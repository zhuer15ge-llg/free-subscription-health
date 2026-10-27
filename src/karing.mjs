/**
 * Native sing-box OpenVPN endpoints for Karing >= 1.2.26.2909.
 * Endpoint schema: sing-box 1.14 / KaringX's karing_v1.14.3 core.
 * This formats public VPN Gate nodes; it does not run an OpenVPN client.
 */

const CIPHERS = new Set(['AES-128-GCM', 'AES-256-GCM', 'AES-128-CBC', 'AES-256-CBC', 'CHACHA20-POLY1305']);
const AUTHS = new Set(['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512']);
const KNOWN = new Set(['name', 'type', 'server', 'port', 'proto', 'dev', 'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'key-direction', 'username', 'password', 'cipher', 'data-ciphers', 'data-ciphers-fallback', 'auth', 'comp-lzo', 'ping', 'ping-restart', 'tran-window', 'handshake-timeout', 'mtu', 'remote-dns-resolve', 'dns', 'udp']);

function fail(message) { throw new Error(message); }
function has(object, name) { return Object.prototype.hasOwnProperty.call(object, name); }

function certificate(value, name, key = false) {
  if (typeof value !== 'string' || !value.trim()) fail(`Missing ${name} material`);
  const expression = key ? /^-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+-----END (?:RSA |EC )?PRIVATE KEY-----\s*$/ : /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/;
  if (!expression.test(value)) fail(`Invalid ${name} PEM`);
  return [value];
}

function cipher(value) {
  if (typeof value !== 'string' || !CIPHERS.has(value.toUpperCase())) fail('Unsupported data-channel cipher');
  return value.toUpperCase();
}

function seconds(value, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 2147483647) fail(`Invalid ${name} duration`);
  return `${value}s`;
}

function endpoint(node) {
  const proxy = node?.proxy;
  if (!proxy || proxy.type !== 'openvpn') fail('Expected a converted OpenVPN node');
  if (Object.keys(proxy).some(name => !KNOWN.has(name))) fail('Unsupported proxy field');
  if (typeof proxy.name !== 'string' || !proxy.name || /[\u0000-\u001f\u007f]/.test(proxy.name)) fail('Invalid endpoint name');
  if (typeof proxy.server !== 'string' || !proxy.server || /[\s\u0000-\u001f/@?#\\]/.test(proxy.server)) fail('Invalid endpoint server');
  if (!Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) fail('Invalid endpoint port');
  if (!['udp', 'tcp'].includes(proxy.proto)) fail('Unsupported OpenVPN transport');
  if (proxy.dev && proxy.dev !== 'tun') fail('Only dev tun is supported');
  if (has(proxy, 'tran-window')) fail('Explicit tran-window cannot be represented by sing-box');
  if (has(proxy, 'handshake-timeout') && proxy['handshake-timeout'] === 0) fail('A zero hand-window cannot be represented by sing-box');
  const tls = {
    certificate: certificate(proxy.ca, 'CA'),
    remote_certificate_tls: 'server',
  };
  if (Boolean(proxy.cert) !== Boolean(proxy.key)) fail('Client certificate and key must both be present');
  if (proxy.cert) {
    tls.client_certificate = certificate(proxy.cert, 'client certificate');
    tls.client_key = certificate(proxy.key, 'client key', true);
  }
  if (!proxy.cert && !(typeof proxy.username === 'string' && proxy.username && typeof proxy.password === 'string')) fail('Missing client authentication material');

  const wraps = ['tls-auth', 'tls-crypt', 'tls-crypt-v2'].filter(name => proxy[name]);
  if (wraps.length > 1) fail('Conflicting TLS control wrapping keys');
  if (wraps.length) {
    const name = wraps[0];
    if (typeof proxy[name] !== 'string' || !proxy[name].trim()) fail('Invalid TLS control wrapping key');
    tls.control_wrap = { type: name.replaceAll('-', '_'), key: [proxy[name]] };
    if (has(proxy, 'key-direction')) {
      if (name !== 'tls-auth' || !['0', '1'].includes(String(proxy['key-direction']))) fail('Invalid TLS auth key direction');
      tls.control_wrap.direction = String(proxy['key-direction']) === '1' ? 'client' : 'server';
    }
  } else if (has(proxy, 'key-direction')) fail('Key direction requires tls-auth');

  const result = {
    type: 'openvpn-client',
    tag: proxy.name,
    mode: 'tls',
    server: proxy.server,
    server_port: proxy.port,
    network: proxy.proto,
    // `cipher` is forbidden in sing-box TLS mode. The original legacy cipher
    // becomes the fallback for SoftEther peers without cipher negotiation.
    data_ciphers: has(proxy, 'data-ciphers') ? proxy['data-ciphers'].map(cipher) : [cipher(proxy.cipher)],
    data_ciphers_fallback: cipher(proxy['data-ciphers-fallback'] ?? proxy.cipher),
    auth: proxy.auth ?? 'SHA1',
    tls,
    system: false,
  };
  if (!result.data_ciphers.length) fail('Empty data-ciphers list');
  if (!AUTHS.has(result.auth)) fail('Unsupported data-channel authentication digest');
  if (has(proxy, 'username')) { result.username = proxy.username; result.password = proxy.password; }

  // converter.mjs adds comp-lzo:no to Mihomo even when the .ovpn has no
  // comp-lzo directive. Absence must stay disabled here, without new framing.
  const explicitLzo = typeof node.ovpn !== 'string' || /^[ \t]*(?:--)?comp-lzo(?:[ \t]|$)/m.test(node.ovpn);
  if (explicitLzo && has(proxy, 'comp-lzo')) {
    if (proxy['comp-lzo'] !== 'no') fail('Symmetric LZO compression cannot be preserved by sing-box');
    result.compression_lzo = 'no';
  }
  result.allow_compression = 'no';
  if (has(proxy, 'ping')) result.ping_interval = seconds(proxy.ping, 'ping');
  if (has(proxy, 'ping-restart')) {
    if (proxy['ping-restart'] === 0) result.ping_restart_disabled = true;
    else result.ping_restart = seconds(proxy['ping-restart'], 'ping-restart');
  }
  if (has(proxy, 'handshake-timeout')) result.handshake_window = seconds(proxy['handshake-timeout'], 'hand-window');
  if (has(proxy, 'mtu')) {
    if (!Number.isInteger(proxy.mtu) || proxy.mtu < 576 || proxy.mtu > 65535) fail('Invalid tunnel MTU');
    result.mtu = proxy.mtu;
  }
  return result;
}

/** Return native configuration and compatibility counts without exposing keys. */
export function buildKaring(nodes) {
  if (!Array.isArray(nodes) || !nodes.length) fail('Cannot render an empty Karing subscription');
  const endpoints = [], warnings = [], seen = new Set();
  for (const [index, node] of nodes.entries()) {
    try {
      const item = endpoint(node);
      if (seen.has(item.tag)) fail('Duplicate endpoint name');
      seen.add(item.tag);
      endpoints.push(item);
    } catch (error) {
      // Only errors generated above are returned; no source values or key
      // contents are interpolated into diagnostic messages.
      if (warnings.length < 100) warnings.push(`Node ${index + 1}: ${error instanceof TypeError ? 'Invalid proxy field shape' : error.message}`);
    }
  }
  if (!endpoints.length) fail('No Karing-compatible OpenVPN endpoints: ' + warnings.slice(0, 3).join('; '));
  // This is a node subscription, not a complete runtime configuration. Karing
  // manages its own selectors/routes. An outbounds array containing only a
  // selector can select the outbound importer, which skips selector nodes and
  // reports "singbox outbounds: No server available" before reading endpoints.
  // Keep this envelope unambiguous; do not add even an empty outbounds array.
  const document = { endpoints };
  return { config: JSON.stringify(document, null, 2) + '\n', nodeCount: endpoints.length, skipped: nodes.length - endpoints.length, warnings };
}

/** Karing's subscription importer reads endpoints from this native JSON. */
export function renderKaring(nodes) { return buildKaring(nodes).config; }
