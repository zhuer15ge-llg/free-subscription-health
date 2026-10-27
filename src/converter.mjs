/**
 * VPN Gate's public CSV -> Mihomo's native OpenVPN adapter.
 * No OpenVPN command, referenced file, script, or executable is ever run.
 * Unknown connection/security options reject the profile instead of disappearing.
 * Requires a recent Mihomo build with native `type: openvpn` support.
 */

const MAX_CSV_BYTES = 12 * 1024 * 1024;
const MAX_OVPN_BYTES = 128 * 1024;
const MAX_WARNINGS = 100;
const COUNTRY_NAMES_ZH = new Intl.DisplayNames(['zh-CN'], { type: 'region', fallback: 'none' });
const CIPHERS = new Set(['AES-128-GCM', 'AES-256-GCM', 'AES-128-CBC', 'AES-256-CBC', 'CHACHA20-POLY1305']);
const AUTHS = new Set(['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512']);
const BLOCKS = new Set(['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'auth-user-pass']);
// These govern the standalone OpenVPN process rather than Mihomo's in-process adapter.
const PROCESS_OPTIONS = new Set(['client', 'tls-client', 'nobind', 'persist-key', 'persist-tun', 'resolv-retry', 'verb', 'mute', 'mute-replay-warnings', 'auth-nocache', 'explicit-exit-notify']);

function fail(message) { throw new Error(message); }

/** RFC 4180 quoting, including embedded commas, doubled quotes and newlines. */
function csvRecords(text) {
  const records = [];
  text = text.replace(/^\uFEFF/, '');
  let record = [], index = 0;
  const delimiter = /[,\r\n"]/g;
  while (index < text.length) {
    let value;
    if (text[index] === '"') {
      const parts = [];
      let start = ++index;
      for (;;) {
        const closing = text.indexOf('"', index);
        if (closing < 0) fail('Malformed CSV: unterminated quoted field');
        parts.push(text.slice(start, closing));
        index = closing + 1;
        if (text[index] !== '"') break;
        parts.push('"'); start = ++index;
      }
      value = parts.join('');
      while (text[index] === ' ' || text[index] === '\t') index++;
      if (index < text.length && ![',', '\r', '\n'].includes(text[index])) fail('Malformed CSV: text after a closing quote');
    } else {
      delimiter.lastIndex = index;
      const match = delimiter.exec(text);
      const end = match ? match.index : text.length;
      if (match?.[0] === '"') fail('Malformed CSV: unexpected quote');
      value = text.slice(index, end);
      index = end;
    }
    record.push(value);
    const end = text[index++];
    if (end === ',') {
      if (index === text.length) { record.push(''); records.push(record); record = []; }
      continue;
    }
    if (end === '\r' && text[index] === '\n') index++;
    records.push(record); record = [];
  }
  return records;
}

function safeText(value, length = 80) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, length);
}

function numeric(value, defaultValue = 0) {
  return /^\d+(?:\.\d+)?$/.test(String(value)) && Number.isFinite(Number(value)) ? Number(value) : defaultValue;
}

function isIPv4(host) {
  const parts = host.split('.');
  return parts.length === 4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function validHost(host) {
  if (!host || host.length > 253 || /[\s\u0000-\u001f\u007f/@?#\\]/.test(host)) return false;
  if (isIPv4(host)) return true;
  // Do not mistake an invalid numeric IP for a DNS name.
  if (/^[\d.]+$/.test(host)) return false;
  if (host.includes(':')) {
    try { return new URL(`https://[${host}]/`).hostname.startsWith('['); } catch { return false; }
  }
  return host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

function tokenize(line) {
  const result = [];
  let value = '', quote = null, escaped = false, active = false;
  for (const c of line) {
    if (escaped) { value += c; escaped = false; active = true; continue; }
    if (c === '\\') { escaped = true; active = true; continue; }
    if (quote) { if (c === quote) quote = null; else value += c; active = true; continue; }
    if (c === '"' || c === "'") { quote = c; active = true; continue; }
    if ((c === '#' || c === ';') && !active) break;
    if (/\s/.test(c)) {
      if (active) { result.push(value); value = ''; active = false; }
    } else { value += c; active = true; }
  }
  if (escaped || quote) fail('Malformed OpenVPN quoting');
  if (active) result.push(value);
  return result;
}

function protocol(value) {
  const name = String(value).toLowerCase();
  if (['tcp', 'tcp-client', 'tcp4', 'tcp4-client'].includes(name)) return 'tcp';
  if (['udp', 'udp4'].includes(name)) return 'udp';
  fail(`Unsupported OpenVPN proto: ${safeText(name, 32)}`);
}

function pem(value, type, name) {
  // Shape checking only: Mihomo performs X.509/key parsing at connection time.
  const expression = new RegExp(`^-----BEGIN (${type})-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END \\1-----$`);
  if (!expression.test(value.trim())) fail(`Invalid inline ${name} PEM`);
  return value.trim() + '\n';
}

function staticKey(value, name) {
  if (name === 'tls-crypt-v2') return pem(value, 'OpenVPN tls-crypt-v2 client key', name);
  const normalized = value.split('\n').map(x => x.trim()).filter(x => x && !x.startsWith('#')).join('\n');
  const body = normalized.replace(/^-----BEGIN OpenVPN Static key V1-----\n/, '').replace(/\n-----END OpenVPN Static key V1-----$/, '');
  if (!/^[0-9a-fA-F\n]+$/.test(body) || body.replace(/\n/g, '').length !== 512) fail(`Invalid inline ${name} static key`);
  return value.trim() + '\n';
}

function parseOvpn(text) {
  if (text.length > MAX_OVPN_BYTES || text.includes('\0')) fail('OpenVPN profile is oversized or contains NUL');
  const lines = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');
  const options = new Map(), blocks = new Map(), remotes = [], warnings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const opening = line.match(/^<([a-z0-9-]+)>$/i);
    if (opening) {
      const name = opening[1].toLowerCase();
      if (!BLOCKS.has(name)) fail(`Unsupported OpenVPN inline block: ${safeText(name, 40)}`);
      if (blocks.has(name)) fail(`Duplicate OpenVPN inline block: ${name}`);
      const contents = [];
      while (++i < lines.length && lines[i].trim().toLowerCase() !== `</${name}>`) contents.push(lines[i]);
      if (i >= lines.length) fail(`Unterminated OpenVPN inline block: ${name}`);
      blocks.set(name, contents.join('\n').trim());
      continue;
    }
    const tokens = tokenize(line);
    if (!tokens.length) continue;
    const name = tokens.shift().replace(/^--/, '').toLowerCase();
    if (name === 'remote') { remotes.push(tokens); continue; }
    if (PROCESS_OPTIONS.has(name)) continue;
    if (options.has(name)) fail(`Duplicate OpenVPN option: ${safeText(name, 40)}`);
    options.set(name, tokens);
  }
  const known = new Set(['dev', 'dev-type', 'proto', 'port', 'rport', 'cipher', 'data-ciphers', 'data-ciphers-fallback', 'auth', 'comp-lzo', 'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'key-direction', 'auth-user-pass', 'ping', 'ping-restart', 'tran-window', 'hand-window', 'tun-mtu', 'remote-random']);
  for (const name of options.keys()) if (!known.has(name)) fail(`Unsupported OpenVPN option: ${safeText(name, 40)}`);
  const one = (name, fallback) => {
    if (!options.has(name)) return fallback;
    const values = options.get(name);
    if (values.length !== 1) fail(`OpenVPN ${name} requires one value`);
    return values[0];
  };
  if (one('dev', 'tun') !== 'tun' || one('dev-type', 'tun') !== 'tun') fail('Only OpenVPN dev tun is supported');
  const defaultProto = protocol(one('proto', 'udp'));
  const defaultPort = one('rport', one('port', '1194'));
  let remote;
  for (const values of remotes) {
    try {
      if (values.length < 1 || values.length > 3) fail('Invalid remote argument count');
      const [host, port = defaultPort, proto = defaultProto] = values;
      if (!validHost(host)) fail('Invalid remote host');
      if (!/^\d+$/.test(String(port)) || Number(port) < 1 || Number(port) > 65535) fail('Invalid remote port');
      remote = { server: host, port: Number(port), proto: protocol(proto) };
      break;
    } catch { warnings.push('An invalid or unsupported remote was skipped'); }
  }
  if (!remote) fail('No supported OpenVPN remote');
  if (remotes.length > 1 || options.has('remote-random')) warnings.push('Selected the first supported remote; alternate remote/retry selection is not exported');

  const proxy = { type: 'openvpn', ...remote, dev: 'tun' };
  for (const name of ['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2']) {
    if (options.has(name) && one(name) !== '[inline]') fail(`External OpenVPN ${name} files are not supported`);
    if (options.has(name) && !blocks.has(name)) fail(`Missing inline ${name} block`);
    if (!blocks.has(name)) continue;
    if (name === 'ca' || name === 'cert') proxy[name] = pem(blocks.get(name), 'CERTIFICATE', name);
    else if (name === 'key') proxy[name] = pem(blocks.get(name), '(?:RSA |EC )?PRIVATE KEY', name);
    else proxy[name] = staticKey(blocks.get(name), name);
  }
  if (!proxy.ca) fail('Missing inline CA certificate');
  if (Boolean(proxy.cert) !== Boolean(proxy.key)) fail('Client certificate and key must both be present');
  const keyModes = ['tls-auth', 'tls-crypt', 'tls-crypt-v2'].filter(name => proxy[name]);
  if (keyModes.length > 1) fail('tls-auth, tls-crypt and tls-crypt-v2 are mutually exclusive');
  if (options.has('key-direction')) {
    const value = one('key-direction');
    if (!proxy['tls-auth'] || !['0', '1'].includes(value)) fail('Invalid key-direction or no tls-auth key');
    proxy['key-direction'] = value;
  }

  if (options.has('auth-user-pass') || blocks.has('auth-user-pass')) {
    const argument = options.get('auth-user-pass') ?? [];
    if (argument.length > 1 || (argument.length && argument[0] !== '[inline]')) fail('External auth-user-pass files are not supported');
    if (!blocks.has('auth-user-pass')) fail('Interactive auth-user-pass credentials are unavailable');
    const credentials = blocks.get('auth-user-pass').split('\n');
    if (credentials.length !== 2 || !credentials[0] || !credentials[1]) fail('Invalid inline auth-user-pass credentials');
    if (proxy.cert || proxy.key) fail('Combined certificate and username/password authentication is not exported');
    [proxy.username, proxy.password] = credentials;
  }
  if (!proxy.cert && !proxy.username) fail('No supported client authentication material');

  if (options.has('cipher')) {
    const value = one('cipher').toUpperCase();
    if (!CIPHERS.has(value)) fail(`Unsupported cipher: ${safeText(value, 40)}`);
    proxy.cipher = value;
  } else {
    // OpenVPN 2.x profiles can otherwise inherit a cipher unlike Mihomo's default.
    fail('Explicit OpenVPN cipher is required');
  }
  if (options.has('auth')) {
    const value = one('auth').toUpperCase().replace(/^SHA-1$/, 'SHA1');
    if (!AUTHS.has(value)) fail(`Unsupported auth digest: ${safeText(value, 40)}`);
    proxy.auth = value;
  } else proxy.auth = 'SHA1'; // OpenVPN's auth default, unlike Mihomo's SHA256 default.
  if (options.has('data-ciphers')) {
    const values = one('data-ciphers').toUpperCase().split(':');
    if (!values.length || values.some(value => !CIPHERS.has(value))) fail('Unsupported data-ciphers list');
    proxy['data-ciphers'] = values;
  }
  if (options.has('data-ciphers-fallback')) {
    const value = one('data-ciphers-fallback').toUpperCase();
    if (!CIPHERS.has(value)) fail('Unsupported data-ciphers-fallback');
    proxy['data-ciphers-fallback'] = value;
  }
  if (options.has('comp-lzo')) {
    const values = options.get('comp-lzo');
    const value = values.length ? one('comp-lzo').toLowerCase() : 'adaptive';
    if (!['yes', 'no', 'adaptive'].includes(value)) fail('Unsupported comp-lzo mode');
    proxy['comp-lzo'] = value;
  } else proxy['comp-lzo'] = 'no';
  for (const [name, target] of [['ping', 'ping'], ['ping-restart', 'ping-restart'], ['tran-window', 'tran-window'], ['hand-window', 'handshake-timeout'], ['tun-mtu', 'mtu']]) {
    if (!options.has(name)) continue;
    const value = one(name);
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > 2147483647 || (name === 'tun-mtu' && (Number(value) < 576 || Number(value) > 65535))) fail(`Invalid OpenVPN ${name}`);
    proxy[target] = Number(value);
  }
  // Keep initial handshakes alive beyond Mihomo's 5s request timeout, and
  // maintain/recover idle tunnels when the profile omits keepalive settings.
  proxy['handshake-timeout'] ??= 30;
  proxy.ping ??= 10;
  proxy['ping-restart'] ??= 60;
  // This is DNS inside the established OpenVPN tunnel, not a bootstrap resolver.
  proxy['remote-dns-resolve'] = true;
  proxy.dns = ['1.1.1.1', '8.8.8.8'];
  proxy.udp = true;
  return { proxy, warnings };
}

function decodeBase64(value) {
  const compact = value.replace(/\s/g, '');
  if (!compact || compact.length > Math.ceil(MAX_OVPN_BYTES * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0) fail('Invalid or oversized OpenVPN base64');
  let binary;
  try { binary = atob(compact); } catch { fail('Invalid OpenVPN base64'); }
  // Public profiles are normally ASCII. Avoid allocating/copying a typed-array
  // for every byte in the common case (important on Workers' short CPU budget).
  if (/^[\x00-\x7f]*$/.test(binary)) return binary.replace(/\r\n?/g, '\n');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\r\n?/g, '\n'); } catch { fail('OpenVPN profile is not UTF-8'); }
}

function stableId(value) {
  let hash = 14695981039346656037n;
  for (const byte of new TextEncoder().encode(value)) { hash ^= BigInt(byte); hash = BigInt.asUintN(64, hash * 1099511628211n); }
  return 'vg-' + hash.toString(16).padStart(16, '0');
}

/**
 * sourceCount includes CSV data rows. skipped includes invalid, duplicate and
 * over-limit rows. warnings are bounded plain-text messages, never profile data.
 */
export function parseVpnGateCsv(text, { limit = 100 } = {}) {
  if (typeof text !== 'string' || text.length > MAX_CSV_BYTES) fail('VPN Gate CSV is missing or oversized');
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) fail('limit must be an integer between 1 and 200');
  const records = csvRecords(text);
  const headerIndex = records.findIndex(row => row[0]?.replace(/^#/, '').trim() === 'HostName' && row.includes('OpenVPN_ConfigData_Base64'));
  if (headerIndex < 0) fail('VPN Gate CSV header was not found');
  const header = records[headerIndex].map((value, index) => index === 0 ? value.replace(/^#/, '').trim() : value.trim());
  if (new Set(header).size !== header.length || !['HostName', 'IP', 'Score', 'Ping', 'Speed', 'CountryLong', 'CountryShort', 'Uptime', 'OpenVPN_ConfigData_Base64'].every(name => header.includes(name))) fail('VPN Gate CSV header is incomplete or ambiguous');
  const nodes = [], candidates = [], warnings = [], seen = new Set();
  let sourceCount = 0;
  const warn = value => { if (warnings.length < MAX_WARNINGS) warnings.push(value); };
  for (const row of records.slice(headerIndex + 1)) {
    if (row.every(value => !value.trim()) || row[0]?.startsWith('*') || row[0]?.startsWith('#')) continue;
    sourceCount++;
    const label = `Row ${sourceCount}`;
    if (row.length !== header.length) { warn(`${label}: CSV field count differs from header`); continue; }
    const entry = Object.fromEntries(header.map((name, index) => [name, row[index]]));
    candidates.push({ entry, label });
  }
  candidates.sort((a, b) => numeric(b.entry.Score) - numeric(a.entry.Score) || numeric(b.entry.Speed) - numeric(a.entry.Speed));
  for (const { entry, label } of candidates) {
    if (nodes.length === limit) break;
    try {
      if (!validHost(entry.IP) || !entry.HostName) fail('Invalid VPN Gate server metadata');
      const ovpn = decodeBase64(entry.OpenVPN_ConfigData_Base64);
      const parsed = parseOvpn(ovpn);
      const { server, port, proto } = parsed.proxy;
      const key = `${server.toLowerCase()}|${port}|${proto}`;
      if (seen.has(key)) fail('Duplicate OpenVPN endpoint');
      seen.add(key);
      const id = stableId(key), country = /^[A-Za-z]{2}$/.test(entry.CountryShort) ? entry.CountryShort.toUpperCase() : 'ZZ';
      const countryName = COUNTRY_NAMES_ZH.of(country) || '未知地区';
      const name = `${countryName} ${server}:${port} ${proto.toUpperCase()} ${id.slice(-6)}`;
      const node = { id, name, country, countryLong: safeText(entry.CountryLong), ip: entry.IP, score: numeric(entry.Score), speed: numeric(entry.Speed), ping: numeric(entry.Ping, -1), uptime: numeric(entry.Uptime), ovpn, proxy: { name, ...parsed.proxy } };
      nodes.push(node);
      for (const message of parsed.warnings) warn(`${label}: ${message}`);
    } catch (error) { warn(`${label}: ${safeText(error.message, 180)}`); }
  }
  nodes.sort((a, b) => b.score - a.score || b.speed - a.speed || a.id.localeCompare(b.id));
  const result = nodes;
  if (nodes.length === limit && sourceCount > limit) warn(`Output limit ${limit} reached; remaining rows were not converted`);
  return { nodes: result, sourceCount, skipped: sourceCount - result.length, warnings };
}

function scalar(value) {
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  return JSON.stringify(String(value)).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

/** A small emitter for plain mappings/lists/scalars; every string is quoted. */
function yaml(value, indent = 0) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    if (!value.length) return pad + '[]';
    return value.map(item => {
      if (item !== null && typeof item === 'object') return pad + '-\n' + yaml(item, indent + 2);
      return pad + '- ' + scalar(item);
    }).join('\n');
  }
  return Object.entries(value).map(([key, item]) => {
    if (item !== null && typeof item === 'object') {
      if (Array.isArray(item) && item.length === 0) return pad + scalar(key) + ': []';
      return pad + scalar(key) + ':\n' + yaml(item, indent + 2);
    }
    return pad + scalar(key) + ': ' + scalar(item);
  }).join('\n');
}

/** Render either a complete Mihomo config or a proxy-provider document. */
export function renderMihomo(nodes, { providerOnly = false } = {}) {
  if (!Array.isArray(nodes) || !nodes.length) fail('Cannot render an empty VPN Gate subscription');
  const names = nodes.map(node => node.proxy?.name);
  if (names.some(name => typeof name !== 'string' || !name || ['DIRECT', 'REJECT', 'VPN Gate'].includes(name)) || new Set(names).size !== names.length) fail('Proxy names must be non-empty, unique and non-reserved');
  const proxies = nodes.map(node => node.proxy);
  const document = providerOnly ? { proxies } : {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    dns: {
      enable: true,
      listen: '127.0.0.1:1053',
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'default-nameserver': ['1.1.1.1', '8.8.8.8'],
      nameserver: ['https://1.1.1.1/dns-query#VPN Gate', 'https://8.8.8.8/dns-query#VPN Gate'],
    },
    proxies,
    'proxy-groups': [{ name: 'VPN Gate', type: 'select', proxies: names }],
    rules: ['MATCH,VPN Gate'],
  };
  return '# Requires Mihomo with native OpenVPN support.\n' + yaml(document) + '\n';
}
