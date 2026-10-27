/** Public subscription URIs -> independently constructed Mihomo/sing-box nodes.
 * Never imports upstream routing, scripts, files, plugins or executable content.
 */
const MAX_TEXT = 4 * 1024 * 1024;
const MAX_URI = 16384;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const METHODS = new Set(['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305']);
const FINGERPRINTS = new Set(['chrome', 'firefox', 'safari', 'edge', 'ios', 'android', '360', 'qq', 'random', 'randomized']);
const ZH = new Intl.DisplayNames(['zh-CN'], { type: 'region', fallback: 'none' });
const EN = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' });
const COUNTRIES = ['JP','US','KR','HK','TW','SG','DE','GB','FR','NL','CA','AU','RU','IN','TH','VN','MY','ID','PH','TR','IR','AE','SA','IL','ZA','BR','AR','CL','MX','IT','ES','PT','SE','NO','FI','DK','CH','AT','PL','CZ','RO','HU','UA','BG','GR','IE','IS','LU','BE','NZ','CN','MO','PK','BD','KZ','MD','EE','LT','LV','CY','GE','AM','AZ','HR','RS','SI','SK'];
const COUNTRY_NAMES = new Map(COUNTRIES.map(code => [code, { zh: ZH.of(code), en: EN.of(code) }]));
const COUNTRY_RULES = COUNTRIES.map(code => ({ code, zh: COUNTRY_NAMES.get(code).zh, english: COUNTRY_NAMES.get(code).en.toLowerCase(), codePattern: new RegExp(`(?:^|[^a-z])${code}(?:$|[^a-z])`, 'i') })).sort((a,b) => b.zh.length-a.zh.length);
const COUNTRY_ALIASES = [['USA','US'],['UK','GB'],['United States','US'],['United Kingdom','GB'],['South Korea','KR'],['Hong Kong','HK'],['Taiwan','TW']].map(([name,code])=>({code,pattern:new RegExp(`(?:^|[^a-z])${name}(?:$|[^a-z])`,'i')}));
function countryNames(code) { if (!COUNTRY_NAMES.has(code)) COUNTRY_NAMES.set(code,{zh:ZH.of(code),en:EN.of(code)}); return COUNTRY_NAMES.get(code); }
class InvalidNode extends Error {}
function fail(message) { throw new InvalidNode(message); }
function clean(value, max = 80) { return String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, max); }
function value(value, max = 4096) { if (typeof value !== 'string' || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) fail('Invalid connection text'); return value; }
function decode(value) { try { return decodeURIComponent(value); } catch { fail('Invalid percent encoding'); } }
function fromBase64(text) {
  const input = text.replace(/\s/g, '').replaceAll('-', '+').replaceAll('_', '/');
  if (!input || !/^[a-zA-Z0-9+/]*={0,2}$/.test(input) || input.length % 4 === 1) fail('Invalid base64');
  try {
    const raw = atob(input);
    if (!/[^\x00-\x7f]/.test(raw)) return raw;
    const bytes = new Uint8Array(raw.length);
    for (let i=0;i<raw.length;i++) bytes[i]=raw.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }
  catch { fail('Invalid base64 or UTF-8'); }
}
function toBase64(text) {
  const bytes = new TextEncoder().encode(text); let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
function host(input) {
  const s = value(input, 253).replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!s || /[\s/%@?#\\]/.test(s)) fail('Invalid server address');
  if (s.includes(':')) {
    try { new URL(`http://[${s}]/`); } catch { fail('Invalid IPv6 server'); }
    if (!/^[23][0-9a-f]{3}:/i.test(s) || /^200[12]:|^2001:db8:/i.test(s)) fail('Non-public server address');
    return s;
  }
  if (/^[0-9.]+$/.test(s)) {
    const octets = s.split('.');
    if (octets.length !== 4 || octets.some(n => !/^(0|[1-9][0-9]{0,2})$/.test(n) || +n > 255)) fail('Invalid IPv4 server');
    const [a,b,c] = octets.map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && [0,2].includes(c)))) || (a === 198 && ([18,19].includes(b) || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113)) fail('Non-public server address');
    return s;
  }
  if (!s.includes('.') || /(?:^|\.)(?:localhost|local|internal|lan|home|test)$/.test(s) || !/[a-z]$/i.test(s) || s.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) fail('Invalid public server hostname');
  return s;
}
function port(input, fallback) { const s = String(input || fallback || ''); if (!/^\d+$/.test(s) || +s < 1 || +s > 65535) fail('Invalid server port'); return +s; }
function identifier(input) { if (!UUID.test(input)) fail('Invalid UUID'); return input.toLowerCase(); }
function parseUrl(uri) { try { return new URL(uri); } catch { fail('Invalid node URI'); } }
function query(url, allowed) {
  const result = Object.create(null);
  for (const [key, val] of url.searchParams) {
    if (Object.hasOwn(result, key)) fail('Duplicate URI option');
    if (!allowed.has(key) && val !== '') fail('Unsupported URI option');
    if (allowed.has(key)) result[key] = value(val);
  }
  for (const key of ['insecure','allowInsecure','skip-cert-verify']) {
    if (result[key] && !['false','0'].includes(result[key].toLowerCase())) fail('Certificate verification disabled');
  }
  return result;
}
const META = ['remarks','remark','group'];
const VERIFY = ['insecure','allowInsecure','skip-cert-verify'];
const COMMON = new Set([...META,...VERIFY,'security','type','headerType','sni','peer','host','path','fp','alpn','pbk','sid','spx','flow','encryption','packetEncoding','serviceName','mode']);
function transport(proxy, outbound, options) {
  const network = options.type || 'tcp';
  if (!['tcp','raw','ws','grpc'].includes(network)) fail('Unsupported transport');
  if (options.headerType && options.headerType !== 'none') fail('Unsupported TCP header');
  if (options.mode && options.mode !== 'gun') fail('Unsupported gRPC mode');
  if (network === 'tcp' || network === 'raw') {
    if (options.path || options.serviceName || options.host) fail('Unexpected TCP transport option');
    return 'tcp';
  }
  proxy.network = network;
  if (network === 'ws') {
    if (options.serviceName || options.mode) fail('Unexpected WebSocket option');
    let path = options.path || '/';
    if (!path.startsWith('/')) fail('Invalid WebSocket path');
    const ws = { path }, sb = { type: 'ws', path };
    if (options.host) { const h = value(options.host, 253); if (/[\s,]/.test(h)) fail('Invalid WebSocket host'); ws.headers = { Host: h }; sb.headers = { Host: h }; }
    // v2ray sharing links commonly encode early data as ?ed=N in the WS path.
    const u = new URL(path, 'https://example.invalid');
    if (u.searchParams.has('ed')) {
      const ed = u.searchParams.get('ed');
      if (!/^\d+$/.test(ed) || +ed > 65535) fail('Invalid WebSocket early data');
      u.searchParams.delete('ed'); path = u.pathname + u.search;
      ws.path = sb.path = path;
      if (+ed > 0) { ws['max-early-data'] = +ed; ws['early-data-header-name'] = 'Sec-WebSocket-Protocol'; sb.max_early_data = +ed; sb.early_data_header_name = 'Sec-WebSocket-Protocol'; }
    }
    proxy['ws-opts'] = ws; outbound.transport = sb;
  } else {
    if (options.host) fail('Unsupported gRPC authority');
    const service = options.serviceName || options.path || '';
    proxy['grpc-opts'] = { 'grpc-service-name': service };
    outbound.transport = { type: 'grpc', service_name: service };
  }
  return network;
}
function tls(proxy, outbound, options, { defaultSecurity = 'none', trojan = false } = {}) {
  const security = options.security || defaultSecurity;
  if (!['none','tls','reality'].includes(security) || (trojan && security !== 'tls')) fail('Unsupported transport security');
  if (options.sni && options.peer && options.sni !== options.peer) fail('Conflicting TLS server names');
  const sni = options.sni || options.peer || '';
  if (security === 'none') {
    if (sni || options.fp || options.alpn || options.pbk || options.sid || options.spx) fail('TLS options without TLS');
    return security;
  }
  const sb = { enabled: true, insecure: false };
  if (!trojan) proxy.tls = true;
  proxy['skip-cert-verify'] = false;
  if (sni) { if (/[\s/@?#\\]/.test(sni)) fail('Invalid TLS server name'); proxy[trojan ? 'sni' : 'servername'] = sni; sb.server_name = sni; }
  if (options.alpn) {
    const list = options.alpn.split(',');
    if (list.some(x => !x || x.length > 64 || /\s/.test(x)) || list.length > 8) fail('Invalid ALPN');
    proxy.alpn = list; sb.alpn = list;
  }
  const fp = options.fp || (security === 'reality' ? 'chrome' : '');
  if (fp) { if (!FINGERPRINTS.has(fp)) fail('Unsupported TLS fingerprint'); proxy['client-fingerprint'] = fp; sb.utls = { enabled: true, fingerprint: fp }; }
  if (security === 'reality') {
    if (!/^[A-Za-z0-9_-]{43}$/.test(options.pbk || '') || !/^(?:[0-9a-f]{2}){0,8}$/i.test(options.sid || '') || !sni) fail('Invalid Reality parameters');
    // SpiderX is not a connection parameter implemented by these cores.
    if (options.spx && options.spx !== '/') fail('Unsupported Reality spider path');
    proxy['reality-opts'] = { 'public-key': options.pbk, 'short-id': (options.sid || '').toLowerCase() };
    sb.reality = { enabled: true, public_key: options.pbk, short_id: (options.sid || '').toLowerCase() };
  } else if (options.pbk || options.sid || options.spx) fail('Reality options without Reality');
  outbound.tls = sb;
  return security;
}
function pair(type, server, serverPort) { return { proxy: { type, server, port: serverPort, udp: true }, outbound: { type: type === 'ss' ? 'shadowsocks' : type, server, server_port: serverPort } }; }
function parseVlessTrojan(uri, kind) {
  const u = parseUrl(uri), q = query(u, COMMON), server = host(u.hostname), p = port(u.port, 443);
  if (u.pathname && u.pathname !== '/') fail('Unexpected URI pathname');
  const result = pair(kind, server, p), { proxy, outbound } = result;
  if (u.password) fail('Unexpected password separator');
  if (kind === 'vless') { proxy.uuid = outbound.uuid = identifier(decode(u.username)); }
  else { proxy.password = outbound.password = value(decode(u.username)); if (!proxy.password) fail('Missing password'); }
  const network = transport(proxy, outbound, q);
  const security = tls(proxy, outbound, q, { defaultSecurity: kind === 'trojan' ? 'tls' : 'none', trojan: kind === 'trojan' });
  if (q.encryption && q.encryption !== 'none') fail('Unsupported VLESS encryption');
  if (q.flow) { if (kind !== 'vless' || q.flow !== 'xtls-rprx-vision' || network !== 'tcp' || security === 'none') fail('Unsupported VLESS flow'); proxy.flow = outbound.flow = q.flow; }
  if (q.packetEncoding) { if (kind !== 'vless' || !['xudp','packetaddr'].includes(q.packetEncoding)) fail('Unsupported packet encoding'); proxy['packet-encoding'] = outbound.packet_encoding = q.packetEncoding; }
  return { ...result, remark: decode(u.hash.slice(1)) || q.remarks || q.remark || '', protocol: kind };
}
function parseVmess(uri) {
  let data; try { data = JSON.parse(fromBase64(uri.slice(8).split('#')[0])); } catch { fail('Invalid VMess document'); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('Invalid VMess document');
  const allowed = new Set(['v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp',...VERIFY]);
  for (const key of Object.keys(data)) if (!allowed.has(key) && data[key] !== '') fail('Unsupported VMess field');
  for (const key of VERIFY) if (data[key] && !['false','0'].includes(String(data[key]).toLowerCase())) fail('Certificate verification disabled');
  if (data.aid !== undefined && Number(data.aid) !== 0) fail('Legacy VMess alterId unsupported');
  const result = pair('vmess', host(data.add), port(data.port)), { proxy, outbound } = result;
  proxy.uuid = outbound.uuid = identifier(data.id);
  const cipher = data.scy || 'auto'; if (!['auto','aes-128-gcm','chacha20-poly1305','none','zero'].includes(cipher)) fail('Unsupported VMess cipher');
  proxy.alterId = 0; proxy.cipher = outbound.security = cipher;
  const q = { type: data.net || 'tcp', headerType: data.type || 'none', host: data.host || '', path: data.path || '', security: data.tls || 'none', sni: data.sni || '', alpn: data.alpn || '', fp: data.fp || '' };
  for (const v of Object.values(q)) value(v);
  transport(proxy, outbound, q); tls(proxy, outbound, q);
  return { ...result, remark: clean(data.ps, 200), protocol: 'vmess', uriDocument: data };
}
function parseSS(uri) {
  let u = parseUrl(uri), auth;
  if (!u.hostname || !u.port) {
    const [body, fragment = ''] = uri.slice(5).split('#');
    if (body.includes('?')) fail('Unsupported legacy Shadowsocks options');
    u = parseUrl(`ss://${fromBase64(body)}#${fragment}`);
  }
  query(u, new Set(META));
  if (u.pathname && u.pathname !== '/') fail('Unexpected Shadowsocks pathname');
  if (u.password) auth = decode(u.username) + ':' + decode(u.password);
  else auth = fromBase64(decode(u.username));
  const colon = auth.indexOf(':'); if (colon < 1) fail('Invalid Shadowsocks credentials');
  const method = auth.slice(0, colon).toLowerCase(), password = value(auth.slice(colon + 1));
  if (!METHODS.has(method) || !password) fail('Unsupported Shadowsocks cipher or missing password');
  if (method.startsWith('2022-')) {
    // SIP022 requires fixed-length base64 PSKs; SIP023 permits colon-separated AES identity keys.
    const keys = password.split(':'), keyBytes = method === '2022-blake3-aes-128-gcm' ? 16 : 32;
    if (method === '2022-blake3-chacha20-poly1305' && keys.length !== 1) fail('Shadowsocks 2022 identity keys require AES');
    for (const key of keys) {
      let binary;
      try { binary = atob(key); } catch { fail('Invalid Shadowsocks 2022 key'); }
      // Decode as bytes, not UTF-8; preserve only the padded standard base64 accepted by both cores.
      if (binary.length !== keyBytes || btoa(binary) !== key) fail('Invalid Shadowsocks 2022 key');
    }
  }
  const result = pair('ss', host(u.hostname), port(u.port)), { proxy, outbound } = result;
  proxy.cipher = outbound.method = method; proxy.password = outbound.password = password;
  return { ...result, remark: decode(u.hash.slice(1)), protocol: 'ss' };
}
function parseHysteria2(uri) {
  const u = parseUrl(uri), q = query(u, new Set([...META,...VERIFY,'sni','peer','alpn','security','obfs','obfs-password']));
  if (u.pathname && u.pathname !== '/') fail('Unexpected Hysteria2 pathname');
  if (q.security && q.security !== 'tls') fail('Hysteria2 requires TLS');
  const result = pair('hysteria2', host(u.hostname), port(u.port, 443)), { proxy, outbound } = result;
  const password = value(decode(u.username) + (u.password ? ':' + decode(u.password) : ''));
  if (!password) fail('Missing Hysteria2 password');
  proxy.password = outbound.password = password;
  tls(proxy, outbound, { ...q, security: 'tls' }, { trojan: true });
  if (q.obfs) { if (q.obfs !== 'salamander' || !q['obfs-password']) fail('Unsupported Hysteria2 obfuscation'); proxy.obfs = q.obfs; proxy['obfs-password'] = q['obfs-password']; outbound.obfs = { type: q.obfs, password: q['obfs-password'] }; }
  else if (q['obfs-password']) fail('Obfuscation password without obfuscation');
  return { ...result, remark: decode(u.hash.slice(1)), protocol: 'hysteria2' };
}
function stableId(text) {
  let a = 2166136261, b = 2246822519;
  for (let i = 0; i < text.length; i++) { a = Math.imul(a ^ text.charCodeAt(i), 16777619); b = Math.imul(b ^ text.charCodeAt(i), 3266489917); }
  return 'free-' + (a >>> 0).toString(16).padStart(8,'0') + (b >>> 0).toString(16).padStart(8,'0');
}
function countryFromName(name) {
  const flag = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u)?.[0];
  if (flag) { const code = [...flag].map(c => String.fromCharCode(c.codePointAt(0) - 0x1f1e6 + 65)).join(''); if (countryNames(code).zh) return code; }
  const text = clean(name, 200);
  for (const [alias,code] of [['香港','HK'],['澳门','MO'],['台湾','TW'],['韩国','KR'],['俄罗斯','RU'],['英国','GB']]) if (text.includes(alias)) return code;
  for (const {pattern,code} of COUNTRY_ALIASES) if (pattern.test(text)) return code;
  const lower=text.toLowerCase();
  for (const {code,zh,english,codePattern} of COUNTRY_RULES) {
    if (codePattern.test(text) || text.includes(zh) || lower.includes(english)) return code;
  }
  return 'ZZ';
}
/** Unknown or unsafe individual entries are skipped; malformed envelopes fail. */
export function parseFreeSubscription(text, { sourceId = 'free', sourceName = 'Free', limit = 200 } = {}) {
  if (typeof text !== 'string' || text.length > MAX_TEXT) fail('Subscription is missing or oversized');
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) fail('Invalid node limit');
  let decoded = text.replace(/^\uFEFF/, '').trim();
  // A greedy, unanchored scheme regexp is quadratic on large base64 bodies.
  if (!decoded.includes('://')) decoded = fromBase64(decoded);
  if (decoded.length > MAX_TEXT) fail('Subscription is oversized');
  const lines = decoded.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  const nodes = [], warnings = [], seen = new Set(); let sourceCount = 0;
  for (const uri of lines) {
    sourceCount++;
    if (nodes.length >= limit) continue;
    try {
      if (uri.length > MAX_URI) fail('Node URI too long');
      const scheme = uri.match(/^([a-z0-9]+):\/\//i)?.[1]?.toLowerCase();
      let parsed;
      if (scheme === 'ss') parsed = parseSS(uri);
      else if (scheme === 'vmess') parsed = parseVmess(uri);
      else if (scheme === 'vless' || scheme === 'trojan') parsed = parseVlessTrojan(uri, scheme);
      else if (scheme === 'hysteria2' || scheme === 'hy2') parsed = parseHysteria2(uri);
      else fail('Unsupported node protocol');
      const identity = JSON.stringify(parsed.outbound), id = stableId(identity);
      if (seen.has(identity)) continue;
      seen.add(identity);
      const country = countryFromName(parsed.remark), label = country === 'ZZ' ? '未标注' : countryNames(country).zh;
      const name = `${label} ${clean(sourceName, 24)} ${parsed.protocol.toUpperCase()} ${parsed.proxy.server}:${parsed.proxy.port} ${id.slice(-6)}`;
      parsed.proxy.name = name; parsed.outbound.tag = name;
      // VMess stores its label inside the base64 JSON, unlike URL-style formats.
      const cleanUri = parsed.uriDocument ? 'vmess://' + toBase64(JSON.stringify({ ...parsed.uriDocument, ps: name })) : uri.split('#')[0] + '#' + encodeURIComponent(name);
      nodes.push({ id, name, country, countryLong: country === 'ZZ' ? 'Unspecified' : countryNames(country).en, ip: parsed.proxy.server, protocol: parsed.protocol, sourceId: clean(sourceId, 64), sourceName: clean(sourceName, 80), proxy: parsed.proxy, outbound: parsed.outbound, uri: cleanUri });
    } catch (error) { if (warnings.length < 100) warnings.push(`Node ${sourceCount}: ${error instanceof InvalidNode ? error.message : 'Invalid node data'}`); }
  }
  return { nodes, sourceCount, skipped: sourceCount - nodes.length, warnings };
}
export function renderFreeKaring(nodes) {
  if (!Array.isArray(nodes) || !nodes.length || nodes.some(n => !n.outbound?.tag)) fail('No compatible Karing nodes');
  return JSON.stringify({ outbounds: nodes.map(n => n.outbound) }, null, 2) + '\n';
}
export function renderUriSubscription(nodes) {
  if (!Array.isArray(nodes) || !nodes.length || nodes.some(n => !n.uri)) fail('No compatible URI nodes');
  return toBase64(nodes.map(n => n.uri).join('\n') + '\n') + '\n';
}
