import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFreeSubscription, renderFreeKaring, renderUriSubscription } from '../src/free-converter.mjs';

const UUID = '11111111-2222-4333-8444-555555555555';
const PK = 'G'.repeat(43);
const b64 = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64');
const parse = value => parseFreeSubscription(value, { sourceId: 'public-test', sourceName: '公开测试' });
const vless = query => `vless://${UUID}@node.example.com:443?${query}#${encodeURIComponent('🇯🇵 Japan')}`;

test('VLESS Reality preserves keys, vision, SNI, fingerprint and packet encoding', () => {
  const { nodes, warnings } = parse(vless(`security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=${PK}&sid=ab12&flow=xtls-rprx-vision&packetEncoding=xudp`));
  assert.equal(warnings.length, 0); assert.equal(nodes.length, 1);
  const n = nodes[0]; assert.equal(n.country, 'JP'); assert.match(n.name, /^日本 /);
  assert.equal(n.proxy.uuid, UUID); assert.equal(n.proxy.flow, 'xtls-rprx-vision');
  assert.deepEqual(n.proxy['reality-opts'], { 'public-key': PK, 'short-id': 'ab12' });
  assert.equal(n.proxy['skip-cert-verify'], false); assert.equal(n.outbound.tls.insecure, false);
  assert.deepEqual(n.outbound.tls.reality, { enabled: true, public_key: PK, short_id: 'ab12' });
  assert.equal(n.outbound.packet_encoding, 'xudp'); assert.equal(n.outbound.tls.server_name, 'www.example.com');
  assert.equal(n.outbound.tag, n.name); assert.equal(n.sourceId, 'public-test');
});

test('VLESS WebSocket TLS and early data map to both clients', () => {
  const n = parse(vless('security=tls&type=ws&sni=tls.example.com&host=ws.example.com&path=%2Fsocket%3Fed%3D2048&alpn=h2,http%2F1.1')).nodes[0];
  assert.deepEqual(n.proxy['ws-opts'], { path: '/socket', headers: { Host: 'ws.example.com' }, 'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol' });
  assert.deepEqual(n.outbound.transport, { type: 'ws', path: '/socket', headers: { Host: 'ws.example.com' }, max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' });
  assert.deepEqual(n.outbound.tls.alpn, ['h2','http/1.1']);
});

test('VLESS raw TCP normalizes to the same identity as TCP, ignoring remarks and source', () => {
  const a = parse(vless('type=tcp&security=none&encryption=none')).nodes[0];
  const b = parseFreeSubscription(vless('encryption=none&security=none&type=raw').replace('Japan','Other'), { sourceName: 'Other' }).nodes[0];
  assert.equal(a.id, b.id); assert.equal(a.outbound.tls, undefined); assert.equal(a.outbound.transport, undefined);
  assert.notEqual(a.name,b.name);
  const duplicate = parse([vless('security=none&type=tcp'),vless('type=raw&security=none')].join('\n'));
  assert.equal(duplicate.nodes.length, 1); assert.equal(duplicate.skipped,1);
});

test('VMess base64 JSON supports gRPC and secure TLS without upstream routing', () => {
  const uri = 'vmess://' + b64({ v:'2', ps:'美国', add:'node.example.com', port:'443', id:UUID, aid:'0', scy:'auto', net:'grpc', type:'none', path:'myService', tls:'tls', sni:'www.example.com', fp:'firefox' });
  const n = parse(uri).nodes[0]; assert.equal(n.country,'US'); assert.equal(n.proxy.type,'vmess');
  assert.equal(n.proxy.alterId,0); assert.equal(n.outbound.security,'auto');
  assert.deepEqual(n.proxy['grpc-opts'],{'grpc-service-name':'myService'});
  assert.deepEqual(n.outbound.transport,{type:'grpc',service_name:'myService'});
  assert.equal(n.outbound.tls.utls.fingerprint,'firefox');
  assert.ok(!n.uri.includes('#'));
  const shared=JSON.parse(Buffer.from(n.uri.slice(8),'base64').toString('utf8'));
  assert.equal(shared.ps,n.name); assert.equal(shared.id,UUID); assert.equal(shared.path,'myService');
  assert.equal(parse(n.uri).nodes[0].id,n.id);
  const evil = 'vmess://' + b64({ v:'2',add:'node.example.com',port:443,id:UUID,rules:['MATCH,DIRECT'] });
  assert.equal(parse(evil).nodes.length,0);
});

test('Shadowsocks SIP002 and legacy base64 credentials preserve AEAD passwords', () => {
  const creds = 'aes-256-gcm:secret:with-colon';
  const a = parse(`ss://${b64(creds)}@node.example.com:8388#KR`).nodes[0];
  const b = parse(`ss://${b64(`${creds}@node.example.com:8388`)}#Korea`).nodes[0];
  assert.equal(a.id,b.id); assert.equal(a.proxy.password,'secret:with-colon');
  assert.equal(a.outbound.type,'shadowsocks'); assert.equal(a.outbound.method,'aes-256-gcm');
  assert.equal(a.country,'KR'); assert.match(a.name,/^韩国 /);
  assert.equal(parse(`ss://${b64('rc4-md5:secret')}@node.example.com:8388`).nodes.length,0);
  assert.equal(parse(`ss://${b64(creds)}@node.example.com:8388?plugin=external-script`).nodes.length,0);
});

test('Shadowsocks 2022 preserves binary PSKs and AES identity key chains', () => {
  for (const [method, size] of [['2022-blake3-aes-128-gcm',16], ['2022-blake3-aes-256-gcm',32], ['2022-blake3-chacha20-poly1305',32]]) {
    for (const count of method.includes('aes-') ? [1,3] : [1]) {
      const password = Array.from({ length: count }, (_, i) => Buffer.alloc(size, 255-i).toString('base64')).join(':');
      for (const credentials of [b64(`${method}:${password}`), `${method}:${encodeURIComponent(password)}`]) {
        const result = parse(`ss://${credentials}@node.example.com:8388#JP`);
        assert.equal(result.nodes.length,1,`${method}: ${count} keys`);
        assert.equal(result.nodes[0].proxy.password,password);
        assert.equal(result.nodes[0].outbound.password,password);
        assert.equal(parse(result.nodes[0].uri).nodes[0].id,result.nodes[0].id);
      }
    }
  }
});

test('invalid Shadowsocks 2022 keys are skipped before they can prevent core startup', () => {
  const key16 = Buffer.alloc(16,255).toString('base64'), key32 = Buffer.alloc(32,255).toString('base64');
  for (const [method, passwords] of [
    ['2022-blake3-aes-128-gcm', ['not-a-valid-key',key32,`${key16}:${key32}`,`${key16}:`, `:${key16}`, `${key16}::${key16}`, key16.replace(/=+$/,''), key16.replaceAll('/','_'), 'AAAAAAAAAAAAAAAAAAAAAB==']],
    ['2022-blake3-aes-256-gcm', [key16,`${key32}:${key16}`,`${key32}:bad`,`${key32}=`]],
    ['2022-blake3-chacha20-poly1305', [key16,`${key32}:${key32}`]],
  ]) {
    for (const password of passwords) {
      const result = parse(`ss://${b64(`${method}:${password}`)}@node.example.com:8388\n${vless('security=none')}`);
      assert.equal(result.nodes.length,1,`${method} invalid key accepted`);
      assert.equal(result.nodes[0].protocol,'vless');
      assert.equal(result.warnings.length,1);
      assert.ok(!JSON.stringify(result.warnings).includes(password));
    }
  }
});

test('Trojan password escaping and WebSocket transport are preserved', () => {
  const n = parse('trojan://secret%3Apass%40word@node.example.com:443?security=tls&type=ws&sni=www.example.com&host=ws.example.com&path=%2Fproxy#Singapore').nodes[0];
  assert.equal(n.proxy.password,'secret:pass@word'); assert.equal(n.outbound.password,'secret:pass@word');
  assert.equal(n.proxy.sni,'www.example.com'); assert.equal(n.outbound.transport.path,'/proxy');
  assert.equal(n.country,'SG'); assert.equal(n.proxy.tls,undefined);
});

test('Hysteria2 supports alias, authentication and salamander without weakening TLS', () => {
  const n = parse('hy2://user:pass@node.example.com:8443?sni=cert.example.com&obfs=salamander&obfs-password=obfssecret&insecure=0#%E9%A6%99%E6%B8%AF').nodes[0];
  assert.equal(n.protocol,'hysteria2'); assert.equal(n.country,'HK'); assert.equal(n.outbound.password,'user:pass');
  assert.equal(n.proxy.sni,'cert.example.com'); assert.equal(n.outbound.tls.insecure,false);
  assert.deepEqual(n.outbound.obfs,{type:'salamander',password:'obfssecret'});
});

test('base64 subscriptions accept URL safe encoding and missing padding with Chinese names', () => {
  const original = [vless('security=none'), 'trojan://abc@node.example.com:443#%E8%8B%B1%E5%9B%BD'].join('\n');
  const input = Buffer.from(original).toString('base64url');
  const result = parse(input); assert.equal(result.nodes.length,2); assert.equal(result.nodes[1].country,'GB');
  const exported = Buffer.from(renderUriSubscription(result.nodes),'base64').toString('utf8');
  const again = parse(exported); assert.deepEqual(again.nodes.map(n=>n.id),result.nodes.map(n=>n.id));
  assert.ok(exported.includes(encodeURIComponent('日本')));
  assert.ok(!exported.includes('🇯🇵'));
});

test('TLS verification disabling, unsupported transports and ambiguous options are rejected', () => {
  for (const q of ['security=tls&allowInsecure=1','security=tls&insecure=true','security=tls&skip-cert-verify=1','security=reality&pbk=bad','type=xhttp','type=ws&unknown=key','security=tls&sni=a.example.com&sni=b.example.com','security=none&sni=tls.example.com','type=tcp&headerType=http']) {
    assert.equal(parse(vless(q)).nodes.length,0,q);
  }
  assert.equal(parse('hysteria2://secret@node.example.com:443?insecure=1').nodes.length,0);
});

test('private, loopback, link local, reserved and encoded numeric servers are rejected', () => {
  for (const address of ['127.0.0.1','10.2.3.4','192.168.1.1','172.16.0.1','169.254.169.254','100.64.1.1','198.18.0.1','224.0.0.1','2130706433','127.1','0x7f.0.0.1','localhost','proxy.local','[::1]','[::ffff:127.0.0.1]','[fc00::1]','[fe80::1]']) {
    assert.equal(parse(`trojan://secret@${address}:443`).nodes.length,0,address);
  }
  assert.equal(parse('trojan://secret@[2606:4700:4700::1111]:443').nodes.length,1);
});

test('malformed and unsupported entries are skipped without exposing credentials in warnings', () => {
  const secrets = ['TOPSECRET','ANOTHERSECRET'];
  const r = parse(`trojan://${secrets[0]}@bad_server:443\nssr://${secrets[1]}\n${vless('security=none')}\nvmess://%%%`);
  assert.equal(r.sourceCount,4); assert.equal(r.nodes.length,1); assert.equal(r.warnings.length,3);
  for (const secret of secrets) assert.ok(!JSON.stringify(r.warnings).includes(secret));
  assert.ok(!JSON.stringify(r.warnings).includes(UUID));
  assert.throws(()=>parse('this is not base64'));
  assert.throws(()=>parseFreeSubscription(vless('security=none'),{limit:0}));
});

test('Karing export uses only real proxy outbounds and node limits remain bounded', () => {
  const result = parseFreeSubscription([vless('security=none'),'trojan://secret@node.example.com:443'].join('\n'),{limit:1});
  assert.equal(result.nodes.length,1); assert.equal(result.sourceCount,2);
  const doc = JSON.parse(renderFreeKaring(result.nodes));
  assert.deepEqual(Object.keys(doc),['outbounds']); assert.equal(doc.outbounds[0].type,'vless');
  assert.equal(doc.outbounds[0].uuid,UUID); assert.equal(doc.route,undefined);
  assert.throws(()=>renderFreeKaring([])); assert.throws(()=>renderUriSubscription([]));
});

test('large base64 bodies are detected without quadratic scheme matching', () => {
  const input=b64('#'+'a'.repeat(700000)+'\n'+vless('security=none'));
  const started=performance.now();const result=parseFreeSubscription(input,{limit:1});
  assert.equal(result.nodes.length,1);assert.equal(result.sourceCount,1);
  assert.ok(performance.now()-started<1000,'Large base64 detection exceeded a generous CPU budget');
});
