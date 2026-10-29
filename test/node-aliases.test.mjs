import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFreeSubscription } from '../src/free-converter.mjs';
import { renameSubscriptionNodes, aliasesAreCurrent } from '../src/node-aliases.mjs';

const uuid='11111111-2222-4333-8444-555555555555';
const b64=value=>Buffer.from(typeof value==='string'?value:JSON.stringify(value),'utf8').toString('base64');
const parse=uri=>parseFreeSubscription(uri,{sourceId:'synthetic-publisher',sourceName:'测试来源'}).nodes[0];
const vless=(server,country='JP')=>parse(`vless://${uuid}@${server}:443?security=tls&sni=tls.example.com&type=ws&host=ws.example.com&path=%2Fsocket#${country}`);
const removeLabels=node=>{
  const {name,proxy,outbound,uri,...rest}=node;
  const {name:proxyName,...proxySettings}=proxy;
  const {tag,...outboundSettings}=outbound;
  return {...rest,proxy:proxySettings,outbound:outboundSettings};
};

test('country aliases have unique per-country numbering across interleaved publishers',()=>{
  const nodes=[vless('one.example.com'),vless('two.example.com','US'),vless('three.example.com'),vless('four.example.com','Unspecified')];
  assert.equal(nodes[3].country,'ZZ');
  const renamed=renameSubscriptionNodes(nodes);
  assert.deepEqual(renamed.map(n=>n.name),['日本阿高节点01','美国阿高节点01','日本阿高节点02','未标注阿高节点01']);
  assert.equal(new Set(renamed.map(n=>n.name)).size,renamed.length);
  assert.equal(aliasesAreCurrent(renamed.map(({name,country})=>({name,country}))),true);
});

test('renaming changes display labels in every representation without modifying connections or input nodes',()=>{
  const inputs=[
    vless('one.example.com'),
    parse(`ss://${b64('chacha20-ietf-poly1305:synthetic-password')}@two.example.com:8388#US`),
    parse('trojan://synthetic-password@three.example.com:443?sni=tls.example.com#KR'),
    parse('hysteria2://synthetic-password@four.example.com:443?sni=tls.example.com#SG'),
  ];
  const before=structuredClone(inputs);
  const renamed=renameSubscriptionNodes(inputs);
  assert.deepEqual(inputs,before);
  for(let i=0;i<inputs.length;i++){
    assert.notEqual(renamed[i],inputs[i]);
    assert.equal(renamed[i].proxy.name,renamed[i].name);
    assert.equal(renamed[i].outbound.tag,renamed[i].name);
    assert.equal(decodeURIComponent(new URL(renamed[i].uri).hash.slice(1)),renamed[i].name);
    assert.equal(renamed[i].uri.split('#')[0],inputs[i].uri.split('#')[0]);
    assert.deepEqual(removeLabels(renamed[i]),removeLabels(inputs[i]));
    assert.equal(parseFreeSubscription(renamed[i].uri).nodes[0].id,inputs[i].id);
  }
});

test('VMess ps uses UTF-8-safe base64 and retains the original transport and authentication fields',()=>{
  const original=parse('vmess://'+b64({v:'2',ps:'美国测试节点',add:'vmess.example.com',port:'443',id:uuid,aid:'0',scy:'auto',net:'grpc',type:'none',path:'service-name',tls:'tls',sni:'tls.example.com',fp:'firefox'}));
  const [renamed]=renameSubscriptionNodes([original]);
  const oldDocument=JSON.parse(Buffer.from(original.uri.slice(8),'base64').toString('utf8'));
  const document=JSON.parse(Buffer.from(renamed.uri.slice(8),'base64').toString('utf8'));
  assert.equal(document.ps,'美国阿高节点01');
  assert.deepEqual({...document,ps:oldDocument.ps},oldDocument);
  assert.deepEqual(removeLabels(renamed),removeLabels(original));
  assert.equal(parseFreeSubscription(renamed.uri).nodes[0].id,original.id);
});

test('current alias detection rejects legacy names, duplicate sequences and wrong-country labels',()=>{
  const [first,second]=renameSubscriptionNodes([vless('one.example.com'),vless('two.example.com')]);
  const metadata=[first,second].map(({name,country})=>({name,country}));
  assert.equal(aliasesAreCurrent(metadata),true);
  assert.equal(aliasesAreCurrent([{...metadata[0],name:'日本 Legacy VLESS'},metadata[1]]),false);
  assert.equal(aliasesAreCurrent([metadata[0],{...metadata[1],name:metadata[0].name}]),false);
  assert.equal(aliasesAreCurrent([{...metadata[0],name:'美国阿高节点01'},metadata[1]]),false);
  assert.deepEqual(renameSubscriptionNodes([first,second]),[first,second]);
});

test('numbering remains unique when a country has more than 99 nodes',()=>{
  const prototype=vless('node.example.com');
  const renamed=renameSubscriptionNodes(Array.from({length:101},(_,i)=>({...prototype,id:`synthetic-${i}`})));
  assert.equal(renamed[0].name,'日本阿高节点01');
  assert.equal(renamed[99].name,'日本阿高节点100');
  assert.equal(renamed[100].name,'日本阿高节点101');
  assert.equal(new Set(renamed.map(n=>n.name)).size,101);
  assert.equal(aliasesAreCurrent(renamed),true);
});
