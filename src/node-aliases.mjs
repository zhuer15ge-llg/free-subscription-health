const countries = new Intl.DisplayNames(['zh-CN'], { type:'region', fallback:'none' });
const shortNames = { HK:'香港', MO:'澳门', TW:'台湾' };
function countryName(code) {
  if (!/^[A-Z]{2}$/.test(code ?? '') || code === 'ZZ') return '未标注';
  return shortNames[code] || countries.of(code) || '未标注';
}
function namesFor(nodes) {
  const counts = new Map();
  return nodes.map(node => {
    const base = `${countryName(node.country)}阿高节点`;
    const next = (counts.get(base) || 0) + 1; counts.set(base,next);
    return base + String(next).padStart(2,'0');
  });
}
function base64(text) {
  const bytes = new TextEncoder().encode(text); let binary='';
  for(let i=0;i<bytes.length;i+=8192) binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(binary);
}
function renameUri(uri,name) {
  if (typeof uri !== 'string') throw new Error('Node URI is missing');
  if (uri.startsWith('vmess://')) {
    const bytes=Uint8Array.from(atob(uri.slice(8)),c=>c.charCodeAt(0));
    const document=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    return 'vmess://' + base64(JSON.stringify({...document,ps:name}));
  }
  return uri.split('#')[0] + '#' + encodeURIComponent(name);
}

/** Labels are presentation only; identity, credentials and destinations stay intact. */
export function renameSubscriptionNodes(nodes) {
  const names=namesFor(nodes);
  return nodes.map((node,i)=>({ ...node,name:names[i],
    proxy:{...node.proxy,name:names[i]},outbound:{...node.outbound,tag:names[i]},
    uri:renameUri(node.uri,names[i]),
  }));
}
export function aliasesAreCurrent(nodesMetadata) {
  const names=namesFor(nodesMetadata);
  return nodesMetadata.every((node,i)=>node.name===names[i]);
}
