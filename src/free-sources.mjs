// Fixed public publishers; daily pages are resolved only by their own adapter.
// No user-supplied fetch URLs or traffic forwarding endpoints are supported.
export const MAX_CANDIDATES = 1000;
export const SOURCES = Object.freeze([
  { id: 'nodesradar', name: 'Nodes Radar', homepage: 'https://github.com/nodesradar/nodesradar-en', url: 'https://radarhub.top/v2ray.txt' },
  { id: 'au1rxx', name: 'Au1rxx', homepage: 'https://github.com/Au1rxx/free-vpn-subscriptions', url: 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt' },
  { id: 'pawdroid', name: 'Pawdroid', homepage: 'https://github.com/Pawdroid/Free-servers', url: 'https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub' },
  { id: 'epodonios', name: 'Epodonios', homepage: 'https://github.com/Epodonios/v2ray-configs', url: 'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt' },
  { id: 'mahdibland', name: 'Eternity', homepage: 'https://github.com/mahdibland/V2RayAggregator', url: 'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt' },
  { id: 'roosterkid', name: 'OpenProxyList', homepage: 'https://github.com/roosterkid/openproxylist', url: 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt' },
  { id: 'igareck', name: 'Igareck', homepage: 'https://github.com/igareck/vpn-configs-for-russia', url: 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt' },
  { id: 'mibei', name: '米贝分享', kind: 'mibei', homepage: 'https://www.mibei77.com/category/jiedian', url: 'https://www.mibei77.com/category/jiedian' },
  { id: 'hiddifynext', name: 'HiddifyNext', kind: 'hiddifynext', homepage: 'https://hiddify-next-node.github.io/', url: 'https://hiddify-next-node.github.io/' },
  { id: 'freeclashnode', name: 'FreeClashNode', kind: 'freeclashnode', homepage: 'https://www.freeclashnode.com/free-node/', url: 'https://www.freeclashnode.com/free-node/' },
  { id: 'endgfw', name: '大翻墙运动', kind: 'endgfw', homepage: 'https://end-gfw.com/#free', url: 'https://end-gfw.com/' },
  { id: 'v2raydog', name: 'V2rayDog', kind: 'v2raydog', homepage: 'https://v2raydog.com/', url: 'https://v2raydog.com/' },
  { id: 'cfmem', name: '长风分享', kind: 'cfmem', homepage: 'https://www.cfmem.com/search/label/free', url: 'https://www.cfmem.com/search/label/%E5%85%8D%E8%B4%B9%E8%8A%82%E7%82%B9' },
  { id: 'freev2', name: 'FreeV2', kind: 'freev2', homepage: 'https://b.freev2.net/', url: 'https://b.freev2.net/' },
]);

/** Interleave sources so one large feed cannot occupy every subscription slot. */
export function mergeFreeSources(results, limit = MAX_CANDIDATES) {
  const nodes = [], seen = new Set();
  for (let i = 0; nodes.length < limit && results.some(r => i < r.nodes.length); i++) {
    for (const result of results) {
      const node = result.nodes[i];
      if (!node || seen.has(node.id)) continue;
      // These nodes reset TLS connections in local client checks; keep the
      // pause scoped to this source/protocol pair until it is revalidated.
      if (node.sourceId === 'igareck' && node.protocol === 'trojan') continue;
      seen.add(node.id); nodes.push(node);
      if (nodes.length === limit) break;
    }
  }
  return nodes;
}
