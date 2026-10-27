// Fixed, public feeds explicitly published for free subscription use.
// No user-supplied fetch URLs or traffic forwarding endpoints are supported.
export const SOURCES = Object.freeze([
  { id: 'nodesradar', name: 'Nodes Radar', homepage: 'https://github.com/nodesradar/nodesradar-en', url: 'https://radarhub.top/v2ray.txt' },
  { id: 'au1rxx', name: 'Au1rxx', homepage: 'https://github.com/Au1rxx/free-vpn-subscriptions', url: 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt' },
  { id: 'pawdroid', name: 'Pawdroid', homepage: 'https://github.com/Pawdroid/Free-servers', url: 'https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub' },
  { id: 'epodonios', name: 'Epodonios', homepage: 'https://github.com/Epodonios/v2ray-configs', url: 'https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt' },
  { id: 'mahdibland', name: 'Eternity', homepage: 'https://github.com/mahdibland/V2RayAggregator', url: 'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt' },
  { id: 'roosterkid', name: 'OpenProxyList', homepage: 'https://github.com/roosterkid/openproxylist', url: 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt' },
  { id: 'igareck', name: 'Igareck', homepage: 'https://github.com/igareck/vpn-configs-for-russia', url: 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt' },
]);

/** Interleave sources so one large feed cannot occupy every subscription slot. */
export function mergeFreeSources(results, limit = 120) {
  const nodes = [], seen = new Set();
  for (let i = 0; nodes.length < limit && results.some(r => i < r.nodes.length); i++) {
    for (const result of results) {
      const node = result.nodes[i];
      if (!node || seen.has(node.id)) continue;
      seen.add(node.id); nodes.push(node);
      if (nodes.length === limit) break;
    }
  }
  return nodes;
}
