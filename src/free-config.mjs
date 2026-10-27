export const GROUP_NAME = '免费节点';
export const AUTO_NAME = '自动选择';
export const TEST_URL = 'https://1.1.1.1/cdn-cgi/trace';

function yaml(value, level = 0) {
  const pad = ' '.repeat(level);
  const scalar = v => typeof v === 'string' ? JSON.stringify(v).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029') : JSON.stringify(v);
  if (Array.isArray(value)) return value.length ? value.map(v => v && typeof v === 'object' ? `${pad}-\n${yaml(v, level + 2)}` : `${pad}- ${scalar(v)}`).join('\n') : `${pad}[]`;
  return Object.entries(value).map(([k, v]) => `${pad}${scalar(k)}:${v && typeof v === 'object' ? Array.isArray(v) && !v.length ? ' []' : `\n${yaml(v, level + 2)}` : ` ${scalar(v)}`}`).join('\n');
}

export function buildFreeMihomo(nodes, { providerOnly = false } = {}) {
  if (!Array.isArray(nodes) || !nodes.length) throw new Error('Cannot render an empty subscription');
  const names = nodes.map(n => n.proxy?.name);
  if (new Set(names).size !== names.length || names.some(n => !n || ['DIRECT', 'REJECT', GROUP_NAME, AUTO_NAME].includes(n))) throw new Error('Invalid or duplicate proxy names');
  const proxies = nodes.map(n => n.proxy);
  if (providerOnly) return { proxies };
  return {
    'mixed-port': 7890, 'allow-lan': false, mode: 'rule', 'log-level': 'info', ipv6: false,
    dns: {
      enable: true, listen: '127.0.0.1:1053', ipv6: false,
      'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
      'default-nameserver': ['223.5.5.5', '119.29.29.29'],
      'proxy-server-nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
      nameserver: [`https://1.1.1.1/dns-query#${AUTO_NAME}`, `https://8.8.8.8/dns-query#${AUTO_NAME}`],
    },
    proxies,
    'proxy-groups': [
      { name: GROUP_NAME, type: 'select', proxies: [AUTO_NAME, ...names] },
      { name: AUTO_NAME, type: 'url-test', proxies: names, url: TEST_URL, interval: 300, timeout: 15000, tolerance: 150, lazy: false },
    ],
    rules: [`MATCH,${GROUP_NAME}`],
  };
}

export function renderFreeMihomo(nodes, options) {
  return '# Public free proxies. Independent HTTPS checks filter publication; clients also test locally. This server does not relay traffic.\n' + yaml(buildFreeMihomo(nodes, options)) + '\n';
}
