import { parseFreeSubscription, renderFreeKaring, renderUriSubscription } from './free-converter.mjs';
import { renderFreeMihomo } from './free-config.mjs';
import { MAX_CANDIDATES } from './free-sources.mjs';
import { isBlockedNode } from './block-policy.mjs';

export const HEALTH_TTL_MS = 2 * 60 * 60 * 1000;
export const MAX_REPORT_AGE_MS = 30 * 60 * 1000;
export const CHECK_TARGETS = Object.freeze(['https://1.1.1.1/cdn-cgi/trace', 'https://www.google.com/generate_204']);
const CHECKERS = new Set(['github-actions', 'local-windows']);
const CLOCK_SKEW_MS = 60 * 1000;

export class HealthReportError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
function reject(message, status = 400) { throw new HealthReportError(message, status); }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function timestamp(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) ? Date.parse(value) : NaN;
}
function exactTargets(value) {
  return Array.isArray(value) && value.length === CHECK_TARGETS.length && new Set(value).size === value.length && value.every(url => CHECK_TARGETS.includes(url));
}
export function candidateSummary(candidate) {
  if (!candidate) return null;
  return {
    generationId: candidate.generationId, createdAt: candidate.createdAt,
    candidateCount: candidate.nodes.length, sourceCount: candidate.sourceCount,
    skipped: candidate.skipped, sourceStatus: candidate.sourceStatus,
    warnings: candidate.warnings, trafficRelay: false, publication: 'awaiting-health-check',
  };
}

/** Validate a complete trusted check report against its immutable source batch. */
export function validateCheckReport(report, candidate, previous, now = Date.now()) {
  if (!record(report)) reject('Invalid health report');
  const allowed = new Set(['generationId','startedAt','finishedAt','results','checker','testTargets']);
  if (Object.keys(report).some(key => !allowed.has(key))) reject('Unsupported health report field');
  if (typeof report.generationId !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(report.generationId)) reject('Invalid candidate generation');
  if (!candidate || candidate.generationId !== report.generationId) reject('Candidate generation unavailable or expired', 409);
  if (!CHECKERS.has(report.checker)) reject('Unsupported health checker');
  if (!exactTargets(report.testTargets)) reject('Unexpected health test targets');
  const started = timestamp(report.startedAt), finished = timestamp(report.finishedAt), created = timestamp(candidate.createdAt);
  if (![started,finished,created].every(Number.isFinite) || started > finished) reject('Invalid health check timestamps');
  if (started < now - MAX_REPORT_AGE_MS || finished < now - MAX_REPORT_AGE_MS || started > now + CLOCK_SKEW_MS || finished > now + CLOCK_SKEW_MS) reject('Health report is stale or in the future');
  if (started < created - CLOCK_SKEW_MS) reject('Health check predates its candidate generation');
  const priorHealth = previous?.health ?? previous?.status?.health;
  if (Number.isFinite(timestamp(priorHealth?.checkedAt)) && finished <= timestamp(priorHealth.checkedAt)) reject('A newer health report has already been published', 409);
  if (Number.isFinite(timestamp(priorHealth?.candidateCreatedAt)) && created < timestamp(priorHealth.candidateCreatedAt)) reject('A newer candidate generation has already been published', 409);
  if (!Array.isArray(candidate.nodes) || !candidate.nodes.length || candidate.nodes.length > MAX_CANDIDATES) reject('Invalid candidate generation', 409);
  if (!Array.isArray(report.results) || report.results.length !== candidate.nodes.length) reject('Health report must cover every candidate exactly once');
  const expected = new Set(candidate.nodes.map(n => n.id)), received = new Set(), passed = new Map();
  const blocked = new Set(candidate.nodes.filter(isBlockedNode).map(n => n.id));
  if (expected.size !== candidate.nodes.length) reject('Duplicate candidate identity', 409);
  for (const result of report.results) {
    if (!record(result) || Object.keys(result).some(key => !['id','passed','latencyMs'].includes(key)) || typeof result.id !== 'string' || !expected.has(result.id) || received.has(result.id) || typeof result.passed !== 'boolean') reject('Invalid, unknown or duplicate candidate result');
    received.add(result.id);
    if (result.passed) {
      if (typeof result.latencyMs !== 'number' || !Number.isFinite(result.latencyMs) || result.latencyMs < 0 || result.latencyMs > 60000) reject('Invalid successful check latency');
      if (!blocked.has(result.id)) passed.set(result.id, result.latencyMs);
    } else if (result.latencyMs !== undefined && result.latencyMs !== null && (typeof result.latencyMs !== 'number' || !Number.isFinite(result.latencyMs) || result.latencyMs < 0 || result.latencyMs > 60000)) reject('Invalid failed check latency');
  }
  const health = {
    enabled: true, generationId: candidate.generationId, candidateCreatedAt: candidate.createdAt,
    startedAt: new Date(started).toISOString(), checkedAt: new Date(finished).toISOString(),
    expiresAt: new Date(finished + HEALTH_TTL_MS).toISOString(),
    checkedCount: candidate.nodes.length, passedCount: passed.size, failedCount: candidate.nodes.length - passed.size,
    checker: report.checker, targets: [...CHECK_TARGETS],
    ...(blocked.size ? { policyBlockedCount: blocked.size } : {}),
  };
  return { health, nodes: candidate.nodes.filter(n => passed.has(n.id)).map(n => ({ ...n, latencyMs: passed.get(n.id) })) };
}

/** No failed candidate or arbitrary checker-supplied configuration is rendered. */
export function makeHealthySnapshot(report, candidate, previous, now = Date.now()) {
  const { health, nodes } = validateCheckReport(report, candidate, previous, now);
  const countries = {}, protocols = {};
  for (const n of nodes) { countries[n.country] = (countries[n.country] || 0) + 1; protocols[n.protocol] = (protocols[n.protocol] || 0) + 1; }
  const status = {
    service: 'Free Node Subscription', updatedAt: health.checkedAt,
    sources: candidate.sourceStatus, sourceCount: candidate.sourceCount,
    nodeCount: nodes.length, skipped: candidate.skipped, countries, protocols,
    warnings: candidate.warnings, protocol: Object.keys(protocols).join(', '),
    target: 'Mihomo / Karing / v2rayN', refreshMinutes: 30,
    clientConnectivityTested: true, karingNodeCount: nodes.length, karingSkipped: 0,
    karingWarnings: [], trafficRelay: false, health,
  };
  return renderSnapshot(nodes, status);
}

function renderSnapshot(nodes, status) {
  const health = status.health;
  return {
    health, status,
    mihomo: nodes.length ? renderFreeMihomo(nodes) : null,
    provider: nodes.length ? renderFreeMihomo(nodes, { providerOnly: true }) : null,
    karing: nodes.length ? renderFreeKaring(nodes) : null,
    uris: nodes.length ? renderUriSubscription(nodes) : null,
    nodes: { updatedAt: health.checkedAt, nodes: nodes.map(({ id,name,country,countryLong,ip,protocol,sourceId,latencyMs }) => ({ id,name,country,countryLong,ip,protocol,sourceId,latencyMs })) },
    profiles: [],
  };
}

/** Apply a new denylist to already checked cached nodes without claiming a new test. */
export function applySnapshotBlockPolicy(current) {
  if (!current?.health || !Array.isArray(current.nodes?.nodes) || !current.karing || !current.uris) return current;
  const metadata = current.nodes.nodes;
  const tags = new Map(metadata.map(n => [n.name, n]));
  let outbounds;
  try { outbounds = JSON.parse(current.karing).outbounds; } catch { return null; }
  if (!Array.isArray(outbounds)) return null;
  if (!outbounds.some(n => isBlockedNode({ ...tags.get(n.tag), outbound:n }))) return current;
  let nodes, lines;
  try {
    nodes = parseFreeSubscription(current.uris, { limit:MAX_CANDIDATES }).nodes;
    const bytes=Uint8Array.from(atob(current.uris.trim()), c=>c.charCodeAt(0));
    lines=new TextDecoder('utf-8',{fatal:true}).decode(bytes).trim().split(/\r?\n/);
  } catch { return null; }
  // Published formats originate from one atomic snapshot; mismatches fail closed.
  if (nodes.length !== metadata.length || lines.length !== nodes.length || nodes.some((n,i)=>n.id !== metadata[i].id)) return null;
  const allowed = nodes.map((n,i)=>({ ...n, ...metadata[i],
    proxy:{ ...n.proxy,name:metadata[i].name }, outbound:{ ...n.outbound,tag:metadata[i].name }, uri:lines[i],
  })).filter(n=>!isBlockedNode(n));
  const removed = nodes.length - allowed.length;
  if (!removed) return current;
  const health = { ...current.health, passedCount:allowed.length, failedCount:current.health.checkedCount-allowed.length,
    policyBlockedCount:(current.health.policyBlockedCount||0)+removed };
  const countries={}, protocols={};
  for(const n of allowed){ countries[n.country]=(countries[n.country]||0)+1;protocols[n.protocol]=(protocols[n.protocol]||0)+1; }
  const status={ ...current.status,health,nodeCount:allowed.length,karingNodeCount:allowed.length,countries,protocols,protocol:Object.keys(protocols).join(', ') };
  return renderSnapshot(allowed,status);
}

/** Evaluate freshness at request time, including old snapshots without health. */
export function healthView(current, now = Date.now()) {
  const health = current?.health ?? current?.status?.health;
  const checked = timestamp(health?.checkedAt), expires = timestamp(health?.expiresAt);
  const counts = [health?.checkedCount,health?.passedCount,health?.failedCount];
  const valid = health?.enabled === true && CHECKERS.has(health.checker) && exactTargets(health.targets)
    && Number.isFinite(checked) && Number.isFinite(expires) && expires === checked + HEALTH_TTL_MS && checked <= now + CLOCK_SKEW_MS
    && counts.every(n => Number.isInteger(n) && n >= 0) && health.checkedCount > 0 && health.checkedCount === health.passedCount + health.failedCount
    && current?.nodes?.nodes?.length === health.passedCount;
  if (!valid) return { enabled: true, checkedAt: null, expiresAt: null, checkedCount: 0, passedCount: 0, failedCount: 0, checker: null, targets: [...CHECK_TARGETS], available: false, stale: false, state: 'pending' };
  const stale = expires <= now;
  return { ...health, available: !stale && health.passedCount > 0, stale, state: stale ? 'expired' : health.passedCount ? 'healthy' : 'empty' };
}

export function publicStatus(current, candidate, now = Date.now()) {
  const health = healthView(current, now);
  return {
    ...(current?.status ?? { service: 'Free Node Subscription', updatedAt: null, sources: candidate?.sourceStatus ?? [], sourceCount: candidate?.sourceCount ?? 0, countries: {}, protocols: {}, refreshMinutes: 30, trafficRelay: false }),
    nodeCount: health.available ? health.passedCount : 0,
    karingNodeCount: health.available ? health.passedCount : 0,
    clientConnectivityTested: health.state !== 'pending', health,
    candidateStatus: candidateSummary(candidate), available: health.available,
  };
}
