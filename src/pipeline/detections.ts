import type { CorrelationResult, NormalizedEvent } from './types';

type Canonical = Record<string, unknown>;

export interface DetectionRule {
  id: string;
  name: string;
  /** Pseudo-SPL shown in the UI to make the Splunk framing concrete. */
  spl: string;
  scope: 'network' | 'correlated';
  /** Canonical fields the rule reads; used to explain silent breakage. */
  requiredFields: string[];
  matchNetwork?: (net: Canonical) => boolean;
  matchPair?: (net: Canonical, end: Canonical) => boolean;
}

export interface FiredAlert {
  summary: string;
}

export interface RuleResult {
  rule: DetectionRule;
  fired: FiredAlert[];
  /** Required canonical fields absent from every relevant event. */
  missingFields: string[];
  broken: boolean;
}

export const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'outbound-ssh',
    name: 'Outbound SSH to external host',
    spl: 'event.category=network network.transport=tcp dst.port=22',
    scope: 'network',
    requiredFields: ['dst.port', 'network.transport'],
    matchNetwork: (net) => net['network.transport'] === 'tcp' && net['dst.port'] === 22,
  },
  {
    id: 'external-smb',
    name: 'SMB traffic to external host',
    spl: 'event.category=network dst.port=445',
    scope: 'network',
    requiredFields: ['dst.port'],
    matchNetwork: (net) => net['dst.port'] === 445,
  },
  {
    id: 'http-nonstandard-port',
    name: 'HTTP on non-standard port',
    spl: 'network.protocol=http dst.port!=80',
    scope: 'network',
    requiredFields: ['network.protocol', 'dst.port'],
    matchNetwork: (net) => net['network.protocol'] === 'http' && net['dst.port'] !== 80,
  },
  {
    id: 'temp-process-netconn',
    name: 'Temp-directory process with network connection',
    spl: 'join on src.ip,dst.ip,dst.port | where process.executable LIKE "%\\\\Temp\\\\%"',
    scope: 'correlated',
    requiredFields: ['src.ip', 'dst.ip', 'dst.port', 'process.executable'],
    matchPair: (_net, end) =>
      typeof end['process.executable'] === 'string' &&
      /[\\/]temp[\\/]/i.test(end['process.executable']),
  },
  {
    id: 'ids-alert-attributed',
    name: 'High-severity IDS alert attributed to endpoint process',
    spl: 'event.severity>=2 | join on src.ip,dst.ip,dst.port',
    scope: 'correlated',
    requiredFields: ['src.ip', 'dst.ip', 'dst.port', 'event.severity'],
    matchPair: (net) => typeof net['event.severity'] === 'number' && net['event.severity'] >= 2,
  },
];

export function evaluateDetections(
  networkEvents: NormalizedEvent[],
  endpointEvents: NormalizedEvent[],
  correlation: CorrelationResult,
): RuleResult[] {
  return DETECTION_RULES.map((rule) => {
    const fired: FiredAlert[] = [];

    if (rule.scope === 'network' && rule.matchNetwork) {
      for (const event of networkEvents) {
        if (rule.matchNetwork(event.canonical)) {
          fired.push({ summary: networkSummary(event.canonical) });
        }
      }
    }

    if (rule.scope === 'correlated' && rule.matchPair) {
      for (const match of correlation.matches) {
        const net = networkEvents[match.networkIndex].canonical;
        const end = endpointEvents[match.endpointIndex].canonical;
        if (rule.matchPair(net, end)) {
          fired.push({ summary: pairSummary(net, end) });
        }
      }
    }

    const missingFields = rule.requiredFields.filter((field) => {
      const inNetwork = networkEvents.some((e) => e.canonical[field] !== undefined);
      if (rule.scope === 'network') return !inNetwork;
      const inEndpoint = endpointEvents.some((e) => e.canonical[field] !== undefined);
      return !inNetwork && !inEndpoint;
    });

    return { rule, fired, missingFields, broken: missingFields.length > 0 };
  });
}

export function totalAlerts(results: RuleResult[]): number {
  return results.reduce((sum, r) => sum + r.fired.length, 0);
}

function networkSummary(net: Canonical): string {
  const rule = net['rule.name'] ? ` [${net['rule.name']}]` : '';
  return `${net['src.ip'] ?? '?'} → ${net['dst.ip'] ?? '?'}:${net['dst.port'] ?? '?'}${rule}`;
}

function pairSummary(net: Canonical, end: Canonical): string {
  const proc = end['process.executable'] ?? 'unknown process';
  const host = end['host.name'] ?? '?';
  return `${net['src.ip'] ?? '?'} → ${net['dst.ip'] ?? '?'}:${net['dst.port'] ?? '?'} attributed to ${proc} on ${host}`;
}
