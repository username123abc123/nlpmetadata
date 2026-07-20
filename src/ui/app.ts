import type {
  CanonicalSchema,
  MappingSuggestion,
  MappingTable,
  NormalizedEvent,
  SourceType,
} from '../pipeline/types';
import { ingest } from '../pipeline/ingest';
import { adaptEvents } from '../pipeline/adapters';
import { normalizeEvents } from '../pipeline/normalize';
import { correlate } from '../pipeline/correlate';
import { detectDrift } from '../pipeline/drift';
import { evaluateDetections, totalAlerts } from '../pipeline/detections';
import type { RuleResult } from '../pipeline/detections';
import type { Mapper } from '../nlp/mapper';
import { DEFAULT_CONFIDENCE_THRESHOLD, selectBestSuggestions } from '../nlp/mapper';
import { heuristicMapper } from '../nlp/heuristicMapper';
import { embeddingMapper, isModelReady } from '../nlp/embeddingMapper';
import schemaJson from '../schema/schema.json';
import suricataStable from '../data/suricata_stable.json';
import suricataDrifted from '../data/suricata_drifted.json';
import sysmonStable from '../data/sysmon_stable.json';
import sysmonDrifted from '../data/sysmon_drifted.json';

const schema = schemaJson as CanonicalSchema;

type Dataset = 'stable' | 'drifted';
type ModelStatus = 'loading' | 'ready' | 'failed';

interface AppState {
  dataset: Dataset;
  mapperChoice: 'embedding' | 'heuristic';
  threshold: number;
  modelStatus: ModelStatus;
  suggestions: MappingSuggestion[];
  appliedMappings: Partial<Record<SourceType, MappingTable>>;
  repairing: boolean;
  activeSource: SourceType;
}

const DATA: Record<SourceType, Record<Dataset, unknown>> = {
  suricata: { stable: suricataStable, drifted: suricataDrifted },
  sysmon: { stable: sysmonStable, drifted: sysmonDrifted },
};

const SOURCE_LABELS: Record<SourceType, string> = {
  suricata: 'Network — Suricata EVE',
  sysmon: 'Endpoint — Sysmon',
};

const state: AppState = {
  dataset: 'stable',
  mapperChoice: 'embedding',
  threshold: DEFAULT_CONFIDENCE_THRESHOLD,
  modelStatus: 'loading',
  suggestions: [],
  appliedMappings: {},
  repairing: false,
  activeSource: 'suricata',
};

let root: HTMLElement;

/** Signature of the last render; entry motion replays only when this changes. */
let lastAnimSig = '';

export function createApp(container: HTMLElement): void {
  root = container;
  render();
}

export function setModelStatus(status: ModelStatus): void {
  state.modelStatus = status;
  if (status === 'failed') state.mapperChoice = 'heuristic';
  render();
}

/** Escapes all dynamic content before insertion into HTML templates. */
function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Human-readable field value: strings render bare (no quotes/escapes), the rest as JSON. */
function fmtValue(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function runSource(sourceType: SourceType, withRepairs: boolean) {
  const raw = JSON.stringify(DATA[sourceType][state.dataset], null, 0);
  const adapted = adaptEvents(ingest(raw), sourceType);
  const normalized = normalizeEvents(adapted, {
    extraMappings: withRepairs ? state.appliedMappings : {},
  });
  return { adapted, normalized, drift: detectDrift(normalized, schema) };
}

function runAll() {
  const suricata = runSource('suricata', true);
  const sysmon = runSource('sysmon', true);
  const correlation = correlate(suricata.normalized, sysmon.normalized);
  const detections = evaluateDetections(suricata.normalized, sysmon.normalized, correlation);

  const baselineNet = runSource('suricata', false).normalized;
  const baselineEnd = runSource('sysmon', false).normalized;
  const baselineCorrelation = correlate(baselineNet, baselineEnd);
  const baselineDetections = evaluateDetections(baselineNet, baselineEnd, baselineCorrelation);

  return { suricata, sysmon, correlation, baselineCorrelation, detections, baselineDetections };
}

function activeMapper(): Mapper {
  if (state.mapperChoice === 'embedding' && isModelReady()) return embeddingMapper;
  return heuristicMapper;
}

async function repairMappings(): Promise<void> {
  state.repairing = true;
  render();
  try {
    const mapper = activeMapper();
    const allSuggestions: MappingSuggestion[] = [];
    const applied: Partial<Record<SourceType, MappingTable>> = {};

    for (const sourceType of ['suricata', 'sysmon'] as const) {
      const { normalized } = runSource(sourceType, false);
      const unmapped = new Map(
        normalized.flatMap((e) => e.unmappedObservedFields.map((f) => [f.name, f] as const)),
      );
      const alreadyFilled = new Set(normalized.flatMap((e) => Object.keys(e.canonical)));
      if (unmapped.size === 0) continue;

      const suggestions = await mapper.suggest({
        observedFields: [...unmapped.values()],
        sourceType,
        canonicalFields: schema.fields,
        alreadyFilled,
      });
      const best = selectBestSuggestions(suggestions, state.threshold);
      applied[sourceType] = Object.fromEntries(
        best.map((s) => [s.observedField, s.canonicalField]),
      );
      allSuggestions.push(...best);

      // Also keep the strongest below-threshold candidates for transparency.
      const appliedFields = new Set(best.map((s) => s.observedField));
      const rejected = selectBestSuggestions(suggestions, 0.25).filter(
        (s) => !appliedFields.has(s.observedField),
      );
      allSuggestions.push(...rejected);
    }

    state.suggestions = allSuggestions;
    state.appliedMappings = applied;
  } finally {
    state.repairing = false;
    render();
  }
}

function resetRepairs(): void {
  state.appliedMappings = {};
  state.suggestions = [];
  render();
}

function exportMappingPatch(): void {
  const patch = {
    generatedAt: new Date().toISOString(),
    mapper: activeMapper().name,
    threshold: state.threshold,
    mappings: state.appliedMappings,
  };
  const blob = new Blob([JSON.stringify(patch, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'mapping-patch.json';
  a.click();
  URL.revokeObjectURL(url);
}

function repairsAreActive(): boolean {
  return Object.values(state.appliedMappings).some((t) => t && Object.keys(t).length > 0);
}

function render(): void {
  const results = runAll();
  const repairsActive = repairsAreActive();

  const animSig = `${state.dataset}|${repairsActive}`;
  const animate = animSig !== lastAnimSig;
  lastAnimSig = animSig;

  root.innerHTML = `
    ${renderClassBanner()}
    ${renderMasthead()}
    <main class="layout ${animate ? 'anim' : ''}">
      ${renderDriftBanner(results, repairsActive)}
      ${renderKpis(results, repairsActive)}
      <div class="grid-two">
        <div class="col-main">
          ${renderDetections(results, repairsActive)}
          ${renderCorrelationDetail(results, repairsActive)}
        </div>
        <div class="col-side">
          ${renderRepairPanel(repairsActive)}
          ${renderSuggestions()}
        </div>
      </div>
      ${renderSourceInspector(results)}
    </main>
    <footer class="app-footer">
      ${renderClassBanner('bottom')}
    </footer>
  `;

  wireEvents();
}

function renderClassBanner(position = ''): string {
  return `<div class="class-banner ${position}" role="note" aria-label="Classification marking">UNCLASSIFIED</div>`;
}

function renderMasthead(): string {
  const statusLabel =
    state.modelStatus === 'ready'
      ? 'Model Online:)'
      : state.modelStatus === 'loading'
        ? 'Loading NLP model…'
        : 'Heuristic fallback active';

  return `
    <header class="masthead">
      <div>
        <p class="brand-name">sophie demo 😸</p>
        <h1 class="brand-title">NLP Solution for Metadata Issues 😼👍</h1>
      </div>
      <div class="masthead-side">
        <div class="env-toggle" role="group" aria-label="Data feed">
          <button class="toggle ${state.dataset === 'stable' ? 'active' : ''}" data-action="dataset-stable">Stable feed</button>
          <button class="toggle ${state.dataset === 'drifted' ? 'active' : ''}" data-action="dataset-drifted">Drifted feed</button>
        </div>
        <span class="status-pill ${state.modelStatus}" title="Sentence-embedding model runs fully client-side via WASM"><span class="dot"></span>${statusLabel}</span>
      </div>
    </header>
  `;
}

function renderDriftBanner(results: ReturnType<typeof runAll>, repairsActive: boolean): string {
  const brokenNow = results.detections.filter((r) => r.broken).length;
  const totalRules = results.detections.length;
  const unmappedCount =
    results.suricata.drift.unmappedFieldNames.length +
    results.sysmon.drift.unmappedFieldNames.length;

  if (brokenNow === 0 && unmappedCount === 0) {
    if (repairsActive) {
      return `
        <div class="alert-strip repaired" role="status">
          <span class="strip-icon">✓</span>
          <div>
            <b>Repairs applied — all ${totalRules} detection rules restored.</b>
          </div>
        </div>
      `;
    }
    return `
      <div class="alert-strip ok" role="status">
        <span class="strip-icon">✓</span>
        <div>
          <b>Pipeline healthy</b> — all ${totalRules} detection rules have their required canonical fields.
        </div>
      </div>
    `;
  }

  if (brokenNow > 0) {
    return `
      <div class="alert-strip critical" role="status">
        <span class="strip-icon">⚠</span>
        <div>
          <b>Schema drift — ${brokenNow} of ${totalRules} detection rules silently broken.</b>
          ${unmappedCount} unmapped source field${unmappedCount === 1 ? '' : 's'} :(
        </div>
      </div>
    `;
  }

  return `
    <div class="alert-strip ${repairsActive ? 'repaired' : 'warn'}" role="status">
      <span class="strip-icon">${repairsActive ? '✓' : '△'}</span>
      <div>
        ${repairsActive
      ? `<b>Repairs applied — detection coverage restored.</b>`
      : `<b>${unmappedCount} unmapped source field${unmappedCount === 1 ? '' : 's'}</b>`
    }
      </div>
    </div>
  `;
}

function renderKpis(results: ReturnType<typeof runAll>, repairsActive: boolean): string {
  const alertsNow = totalAlerts(results.detections);
  const alertsBefore = totalAlerts(results.baselineDetections);
  const pairsNow = results.correlation.matches.length;
  const pairsBefore = results.baselineCorrelation.matches.length;
  const brokenNow = results.detections.filter((r) => r.broken).length;
  const brokenBefore = results.baselineDetections.filter((r) => r.broken).length;
  const totalRules = results.detections.length;

  const coverage = (drift: { coverage: Record<string, number> }) => {
    const vals = Object.values(drift.coverage);
    return vals.length ? vals.filter((v) => v > 0).length / vals.length : 0;
  };
  const covNow = Math.round(
    ((coverage(results.suricata.drift) + coverage(results.sysmon.drift)) / 2) * 100,
  );

  const deltaChip = (now: number, before: number, unit: string) => {
    const d = now - before;
    if (d === 0) return `<span class="delta flat">— unchanged</span>`;
    const cls = d > 0 ? 'up' : 'down';
    const glyph = d > 0 ? '▲' : '▼';
    return `<span class="delta ${cls}">${glyph} ${d > 0 ? '+' : ''}${d} ${unit}</span>`;
  };

  const kpi = (
    key: string,
    label: string,
    now: string,
    tone: 'good' | 'bad' | 'warn' | 'neutral',
    opts: { before?: string; sub?: string; subAlerting?: boolean; delta?: string; meter?: string } = {},
  ) => {
    const showBefore = repairsActive && opts.before !== undefined;
    return `
    <div class="kpi ${tone}" data-kpi="${key}" data-now="${now}"${showBefore ? ` data-before="${opts.before}"` : ''}>
      <div class="kpi-label">${label}</div>
      <div class="kpi-value">${now}</div>
      ${showBefore && opts.delta ? opts.delta : ''}
      ${opts.sub ? `<div class="kpi-sub ${opts.subAlerting ? 'alerting' : ''}">${opts.sub}</div>` : ''}
      ${opts.meter ?? ''}
    </div>
  `;
  };

  const covTone = repairsActive ? 'good' : covNow >= 90 ? 'good' : covNow >= 60 ? 'warn' : 'bad';

  return `
    <section class="kpi-band" aria-label="Pipeline health metrics">
      ${kpi('alerts', 'Alerts firing', String(alertsNow), alertsNow > 0 ? 'good' : 'bad', {
    before: String(alertsBefore),
    delta: deltaChip(alertsNow, alertsBefore, 'after repair'),
  })}
      ${kpi(
    'rules',
    'Rules healthy',
    `${totalRules - brokenNow}/${totalRules}`,
    brokenNow === 0 ? 'good' : 'bad',
    {
      before: `${totalRules - brokenBefore}/${totalRules}`,
      delta: deltaChip(totalRules - brokenNow, totalRules - brokenBefore, 'restored'),
      sub: brokenNow > 0 ? `${brokenNow} silently broken` : undefined,
      subAlerting: brokenNow > 0,
    },
  )}
      ${kpi('pairs', 'Correlated pairs', String(pairsNow), pairsNow > 0 ? 'good' : 'bad', {
    before: String(pairsBefore),
    delta: deltaChip(pairsNow, pairsBefore, 'after repair'),
    sub: 'network ↔ endpoint',
  })}
      ${kpi('coverage', 'Field coverage', `${covNow}%`, covTone, {
    sub: 'canonical schema',
    meter: `<div class="meter" role="img" aria-label="Field coverage ${covNow} percent"><span class="meter-fill ${covTone}" style="width:${covNow}%"></span></div>`,
  })}
    </section>
  `;
}

function renderRepairPanel(repairsActive: boolean): string {
  const mapperReady = state.modelStatus === 'ready';
  return `
    <section class="card">
      <h2>Repair engine</h2>
      <div class="field-row">
        <label for="mapper-select">Engine</label>
        <select id="mapper-select">
          <option value="embedding" ${state.mapperChoice === 'embedding' ? 'selected' : ''} ${!mapperReady ? 'disabled' : ''}>Semantic embeddings (MiniLM)</option>
          <option value="heuristic" ${state.mapperChoice === 'heuristic' ? 'selected' : ''}>Heuristic rules</option>
        </select>
      </div>
      <div class="field-row">
        <label for="threshold-input">Confidence threshold</label>
        <input id="threshold-input" type="number" min="0" max="1" step="0.05" value="${state.threshold}" />
      </div>
      <div class="btn-row">
        <button class="primary" data-action="repair" ${state.repairing ? 'disabled' : ''}>
          ${state.repairing ? 'Repairing…' : 'Repair mappings'}
        </button>
        <button data-action="reset" ${repairsActive ? '' : 'disabled'}>Reset</button>
        <button data-action="export" ${repairsActive ? '' : 'disabled'} title="Download applied mappings as a JSON patch">Export patch</button>
      </div>
    </section>
  `;
}

function renderDetections(results: ReturnType<typeof runAll>, repairsActive: boolean): string {
  const baselineById = new Map(results.baselineDetections.map((r) => [r.rule.id, r]));

  const rows = results.detections
    .map((r) => {
      const baseline = baselineById.get(r.rule.id) as RuleResult;
      const status = r.broken
        ? `<span class="badge broken">Silently broken</span>`
        : r.fired.length > 0
          ? `<span class="badge firing">Firing</span>`
          : `<span class="badge skipped">No matches</span>`;

      const detail = r.broken
        ? `<div class="rule-note bad-note">Missing: ${r.missingFields.map(esc).join(', ')}</div>`
        : r.fired.length > 0
          ? `<div class="fired-list">${r.fired.map((f) => `<div>• ${esc(f.summary)}</div>`).join('')}</div>`
          : '';

      const count = repairsActive
        ? `<span class="${baseline.fired.length > 0 ? 'good-text' : 'bad-text'}">${baseline.fired.length}</span> <span class="muted">→</span> <span class="${r.fired.length > 0 ? 'good-text' : 'bad-text'}">${r.fired.length}</span>`
        : `<span class="${r.fired.length > 0 ? 'good-text' : 'bad-text'}">${r.fired.length}</span>`;

      return `<tr class="match-row">
        <td>
          <div class="rule-name">${esc(r.rule.name)}</div>
          <code class="spl">${esc(r.rule.spl)}</code>
          ${detail}
        </td>
        <td class="num">${count}</td>
        <td>${status}</td>
      </tr>`;
    })
    .join('');

  return `
    <section class="card">
      <h2>Detection rules</h2>
      <p class="card-desc">Saved searches — <b>canonical fields only</b>.</p>
      <table>
        <thead><tr><th>Rule</th><th class="num">Alerts${repairsActive ? ' (before → after)' : ''}</th><th>Status</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
  `;
}

function renderCorrelationDetail(
  results: ReturnType<typeof runAll>,
  repairsActive: boolean,
): string {
  const { correlation, baselineCorrelation, suricata, sysmon } = results;
  const rows = correlation.matches
    .map((m) => {
      const net = suricata.normalized[m.networkIndex].canonical;
      const end = sysmon.normalized[m.endpointIndex].canonical;
      return `<tr class="match-row">
        <td>${esc(net['rule.name'] ?? net['event.type'] ?? 'network event')}</td>
        <td><code class="mono">${esc(net['src.ip'])} → ${esc(net['dst.ip'])}:${esc(net['dst.port'])}</code></td>
        <td>${esc(end['host.name'] ?? '?')}</td>
        <td><code class="mono">${esc(end['process.executable'] ?? '?')}</code></td>
        <td class="muted">${esc(m.keys.join(', '))}</td>
      </tr>`;
    })
    .join('');

  const delta =
    repairsActive && correlation.matches.length !== baselineCorrelation.matches.length
      ? ` <span class="delta-note">(${baselineCorrelation.matches.length} before repair)</span>`
      : '';

  return `
    <section class="card">
      <h2>Cross-source correlation <span class="count-chip">${correlation.matches.length}${delta}</span></h2>
      <p class="card-desc">Network ↔ endpoint · <b>src.ip + dst.ip + dst.port</b> · ±60s window</p>
      ${correlation.matches.length === 0
      ? '<div class="empty-note">No correlated pairs — canonical join keys missing.</div>'
      : `<table>
              <thead><tr><th>Network event</th><th>Connection</th><th>Endpoint host</th><th>Process</th><th>Join keys</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>`
    }
    </section>
  `;
}

function renderSuggestions(): string {
  if (state.suggestions.length === 0) {
    return `
      <section class="card">
        <h2>Applied mappings</h2>
        <div class="empty-note">No repairs applied yet.</div>
      </section>
    `;
  }

  const appliedSet = new Set(
    Object.entries(state.appliedMappings).flatMap(([, t]) =>
      Object.entries(t ?? {}).map(([o, c]) => `${o}→${c}`),
    ),
  );

  const sorted = [...state.suggestions].sort((a, b) => b.confidence - a.confidence);
  const appliedRows = sorted.filter((s) =>
    appliedSet.has(`${s.observedField}→${s.canonicalField}`),
  );
  const rejectedRows = sorted.filter(
    (s) => !appliedSet.has(`${s.observedField}→${s.canonicalField}`),
  );

  const row = (s: MappingSuggestion, applied: boolean) => `
    <div class="mapping-row ${applied ? '' : 'rejected'}">
      <div class="mapping-fields">
        <code class="mono src-field">${esc(s.observedField)}</code>
        <span class="map-arrow">→</span>
        <code class="mono dst-field">${esc(s.canonicalField)}</code>
      </div>
      <div class="mapping-meta">
        <span class="conf-bar" title="confidence ${s.confidence.toFixed(2)}">
          <span class="conf-fill ${applied ? '' : 'low'}" style="width:${Math.round(s.confidence * 100)}%"></span>
        </span>
        <span class="conf-num">${s.confidence.toFixed(2)}</span>
        <span class="muted">${esc(s.sourceType)}</span>
      </div>
    </div>
  `;

  return `
    <section class="card">
      <h2>Applied mappings <span class="count-chip">${appliedRows.length}</span></h2>
      <p class="card-desc">Engine: <b>${esc(sorted[0]?.mapper ?? '')}</b> · threshold ≥ ${state.threshold}</p>
      ${appliedRows.map((s) => row(s, true)).join('')}
      ${rejectedRows.length > 0
      ? `<h3 class="subhead">Below threshold — not applied</h3>
             ${rejectedRows.map((s) => row(s, false)).join('')}`
      : ''
    }
    </section>
  `;
}

function renderSourceInspector(results: ReturnType<typeof runAll>): string {
  const tabs = (['suricata', 'sysmon'] as const)
    .map((s) => {
      const unmapped = results[s].drift.unmappedFieldNames.length;
      return `<button class="tab ${state.activeSource === s ? 'active' : ''}" data-source-tab="${s}">
        ${esc(SOURCE_LABELS[s])}
        ${unmapped > 0 ? `<span class="tab-badge">${unmapped} unmapped</span>` : ''}
      </button>`;
    })
    .join('');

  const result = results[state.activeSource];
  const table: MappingTable = state.appliedMappings[state.activeSource] ?? {};
  const repairedSources = new Set(Object.keys(table));
  const repairedTargets = new Set(Object.values(table));

  const rawPane = result.adapted
    .map((e) => `<pre>${esc(e.raw)}</pre>`)
    .join('<div class="pre-sep"></div>');

  const observedRows = result.adapted[0]
    ? result.adapted[0].observedFields
      .map((f) => {
        const repaired = repairedSources.has(f.name);
        const unmapped = result.drift.unmappedFieldNames.includes(f.name);
        const cls = repaired ? 'repaired-text' : unmapped ? 'bad-text' : '';
        const note = repaired
          ? ' title="repaired — re-mapped to canonical"'
          : unmapped
            ? ' title="unmapped — no canonical target"'
            : '';
        return `<tr><td><code class="mono ${cls}"${note}>${esc(f.name)}</code></td><td class="muted mono">${esc(fmtValue(f.value))}</td></tr>`;
      })
      .join('')
    : '';

  const normalizedRows = schema.fields
    .map((field) => {
      const coverage = result.drift.coverage[field.name];
      const sample = firstValue(result.normalized, field.name);
      if (coverage === 0) {
        return `<tr><td><code class="mono bad-text">${esc(field.name)}</code></td><td class="missing">— missing —</td></tr>`;
      }
      const repaired = repairedTargets.has(field.name);
      return `<tr>
        <td><code class="mono ${repaired ? 'repaired-text' : 'good-text'}"${repaired ? ' title="repaired by mapper"' : ''}>${esc(field.name)}</code></td>
        <td class="muted mono">${esc(fmtValue(sample))} <span class="cov">(${Math.round(coverage * 100)}%)</span></td>
      </tr>`;
    })
    .join('');

  return `
    <section class="card inspector">
      <h2>Source inspector</h2>
      <div class="tabs">${tabs}</div>
      <div class="panes">
        <div class="pane">
          <h3>Raw events</h3>
          ${rawPane}
        </div>
        <div class="pane">
          <h3>Observed fields <span class="pane-note">first event</span></h3>
          <table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${observedRows}</tbody></table>
        </div>
        <div class="pane">
          <h3>Canonical fields</h3>
          <table><thead><tr><th>Field</th><th>Sample · coverage</th></tr></thead><tbody>${normalizedRows}</tbody></table>
        </div>
      </div>
    </section>
  `;
}

function firstValue(events: NormalizedEvent[], field: string): unknown {
  for (const e of events) {
    if (e.canonical[field] !== undefined) return e.canonical[field];
  }
  return undefined;
}

function wireEvents(): void {
  root.querySelector('[data-action="dataset-stable"]')?.addEventListener('click', () => {
    state.dataset = 'stable';
    resetRepairs();
  });
  root.querySelector('[data-action="dataset-drifted"]')?.addEventListener('click', () => {
    state.dataset = 'drifted';
    resetRepairs();
  });
  root.querySelector('[data-action="repair"]')?.addEventListener('click', () => {
    void repairMappings();
  });
  root.querySelector('[data-action="reset"]')?.addEventListener('click', resetRepairs);
  root.querySelector('[data-action="export"]')?.addEventListener('click', exportMappingPatch);
  root.querySelectorAll<HTMLButtonElement>('[data-source-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.activeSource = btn.dataset.sourceTab as SourceType;
      render();
    });
  });
  root.querySelector<HTMLSelectElement>('#mapper-select')?.addEventListener('change', (e) => {
    state.mapperChoice = (e.target as HTMLSelectElement).value as 'embedding' | 'heuristic';
    render();
  });
  root.querySelector<HTMLInputElement>('#threshold-input')?.addEventListener('change', (e) => {
    const v = Number((e.target as HTMLInputElement).value);
    if (!Number.isNaN(v) && v >= 0 && v <= 1) state.threshold = v;
    render();
  });
}
