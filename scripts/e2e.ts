import { chromium } from 'playwright';
import type { Page } from 'playwright';

const BASE = process.env.E2E_URL ?? 'http://localhost:4173/nlpmetadata/';
const results: { name: string; ok: boolean; detail?: string }[] = [];
const check = (name: string, ok: boolean, detail?: string) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

/** Reads a KPI's numbers from data attributes: [now] before repair, [before, now] once repaired. */
async function stat(page: Page, key: string): Promise<number[]> {
  const el = page.locator(`[data-kpi="${key}"]`);
  const now = Number(await el.getAttribute('data-now'));
  const before = await el.getAttribute('data-before');
  return before === null ? [now] : [Number(before), now];
}

async function clickRepairAndWait(page: Page, timeout: number): Promise<void> {
  await page.click('[data-action="repair"]');
  await page.waitForFunction(
    () => document.querySelector('[data-kpi="alerts"]')?.hasAttribute('data-before') ?? false,
    { timeout },
  );
}

const browser = await chromium.launch();
const page = await browser.newPage();

const consoleErrors: string[] = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') consoleErrors.push(msg.text());
});
const externalRequests: string[] = [];
page.on('request', (req) => {
  const url = new URL(req.url());
  if (url.origin !== new URL(BASE).origin) externalRequests.push(req.url());
});

await page.goto(BASE, { waitUntil: 'load' });
check(
  'page loads',
  (await page.locator('.brand-name').textContent())?.includes('NLP Solution for Metadata Issues') ??
    false,
);

// Model health indicator must reach "ready" (loaded from same-origin /models).
await page.waitForSelector('.status-pill.ready', { timeout: 60_000 });
check('model loads locally', true);

// Stable dataset: alerts fire and correlation is present.
const [stableAlerts] = await stat(page, 'alerts');
const [stableMatches] = await stat(page, 'pairs');
check('stable logs fire alerts', stableAlerts === 7, `${stableAlerts} alerts`);
check('stable logs correlate', stableMatches >= 4, `${stableMatches} matches`);
const firingBadges = await page.locator('.badge.firing').count();
check('detection rules show FIRING', firingBadges === 5, `${firingBadges} rules firing`);

// Switch to drifted: alerts silently stop, correlation drops to zero.
await page.click('[data-action="dataset-drifted"]');
const [driftedAlerts] = await stat(page, 'alerts');
const [driftedMatches] = await stat(page, 'pairs');
check('drift silences all alerts', driftedAlerts === 0, `${driftedAlerts} alerts`);
check('drift breaks correlation', driftedMatches === 0, `${driftedMatches} matches`);
const brokenBadges = await page.locator('.badge.broken').count();
check('rules marked SILENTLY BROKEN', brokenBadges === 5, `${brokenBadges} broken rules`);
const missingCount = await page.locator('td.missing').count();
check('drift causes missing canonical fields', missingCount > 0, `${missingCount} missing cells`);

// Repair with the embedding mapper.
await clickRepairAndWait(page, 120_000);
const [alertsBefore, alertsAfter] = await stat(page, 'alerts');
const [, matchesAfter] = await stat(page, 'pairs');
check(
  'repair restores all alerts',
  alertsBefore === 0 && alertsAfter === 7,
  `${alertsBefore} → ${alertsAfter} alerts`,
);
check('repair restores correlation', matchesAfter >= 4, `${matchesAfter} matches after repair`);
const brokenAfter = await page.locator('.badge.broken').count();
check('no rules remain broken after repair', brokenAfter === 0, `${brokenAfter} broken`);

const suggestionRows = await page.locator('.mapping-row:not(.rejected)').count();
check('applied suggestions shown', suggestionRows >= 6, `${suggestionRows} applied`);

const embeddingUsed = await page.locator('.card-desc', { hasText: 'embedding' }).count();
check('embedding mapper used', embeddingUsed > 0, `${embeddingUsed} rows`);

// NIPR constraint: nothing may load from outside the site origin.
check(
  'no external network requests',
  externalRequests.length === 0,
  externalRequests.slice(0, 3).join(', ') || 'none',
);
check(
  'no console errors',
  consoleErrors.length === 0,
  consoleErrors.slice(0, 3).join(' | ') || 'none',
);

await browser.close();

// Scenario 2: model files unavailable -> heuristic fallback still repairs.
const browser2 = await chromium.launch();
const page2 = await browser2.newPage();
await page2.route('**/models/**', (route) => route.abort());
await page2.goto(BASE, { waitUntil: 'load' });
await page2.waitForSelector('.status-pill.failed', { timeout: 60_000 });
check('model failure detected, fallback indicator shown', true);
await page2.click('[data-action="dataset-drifted"]');
await clickRepairAndWait(page2, 30_000);
const [, fallbackMatches] = await stat(page2, 'pairs');
const [, fallbackAlerts] = await stat(page2, 'alerts');
check('heuristic fallback restores correlation', fallbackMatches >= 4, `${fallbackMatches} matches`);
check(
  'heuristic fallback restores most alerts',
  fallbackAlerts >= 5,
  `${fallbackAlerts} alerts (embedding restores all 7)`,
);
const heuristicRows = await page2.locator('.card-desc', { hasText: 'heuristic' }).count();
check('heuristic mapper used in fallback', heuristicRows > 0, `${heuristicRows} rows`);
await browser2.close();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} browser checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
