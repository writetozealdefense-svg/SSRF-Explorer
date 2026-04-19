// Security scanner: orchestrates OWASP API Top 10 probes via PowerShell.
//
// For each endpoint, we:
//   1. Fire a baseline probe (no mutation) to capture latency, status, body
//      — used both as a comparator and as signal source for API8.
//   2. Generate category-specific probes via owaspProbes.generateAll().
//   3. Execute each probe by spawning powershell.exe with ssrf_probe.ps1.
//   4. Classify via owaspProbes.classifyProbe(), tag with OWASP category.
//   5. For API4 (rate limiting), run the probe N times in a tight burst and
//      classify the aggregated statuses.
//
// The auth headers / cookies captured on the sampled request are forwarded on
// every probe, so probes run as the authenticated user by default.

const { spawn } = require('child_process');
const path = require('path');
const {
  generateAll,
  classifyProbe,
  classifyRateLimitBurst,
  ALL_CATEGORIES
} = require('./owaspProbes');

const PROBE_SCRIPT = path.join(__dirname, '..', 'scripts', 'ssrf_probe.ps1');

function resolvePwsh() {
  return process.env.PWSH_BIN || (process.platform === 'win32' ? 'powershell.exe' : 'pwsh');
}

function runProbe(payloadJson, timeoutMs) {
  return new Promise((resolve) => {
    const bin = resolvePwsh();
    const args = ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PROBE_SCRIPT];
    const t0 = Date.now();
    let proc;
    try {
      proc = spawn(bin, args, { windowsHide: true });
    } catch (e) {
      return resolve({ status: 0, elapsed_ms: 0, headers: {}, body_excerpt: '', redirect: '', error: `spawn: ${e.message}` });
    }
    let out = '';
    let err = '';
    const killer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, timeoutMs);
    proc.stdout.on('data', (d) => (out += d.toString()));
    proc.stderr.on('data', (d) => (err += d.toString()));
    proc.on('close', () => {
      clearTimeout(killer);
      const lines = out.trim().split(/\r?\n/).filter(Boolean);
      const last = [...lines].reverse().find((l) => l.startsWith('{') && l.endsWith('}'));
      if (!last) {
        return resolve({ status: 0, elapsed_ms: Date.now() - t0, headers: {}, body_excerpt: '', redirect: '', error: err || 'no json' });
      }
      try { resolve(JSON.parse(last)); }
      catch (e) { resolve({ status: 0, elapsed_ms: Date.now() - t0, headers: {}, body_excerpt: '', redirect: '', error: `parse: ${e.message}` }); }
    });
    proc.stdin.write(payloadJson);
    proc.stdin.end();
  });
}

function buildProbeInput(endpoint, probe, config) {
  return JSON.stringify({
    method: endpoint.method,
    url: endpoint.sampleUrl || endpoint.url,
    headers: endpoint.sampleHeaders || {},
    body: endpoint.sampleBody || '',
    param: probe.param,
    payload: probe.payload,
    timeout: config.timeoutSec || 10,
    proxy: config.proxy || ''
  });
}

async function runBaseline(endpoint, config) {
  const input = JSON.stringify({
    method: endpoint.method,
    url: endpoint.sampleUrl || endpoint.url,
    headers: endpoint.sampleHeaders || {},
    body: endpoint.sampleBody || '',
    param: { name: '_baseline', location: 'none' },
    payload: '<baseline>',
    timeout: config.timeoutSec || 10,
    proxy: config.proxy || ''
  });
  return runProbe(input, (config.timeoutSec || 10) * 1000 + 15000);
}

async function pool(tasks, limit, onProgress) {
  const results = new Array(tasks.length);
  let i = 0;
  let done = 0;
  async function worker() {
    while (i < tasks.length) {
      const idx = i++;
      try { results[idx] = await tasks[idx](); }
      catch (e) { results[idx] = { error: e.message }; }
      done++;
      onProgress && onProgress(done, tasks.length);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}

async function scan({ endpoints, config, categories, onProgress, onHit }) {
  const oobHost = (() => {
    if (!config.oobCanary) return '';
    try { return new URL(config.oobCanary).host; } catch { return ''; }
  })();
  const concurrency = Math.max(1, config.concurrency || 5);
  const baselines = new Map();

  // Build the full probe plan first so the client has an accurate total from
  // the very first tick. Baselines are counted as units, not hidden.
  const probePlan = [];
  for (const ep of endpoints) {
    const probes = generateAll(ep, { oobCanary: config.oobCanary }, categories);
    for (const probe of probes) probePlan.push({ ep, probe });
  }
  const totalUnits = endpoints.length + probePlan.length;
  let doneUnits = 0;
  const tick = () => {
    doneUnits++;
    if (onProgress) onProgress(doneUnits, totalUnits);
  };

  // Emit a "0 / totalUnits" frame immediately so the UI flips from "0/?" to a
  // real total before the first PowerShell spawn returns.
  if (onProgress) onProgress(0, totalUnits);

  // Phase 1: baselines, concurrently. One PowerShell spawn per endpoint.
  const baselineTasks = endpoints.map((ep) => async () => {
    const b = await runBaseline(ep, config);
    baselines.set(ep.url, {
      status: b.status,
      elapsed_ms: b.elapsed_ms,
      body: b.body_excerpt || '',
      headers: b.headers || {}
    });
    tick();
  });
  await pool(baselineTasks, concurrency, null);

  // Phase 2: execute probes.
  const probeTasks = probePlan.map(({ ep, probe }) => async () => {
    if (probe.category === 'API4_RateLimit') {
      const repeat = (probe.meta && probe.meta.repeat) || 30;
      const input = buildProbeInput(ep, probe, config);
      const statuses = [];
      const t0 = Date.now();
      for (let r = 0; r < repeat; r++) {
        const resp = await runProbe(input, (config.timeoutSec || 10) * 1000 + 15000);
        statuses.push(resp.status || 0);
        if (resp.status === 429) break;
      }
      const elapsedMs = Date.now() - t0;
      tick();
      const verdict = classifyRateLimitBurst({ statuses, elapsedMs });
      if (!verdict) return null;
      const finding = assembleFinding(ep, probe, {
        status: statuses.slice(-1)[0], elapsed_ms: elapsedMs, headers: {},
        body_excerpt: `statuses: ${statuses.join(',')}`
      }, verdict);
      if (onHit) onHit(finding);
      return finding;
    }
    const input = buildProbeInput(ep, probe, config);
    const resp = await runProbe(input, (config.timeoutSec || 10) * 1000 + 15000);
    const base = baselines.get(ep.url) || {};
    const verdict = classifyProbe(probe, resp, {
      baselineMs: base.elapsed_ms || null,
      baselineBody: base.body || '',
      baselineStatus: base.status || null,
      oobHost
    });
    tick();
    if (!verdict) return null;
    const finding = assembleFinding(ep, probe, resp, verdict);
    if (onHit) onHit(finding);
    return finding;
  });
  const raw = await pool(probeTasks, concurrency, null);
  const findings = raw.filter(Boolean);

  const rank = { Confirmed: 0, Likely: 1, Possible: 2 };
  findings.sort((a, b) =>
    (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) ||
    a.category.localeCompare(b.category) ||
    a.endpoint.localeCompare(b.endpoint)
  );
  return { totalProbes: probePlan.length, findings };
}

function assembleFinding(endpoint, probe, resp, verdict) {
  return {
    category: probe.category,
    severity: verdict.severity,
    signals: verdict.signals,
    endpoint: `${endpoint.method} ${endpoint.url}`,
    param: `${probe.param.name} [${probe.param.location}]`,
    payload: String(probe.payload),
    payloadCategory: (probe.meta && probe.meta.payloadCategory) || probe.category,
    description: probe.description,
    status: resp.status,
    elapsedMs: resp.elapsed_ms,
    redirect: resp.redirect || '',
    bodyExcerpt: (resp.body_excerpt || '').slice(0, 2048),
    error: resp.error || null
  };
}

module.exports = { scan, runProbe, ALL_CATEGORIES };
