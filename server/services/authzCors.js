// Focused quick-check: Authorization + CORS.
//
// Runs automatically after enumeration. For every endpoint that carries an
// auth marker (Authorization / Cookie / X-API-Key / X-Auth-Token) or has CORS
// interest, fires a small set of probes and attaches a concrete PoC to each
// positive finding so the operator can reproduce by hand.

const path = require('path');
const { spawn } = require('child_process');

const {
  pocAuthBypass,
  pocInvalidToken,
  pocCorsReflected,
  pocCorsNull,
  pocCorsWildcardCreds
} = require('./pocGenerator');

const PROBE_SCRIPT = path.join(__dirname, '..', 'scripts', 'ssrf_probe.ps1');
const ATTACKER_ORIGIN = 'https://attacker.example.com';

function resolvePwsh() {
  return process.env.PWSH_BIN || (process.platform === 'win32' ? 'powershell.exe' : 'pwsh');
}

function runProbe(payloadJson, timeoutMs) {
  return new Promise((resolve) => {
    const bin = resolvePwsh();
    const args = ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PROBE_SCRIPT];
    const t0 = Date.now();
    let proc;
    try { proc = spawn(bin, args, { windowsHide: true }); }
    catch (e) {
      return resolve({ status: 0, elapsed_ms: 0, headers: {}, body_excerpt: '', error: `spawn: ${e.message}` });
    }
    let out = '', err = '';
    const killer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, timeoutMs);
    proc.stdout.on('data', (d) => (out += d.toString()));
    proc.stderr.on('data', (d) => (err += d.toString()));
    proc.on('close', () => {
      clearTimeout(killer);
      const last = out.trim().split(/\r?\n/).reverse().find((l) => l.startsWith('{') && l.endsWith('}'));
      if (!last) return resolve({ status: 0, elapsed_ms: Date.now() - t0, headers: {}, body_excerpt: '', error: err || 'no json' });
      try { resolve(JSON.parse(last)); }
      catch (e) { resolve({ status: 0, elapsed_ms: Date.now() - t0, headers: {}, body_excerpt: '', error: `parse: ${e.message}` }); }
    });
    proc.stdin.write(payloadJson);
    proc.stdin.end();
  });
}

function hasAuthMarker(headers) {
  const authRe = /^(authorization|cookie|x-api-key|x-auth-token|x-csrf-token)$/i;
  return Object.keys(headers || {}).some((k) => authRe.test(k));
}

function lowerKeys(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) out[k.toLowerCase()] = v;
  return out;
}

function pool(tasks, limit, onProgress) {
  return new Promise((resolve) => {
    const results = new Array(tasks.length);
    let i = 0, done = 0;
    async function worker() {
      while (i < tasks.length) {
        const idx = i++;
        try { results[idx] = await tasks[idx](); }
        catch (e) { results[idx] = { error: e.message }; }
        done++;
        onProgress && onProgress(done, tasks.length);
      }
    }
    const workers = Array.from({ length: Math.min(limit, tasks.length || 1) }, worker);
    Promise.all(workers).then(() => resolve(results));
  });
}

// ---- Probe builders --------------------------------------------------------

function baselineInput(ep, proxy, timeout) {
  return JSON.stringify({
    method: ep.method,
    url: ep.sampleUrl || ep.url,
    headers: ep.sampleHeaders || {},
    body: ep.sampleBody || '',
    param: { name: '_baseline', location: 'none' },
    payload: '<baseline>',
    timeout,
    proxy
  });
}

function stripAuthInput(ep, proxy, timeout) {
  return JSON.stringify({
    method: ep.method,
    url: ep.sampleUrl || ep.url,
    headers: ep.sampleHeaders || {},
    body: ep.sampleBody || '',
    param: { name: 'Authorization,Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token', location: 'header-remove' },
    payload: '<stripped>',
    timeout,
    proxy
  });
}

function invalidTokenInput(ep, proxy, timeout) {
  return JSON.stringify({
    method: ep.method,
    url: ep.sampleUrl || ep.url,
    headers: ep.sampleHeaders || {},
    body: ep.sampleBody || '',
    param: { name: 'Authorization', location: 'header' },
    payload: 'Bearer invalid-token-for-poc-only',
    timeout,
    proxy
  });
}

function corsInput(ep, proxy, timeout, origin) {
  return JSON.stringify({
    method: ep.method,
    url: ep.sampleUrl || ep.url,
    headers: ep.sampleHeaders || {},
    body: ep.sampleBody || '',
    param: { name: 'Origin', location: 'header' },
    payload: origin,
    timeout,
    proxy
  });
}

// ---- Classifiers -----------------------------------------------------------

function classifyAuthStrip(baseline, stripped) {
  const signals = [];
  if (!stripped.status) return null;
  if (stripped.status >= 200 && stripped.status < 300) {
    const body = stripped.body_excerpt || '';
    if (body.length > 20) {
      if (body === (baseline.body_excerpt || '')) {
        signals.push('identical-body-after-strip');
        return { severity: 'Confirmed', signals };
      }
      signals.push('2xx-after-strip');
      return { severity: 'Likely', signals };
    }
  }
  return null;
}

function classifyInvalidToken(baseline, withBad) {
  if (!withBad.status) return null;
  if (withBad.status >= 200 && withBad.status < 300) {
    const body = withBad.body_excerpt || '';
    if (body.length > 20) {
      return { severity: 'Confirmed', signals: ['2xx-with-invalid-token'] };
    }
  }
  return null;
}

function classifyCors({ origin, resp, sensitiveBaseline, scenario }) {
  const h = lowerKeys(resp.headers || {});
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  if (!acao) return null;

  const reflected = acao === origin;
  const wildcard = acao === '*';
  const isNull = acao === 'null';
  const credsTrue = acac && String(acac).toLowerCase() === 'true';

  // Severity anchored on whether the endpoint likely returns sensitive data.
  // A 2xx baseline with a meaningful body + credentialed CORS leak = critical;
  // no auth context ever present = much lower impact.
  const sensitive = sensitiveBaseline && resp.status >= 200 && resp.status < 300;

  if (reflected && credsTrue) {
    return {
      severity: sensitive ? 'Confirmed' : 'Likely',
      signals: [`reflected-origin:${origin}`, 'credentials-true'],
      scenario
    };
  }
  if (isNull && credsTrue) {
    return {
      severity: sensitive ? 'Confirmed' : 'Likely',
      signals: ['null-origin-accepted', 'credentials-true'],
      scenario
    };
  }
  if (wildcard && credsTrue) {
    return {
      severity: 'Likely',
      signals: ['wildcard-origin', 'credentials-true'],
      scenario
    };
  }
  if (reflected && !credsTrue) {
    return {
      severity: 'Possible',
      signals: [`reflected-origin:${origin}`, 'no-credentials'],
      scenario
    };
  }
  return null;
}

// ---- Orchestrator ----------------------------------------------------------

async function runQuickCheck({ endpoints, config, onProgress, onHit }) {
  const proxy = config.proxy || '';
  const timeout = config.timeoutSec || 10;
  const timeoutMs = timeout * 1000 + 15000;
  const concurrency = Math.max(1, config.concurrency || 5);

  const jobs = [];

  for (const ep of endpoints) {
    const needsAuth = hasAuthMarker(ep.sampleHeaders || {});

    // One baseline per endpoint, reused for all checks on that endpoint.
    let baselineCached = null;
    const getBaseline = async () => {
      if (baselineCached) return baselineCached;
      baselineCached = await runProbe(baselineInput(ep, proxy, timeout), timeoutMs);
      return baselineCached;
    };

    if (needsAuth) {
      jobs.push(async () => {
        const [baseline, stripped] = [await getBaseline(), await runProbe(stripAuthInput(ep, proxy, timeout), timeoutMs)];
        const verdict = classifyAuthStrip(baseline, stripped);
        if (!verdict) return null;
        const finding = buildFinding({
          category: 'AUTHZ_AuthStrip',
          ep, verdict, resp: stripped,
          probe: { description: 'Strip Authorization/Cookie/X-API-Key/X-Auth-Token headers' },
          poc: pocAuthBypass({ endpoint: ep, sample: { url: ep.sampleUrl, body: ep.sampleBody, headers: ep.sampleHeaders } })
        });
        onHit && onHit(finding);
        return finding;
      });

      jobs.push(async () => {
        const [baseline, withBad] = [await getBaseline(), await runProbe(invalidTokenInput(ep, proxy, timeout), timeoutMs)];
        const verdict = classifyInvalidToken(baseline, withBad);
        if (!verdict) return null;
        const finding = buildFinding({
          category: 'AUTHZ_InvalidToken',
          ep, verdict, resp: withBad,
          probe: { description: 'Replace Authorization with an obviously invalid token' },
          poc: pocInvalidToken({ endpoint: ep, sample: { url: ep.sampleUrl, body: ep.sampleBody, headers: ep.sampleHeaders } })
        });
        onHit && onHit(finding);
        return finding;
      });
    }

    // CORS — test four origin variants.
    const host = ep.host || '';
    const corsVariants = [
      { origin: ATTACKER_ORIGIN,                                     scenario: 'arbitrary-attacker-origin' },
      { origin: 'null',                                              scenario: 'null-origin' },
      { origin: `https://${host}.attacker.example.com`,              scenario: 'suffix-confusion' },
      { origin: `https://attacker-${host}`,                          scenario: 'prefix-confusion' }
    ];
    for (const { origin, scenario } of corsVariants) {
      jobs.push(async () => {
        const baseline = await getBaseline();
        const resp = await runProbe(corsInput(ep, proxy, timeout, origin), timeoutMs);
        const sensitiveBaseline = baseline.status >= 200 && baseline.status < 300 && (baseline.body_excerpt || '').length > 40;
        const verdict = classifyCors({ origin, resp, sensitiveBaseline, scenario });
        if (!verdict) return null;
        let poc;
        if (verdict.signals.some((s) => s.startsWith('reflected-origin'))) {
          poc = pocCorsReflected({ endpoint: ep, sample: { url: ep.sampleUrl }, attackerOrigin: ATTACKER_ORIGIN });
        } else if (verdict.signals.includes('null-origin-accepted')) {
          poc = pocCorsNull({ endpoint: ep, sample: { url: ep.sampleUrl } });
        } else if (verdict.signals.includes('wildcard-origin')) {
          poc = pocCorsWildcardCreds({ endpoint: ep, sample: { url: ep.sampleUrl } });
        }
        const finding = buildFinding({
          category: 'CORS_Misconfig',
          ep, verdict, resp,
          probe: { description: `Origin: ${origin} (${scenario})` },
          poc
        });
        onHit && onHit(finding);
        return finding;
      });
    }
  }

  const raw = await pool(jobs, concurrency, onProgress);
  const findings = raw.filter(Boolean);
  const rank = { Confirmed: 0, Likely: 1, Possible: 2 };
  findings.sort((a, b) =>
    (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) ||
    a.category.localeCompare(b.category) ||
    a.endpoint.localeCompare(b.endpoint)
  );
  return { totalProbes: jobs.length, findings };
}

function buildFinding({ category, ep, verdict, resp, probe, poc }) {
  return {
    category,
    severity: verdict.severity,
    signals: verdict.signals,
    endpoint: `${ep.method} ${ep.url}`,
    param: probe.description || '',
    payload: '',
    status: resp.status,
    elapsedMs: resp.elapsed_ms,
    responseHeaders: resp.headers || {},
    bodyExcerpt: (resp.body_excerpt || '').slice(0, 2048),
    scenario: verdict.scenario || null,
    poc: poc || null
  };
}

module.exports = { runQuickCheck };
