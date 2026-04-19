// Probe generators + classifiers for OWASP API Security Top 10 (2023).
//
// Each category exports `generate(endpoint)` → a list of probes and a
// `classify(probe, response, ctx)` → finding-or-null. Probes are consumed by
// the shared executor which calls the PowerShell probe script per probe.
//
// Covered automatically:
//   API1  Broken Object Level Authorization (BOLA)
//   API2  Broken Authentication
//   API3  Broken Object Property Level Authorization (BOPLA / mass assignment)
//   API4  Unrestricted Resource Consumption (rate-limit absence)
//   API5  Broken Function Level Authorization (BFLA / method switching)
//   API7  Server-Side Request Forgery (SSRF)
//   API8  Security Misconfiguration
//   API9  Improper Inventory Management
//
// Not covered here (need application semantics / human judgement):
//   API6  Unrestricted Access to Sensitive Business Flows
//   API10 Unsafe Consumption of APIs

const { buildPayloads: ssrfPayloads } = require('./payloads');
const { classify: classifySsrf } = require('./detector');

const SSRF_PARAM_RE = /(url|uri|src|dest|destination|redirect|redirect_uri|callback|feed|host|hostname|path|target|proxy|image|img|file|document|fetch|load|next|return|return_url|continue|data|site|domain|link|resource|endpoint|webhook|avatar|thumbnail|preview)/i;
const URL_VAL_RE = /^\s*(https?:\/\/|ftp:\/\/|\/\/|\/)/i;
const IP_VAL_RE = /^\s*\d{1,3}(\.\d{1,3}){3}\b/;
const HOST_VAL_RE = /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const ID_NAME_RE = /(^id$|_id$|uuid|guid|account|user|customer|order|invoice|record|doc|document|object)/i;
const ID_VAL_RE = /^(\d{1,}|[0-9a-f-]{8,36})$/i;

const isSsrfTargetable = (p) =>
  SSRF_PARAM_RE.test(p.name) ||
  URL_VAL_RE.test(p.sampleValue || '') ||
  IP_VAL_RE.test(p.sampleValue || '') ||
  HOST_VAL_RE.test(p.sampleValue || '');

const isIdLike = (p) => ID_NAME_RE.test(p.name) || ID_VAL_RE.test(p.sampleValue || '');

const has = (s, arr) => arr.some((m) => (s || '').includes(m));

// ---- API7: SSRF ------------------------------------------------------------

function generateSsrf(endpoint, config) {
  const payloads = ssrfPayloads(config.oobCanary);
  const out = [];
  for (const param of endpoint.params || []) {
    if (!isSsrfTargetable(param)) continue;
    for (const p of payloads) {
      out.push({
        category: 'API7_SSRF',
        description: p.note || p.category,
        param: { name: param.name, location: param.location },
        payload: p.value,
        meta: { payloadCategory: p.category }
      });
    }
  }
  return out;
}

function classifySsrfProbe(probe, resp, ctx) {
  const oobHost = ctx.oobHost || '';
  const hdrBlob = Object.entries(resp.headers || {}).map(([k, v]) => `${k}: ${v}`).join(' ');
  const oobHit = !!(oobHost && (hdrBlob.includes(oobHost) || (resp.body_excerpt || '').includes(oobHost)));
  const { severity, signals } = classifySsrf({
    category: probe.meta.payloadCategory,
    status: resp.status,
    body: resp.body_excerpt,
    elapsedMs: resp.elapsed_ms || 0,
    baselineMs: ctx.baselineMs || null,
    oobHit
  });
  if (severity === 'None') return null;
  return { severity, signals };
}

// ---- API1: BOLA ------------------------------------------------------------

function generateBola(endpoint) {
  const out = [];
  for (const param of endpoint.params || []) {
    if (!isIdLike(param)) continue;
    for (const val of ['1', '2', '99999', '0', '-1', '00000000-0000-0000-0000-000000000001']) {
      if (param.sampleValue === val) continue;
      out.push({
        category: 'API1_BOLA',
        description: `substitute ${param.name}=${val}`,
        param: { name: param.name, location: param.location },
        payload: val
      });
    }
  }
  return out;
}

function classifyBola(probe, resp, ctx) {
  const baselineBody = ctx.baselineBody || '';
  const body = resp.body_excerpt || '';
  const ok = resp.status >= 200 && resp.status < 300;
  if (!ok) return null;
  // Heuristic: same endpoint with a *different* ID returns 2xx with a body
  // that differs meaningfully from the baseline → object is accessible.
  if (body.length > 32 && body !== baselineBody) {
    return { severity: 'Possible', signals: ['id-accepted-diff-body', `status-${resp.status}`] };
  }
  return null;
}

// ---- API2: Broken Authentication -------------------------------------------

function generateBrokenAuth(endpoint) {
  // Only worth testing on endpoints that currently send an auth header/cookie.
  const h = endpoint.sampleHeaders || {};
  const hasAuth = Object.keys(h).some((k) => /^(authorization|cookie|x-api-key|x-auth-token)$/i.test(k));
  if (!hasAuth) return [];
  return [{
    category: 'API2_BrokenAuth',
    description: 'strip Authorization + Cookie + X-API-Key',
    param: { name: 'Authorization,Cookie,X-API-Key,X-Auth-Token', location: 'header-remove' },
    payload: '<stripped>'
  }];
}

function classifyBrokenAuth(probe, resp, ctx) {
  if (resp.status >= 200 && resp.status < 300) {
    // Compare to baseline to avoid flagging genuinely public endpoints.
    const baselineBody = ctx.baselineBody || '';
    const body = resp.body_excerpt || '';
    if (body.length > 20 && body === baselineBody) {
      return { severity: 'Likely', signals: ['auth-stripped-identical-body'] };
    }
    if (body.length > 20) {
      return { severity: 'Possible', signals: ['auth-stripped-2xx'] };
    }
  }
  return null;
}

// ---- API3: BOPLA (mass assignment) -----------------------------------------

function generateBopla(endpoint) {
  if (!['POST', 'PUT', 'PATCH'].includes((endpoint.method || '').toUpperCase())) return [];
  const candidates = ['isAdmin', 'is_admin', 'role', 'admin', 'permissions', 'is_superuser', 'verified', 'emailVerified'];
  return candidates.map((name) => ({
    category: 'API3_BOPLA',
    description: `inject field ${name}`,
    param: { name, location: 'body-inject' },
    payload: name === 'permissions' ? '["*"]' : (name === 'role' ? 'admin' : true)
  }));
}

function classifyBopla(probe, resp, ctx) {
  const body = resp.body_excerpt || '';
  const ok = resp.status >= 200 && resp.status < 300;
  if (ok && body.length > 20 && body.includes(probe.param.name)) {
    return { severity: 'Possible', signals: ['injected-field-echoed', `status-${resp.status}`] };
  }
  if (ok && body !== ctx.baselineBody) {
    return { severity: 'Possible', signals: ['injected-field-accepted-diff-body'] };
  }
  return null;
}

// ---- API4: Rate limiting ---------------------------------------------------

function generateRateLimit() {
  // Single logical probe; the runner detects this category and repeats it.
  return [{
    category: 'API4_RateLimit',
    description: 'rapid-fire 30x to detect missing rate limits',
    param: { name: '_baseline', location: 'none' },
    payload: 'x30',
    meta: { repeat: 30 }
  }];
}

// classifyRateLimit lives on the aggregated burst result, not a single probe.
function classifyRateLimitBurst({ statuses, elapsedMs }) {
  const any429 = statuses.includes(429);
  const any503 = statuses.includes(503);
  const ok2xx = statuses.filter((s) => s >= 200 && s < 300).length;
  if (!any429 && !any503 && ok2xx >= 25) {
    return { severity: 'Likely', signals: [`no-429-in-${statuses.length}`, `2xx-count-${ok2xx}`] };
  }
  return null;
}

// ---- API5: BFLA (method switching) -----------------------------------------

function generateBfla(endpoint) {
  const method = (endpoint.method || 'GET').toUpperCase();
  const candidates = ['DELETE', 'PUT', 'PATCH'].filter((m) => m !== method);
  return candidates.map((m) => ({
    category: 'API5_BFLA',
    description: `switch method to ${m}`,
    param: { name: '_method', location: 'method' },
    payload: m
  }));
}

function classifyBfla(probe, resp) {
  if (resp.status >= 200 && resp.status < 300) {
    return { severity: 'Likely', signals: [`method-${probe.payload}-accepted-${resp.status}`] };
  }
  if (resp.status && ![401, 403, 404, 405, 501].includes(resp.status) && resp.status < 500) {
    return { severity: 'Possible', signals: [`method-${probe.payload}-status-${resp.status}`] };
  }
  return null;
}

// ---- API8: Security Misconfiguration ---------------------------------------

const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy'
];

const STACK_MARKERS = [
  'at java.',
  'at org.springframework',
  'Traceback (most recent call last)',
  'System.Web.HttpException',
  'ORA-0',
  '<b>Fatal error</b>',
  'PHP Fatal',
  'gunicorn.error'
];

function generateMisconfig(endpoint) {
  // Piggyback on baseline: a single no-mutation probe per endpoint.
  return [{
    category: 'API8_Misconfig',
    description: 'baseline header + error inspection',
    param: { name: '_baseline', location: 'none' },
    payload: '<baseline>'
  }];
}

function classifyMisconfig(probe, resp) {
  const signals = [];
  const lowerHeaders = {};
  for (const [k, v] of Object.entries(resp.headers || {})) lowerHeaders[k.toLowerCase()] = v;
  for (const h of SECURITY_HEADERS) {
    if (!lowerHeaders[h]) signals.push(`missing:${h}`);
  }
  const cors = lowerHeaders['access-control-allow-origin'];
  if (cors === '*' && lowerHeaders['access-control-allow-credentials'] === 'true') {
    signals.push('cors-wildcard-with-credentials');
  }
  const server = lowerHeaders['server'] || lowerHeaders['x-powered-by'];
  if (server && /\d/.test(server)) signals.push(`version-disclosure:${server}`);
  const body = resp.body_excerpt || '';
  if (STACK_MARKERS.some((m) => body.includes(m))) signals.push('stack-trace-in-body');
  if (!signals.length) return null;
  const severity = signals.some((s) => s.startsWith('cors-wildcard') || s === 'stack-trace-in-body')
    ? 'Likely'
    : 'Possible';
  return { severity, signals };
}

// ---- API9: Improper Inventory Management -----------------------------------

function generateInventory(endpoint) {
  const probes = [];
  // If path has /v1/, /v2/, etc. — try older/neighbor versions.
  const m = endpoint.path.match(/\/v(\d+)(\/|$)/i);
  if (m) {
    const n = Number(m[1]);
    const candidates = new Set([0, 1, Math.max(0, n - 1)]);
    candidates.delete(n);
    for (const v of candidates) {
      const newPath = endpoint.path.replace(/\/v\d+(\/|$)/i, `/v${v}$1`);
      probes.push({
        category: 'API9_Inventory',
        description: `swap version to v${v}`,
        param: { name: '_path', location: 'path-swap' },
        payload: newPath
      });
    }
  }
  // Try common "non-prod" siblings.
  for (const alt of ['/api/internal', '/api/dev', '/api/debug', '/api/old', '/api/beta']) {
    if (endpoint.path.startsWith('/api/') && !endpoint.path.startsWith(alt)) {
      const newPath = endpoint.path.replace(/^\/api/, alt);
      probes.push({
        category: 'API9_Inventory',
        description: `mirror under ${alt}`,
        param: { name: '_path', location: 'path-swap' },
        payload: newPath
      });
    }
  }
  return probes;
}

function classifyInventory(probe, resp) {
  if (resp.status >= 200 && resp.status < 300 && (resp.body_excerpt || '').length > 20) {
    return { severity: 'Likely', signals: ['inventory-variant-reachable', `status-${resp.status}`] };
  }
  return null;
}

// ---- Orchestration ---------------------------------------------------------

const ALL_CATEGORIES = [
  'API1_BOLA',
  'API2_BrokenAuth',
  'API3_BOPLA',
  'API4_RateLimit',
  'API5_BFLA',
  'API7_SSRF',
  'API8_Misconfig',
  'API9_Inventory'
];

const CATEGORY_META = {
  API1_BOLA:       { number: 'API1:2023', name: 'Broken Object Level Authorization' },
  API2_BrokenAuth: { number: 'API2:2023', name: 'Broken Authentication' },
  API3_BOPLA:      { number: 'API3:2023', name: 'Broken Object Property Level Authorization' },
  API4_RateLimit:  { number: 'API4:2023', name: 'Unrestricted Resource Consumption' },
  API5_BFLA:       { number: 'API5:2023', name: 'Broken Function Level Authorization' },
  API7_SSRF:       { number: 'API7:2023', name: 'Server-Side Request Forgery' },
  API8_Misconfig:  { number: 'API8:2023', name: 'Security Misconfiguration' },
  API9_Inventory:  { number: 'API9:2023', name: 'Improper Inventory Management' }
};

function generateAll(endpoint, config, categories) {
  const active = new Set(categories && categories.length ? categories : ALL_CATEGORIES);
  const out = [];
  if (active.has('API7_SSRF')) out.push(...generateSsrf(endpoint, config));
  if (active.has('API1_BOLA')) out.push(...generateBola(endpoint));
  if (active.has('API2_BrokenAuth')) out.push(...generateBrokenAuth(endpoint));
  if (active.has('API3_BOPLA')) out.push(...generateBopla(endpoint));
  if (active.has('API4_RateLimit')) out.push(...generateRateLimit());
  if (active.has('API5_BFLA')) out.push(...generateBfla(endpoint));
  if (active.has('API8_Misconfig')) out.push(...generateMisconfig(endpoint));
  if (active.has('API9_Inventory')) out.push(...generateInventory(endpoint));
  return out;
}

function classifyProbe(probe, resp, ctx) {
  switch (probe.category) {
    case 'API7_SSRF':       return classifySsrfProbe(probe, resp, ctx);
    case 'API1_BOLA':       return classifyBola(probe, resp, ctx);
    case 'API2_BrokenAuth': return classifyBrokenAuth(probe, resp, ctx);
    case 'API3_BOPLA':      return classifyBopla(probe, resp, ctx);
    case 'API5_BFLA':       return classifyBfla(probe, resp, ctx);
    case 'API8_Misconfig':  return classifyMisconfig(probe, resp);
    case 'API9_Inventory':  return classifyInventory(probe, resp);
    case 'API4_RateLimit':  return null; // handled via burst classifier
    default: return null;
  }
}

module.exports = {
  generateAll,
  classifyProbe,
  classifyRateLimitBurst,
  ALL_CATEGORIES,
  CATEGORY_META
};
