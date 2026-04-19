// Attack-surface analyzer.
//
// Pure, request-free heuristics that look at a single enumerated endpoint and
// decide which OWASP API Top 10 categories are worth exploring against it.
// Output per endpoint is a ranked list of { category, confidence, rationale,
// probes, impact } — the operator reads this and knows exactly where to
// point the active scan.
//
// Nothing here fires a network request. This runs in-process on enumeration
// output, instantly, so the operator always has a prioritized plan before
// any heavy probing happens.

const ID_NAME_RE = /(^id$|_id$|^uid$|uuid|guid|account|user|customer|order|invoice|record|doc|document|object|file|resource)/i;
const ID_VAL_RE = /^(\d{2,}|[0-9a-f]{8,36}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const SSRF_NAME_RE = /(url|uri|src|dest|destination|redirect|redirect_uri|callback|feed|host|hostname|path|target|proxy|image|img|file|document|fetch|load|next|return|return_url|continue|data|site|domain|link|resource|endpoint|webhook|avatar|thumbnail|preview)/i;
const URL_VAL_RE = /^\s*(https?:\/\/|ftp:\/\/|\/\/|\/)/i;
const IP_VAL_RE = /^\s*\d{1,3}(\.\d{1,3}){3}\b/;
const HOST_VAL_RE = /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

const MASS_ASSIGN_FIELDS = ['role', 'is_admin', 'isAdmin', 'admin', 'permissions', 'is_superuser', 'verified', 'emailVerified', 'is_staff', 'scopes'];
const ADMIN_PATH_RE = /\/(admin|internal|debug|private|staff|manage|mgmt|root)\b/i;
const SENSITIVE_OP_RE = /\/(delete|remove|drop|reset|admin|promote|grant|revoke|approve|publish|disable|enable|suspend)/i;

const lowerHeaderKeys = (h) => {
  const out = new Set();
  for (const k of Object.keys(h || {})) out.add(k.toLowerCase());
  return out;
};

function hasAuthMarker(headers) {
  const lower = lowerHeaderKeys(headers);
  return lower.has('authorization') || lower.has('cookie') ||
         lower.has('x-api-key') || lower.has('x-auth-token') ||
         lower.has('x-csrf-token');
}

function contentTypeIsJson(headers) {
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() === 'content-type' && /application\/json/i.test(String(v))) return true;
  }
  return false;
}

// Pull id-looking segments from a path. Returns [{ segment, kind }].
function pathIds(pathStr) {
  const out = [];
  for (const seg of String(pathStr || '').split('/')) {
    if (!seg) continue;
    if (seg === '{id}') { out.push({ segment: seg, kind: 'templated' }); continue; }
    if (/^\d+$/.test(seg) && seg.length >= 2) { out.push({ segment: seg, kind: 'numeric' }); continue; }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
      out.push({ segment: seg, kind: 'uuid' }); continue;
    }
    if (/^[0-9a-f]{16,}$/i.test(seg)) { out.push({ segment: seg, kind: 'hex' }); continue; }
  }
  return out;
}

function idParams(params) {
  return (params || []).filter((p) => {
    const name = p.name || '';
    const val = p.sampleValue || '';
    return ID_NAME_RE.test(name) || ID_VAL_RE.test(val);
  });
}

function ssrfParams(params) {
  return (params || []).filter((p) => {
    const name = p.name || '';
    const val = p.sampleValue || '';
    return SSRF_NAME_RE.test(name) ||
           URL_VAL_RE.test(val) || IP_VAL_RE.test(val) || HOST_VAL_RE.test(val);
  });
}

// ---- Per-category analyzers ------------------------------------------------

function api1Bola(ep) {
  const ids = pathIds(ep.path);
  const idParamList = idParams(ep.params);
  if (ids.length === 0 && idParamList.length === 0) return null;
  const reasons = [];
  const probes = [];
  if (ids.length) {
    reasons.push(`Path contains object-ID segments (${ids.map((i) => `${i.segment}[${i.kind}]`).join(', ')}) that an attacker can swap.`);
    probes.push('Replace the ID segment with 1, 2, 99999, 0, -1, and the UUID 00000000-0000-0000-0000-000000000001');
  }
  if (idParamList.length) {
    reasons.push(`ID-shaped parameters: ${idParamList.map((p) => `${p.name}@${p.location}=${p.sampleValue || ''}`).join(', ')}`);
    probes.push('Substitute each ID-shaped param with neighbor values (±1, 99999, 0)');
  }
  return {
    id: 'API1_BOLA',
    category: 'API1:2023',
    title: 'Broken Object Level Authorization (BOLA)',
    confidence: ids.length ? 'high' : 'medium',
    rationale: reasons.join(' '),
    probes,
    impact: 'Horizontal privilege escalation — read, modify, or delete objects belonging to other users.',
    poc: `# Replace the ID segment and re-send the authenticated request:\ncurl -i '${ep.sampleUrl || ep.url}' \\\n  -H 'Authorization: <your token>'  # then change the ID in the URL and re-run`
  };
}

function api2BrokenAuth(ep) {
  if (!hasAuthMarker(ep.sampleHeaders || {})) return null;
  const markers = [];
  const lower = lowerHeaderKeys(ep.sampleHeaders);
  for (const m of ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token']) {
    if (lower.has(m)) markers.push(m);
  }
  return {
    id: 'API2_BrokenAuth',
    category: 'API2:2023',
    title: 'Broken Authentication',
    confidence: 'high',
    rationale: `Endpoint currently authenticates via ${markers.join(', ')}. If the server fails to validate or require those headers, the endpoint is fully exposed.`,
    probes: [
      `Strip the ${markers.join(' + ')} header(s) entirely`,
      'Replace the token with "Bearer invalid-token-for-poc-only"'
    ],
    impact: 'Full authentication bypass. Any unauthenticated attacker reaches the same data the signed-in user does.',
    poc: `# With all auth headers stripped:\ncurl -i '${ep.sampleUrl || ep.url}'   # — should 401/403. 2xx = bypass.`
  };
}

function api3Bopla(ep) {
  const method = (ep.method || '').toUpperCase();
  if (!['POST', 'PUT', 'PATCH'].includes(method)) return null;
  const isJson = contentTypeIsJson(ep.sampleHeaders) || (ep.sampleBody && ep.sampleBody.trim().startsWith('{'));
  if (!isJson && !ep.sampleBody) return null;
  return {
    id: 'API3_BOPLA',
    category: 'API3:2023',
    title: 'Broken Object Property Level Authorization (Mass Assignment)',
    confidence: isJson ? 'medium' : 'low',
    rationale: `${method} endpoint with a mutable body${isJson ? ' (JSON)' : ''}. Servers often deserialize the whole payload into an ORM object — injecting privileged fields can elevate the caller.`,
    probes: MASS_ASSIGN_FIELDS.map((f) => `Inject "${f}": true (or "admin") into the request body`),
    impact: 'Privilege escalation: set your own role to admin, enable features, bypass approval flags.',
    poc: `# Add a privileged field to the existing JSON body:\ncurl -i '${ep.sampleUrl || ep.url}' -X ${method} \\\n  -H 'Content-Type: application/json' \\\n  --data '{"<original fields>": ..., "isAdmin": true, "role": "admin"}'`
  };
}

function api4RateLimit() {
  // Always applicable, but low-priority — no endpoint-specific reason.
  return {
    id: 'API4_RateLimit',
    category: 'API4:2023',
    title: 'Unrestricted Resource Consumption',
    confidence: 'low',
    rationale: 'Every endpoint is testable for missing rate limits, but without business context the impact of the finding may be small.',
    probes: ['Fire 30 requests in ~1 second; flag if none return 429/503'],
    impact: 'DoS, brute-force, credential-stuffing, scraping.'
  };
}

function api5Bfla(ep) {
  const method = (ep.method || 'GET').toUpperCase();
  const reasons = [];
  let confidence = 'medium';
  if (ADMIN_PATH_RE.test(ep.path || '')) {
    reasons.push(`Path looks administrative (matches /admin|internal|debug|private|staff|manage/).`);
    confidence = 'high';
  }
  if (SENSITIVE_OP_RE.test(ep.path || '')) {
    reasons.push(`Path includes sensitive verb segment (delete/reset/grant/...).`);
    confidence = 'high';
  }
  reasons.push(`Current method is ${method}; servers frequently forget to enforce method-level auth for DELETE/PUT/PATCH.`);
  return {
    id: 'API5_BFLA',
    category: 'API5:2023',
    title: 'Broken Function Level Authorization (BFLA)',
    confidence,
    rationale: reasons.join(' '),
    probes: ['DELETE', 'PUT', 'PATCH'].filter((m) => m !== method).map((m) => `Resend request with method ${m}`),
    impact: 'Privilege escalation via unexpected method support — a regular user deleting admin-only records.',
    poc: `# Switch method only:\ncurl -i '${ep.sampleUrl || ep.url}' -X DELETE  -H 'Authorization: <your token>'`
  };
}

function api7Ssrf(ep) {
  const ssrfP = ssrfParams(ep.params);
  if (ssrfP.length === 0) return null;
  const named = ssrfP.filter((p) => SSRF_NAME_RE.test(p.name));
  const urlShaped = ssrfP.filter((p) => URL_VAL_RE.test(p.sampleValue || '') || IP_VAL_RE.test(p.sampleValue || ''));
  let confidence = 'low';
  if (named.length && urlShaped.length) confidence = 'high';
  else if (named.length) confidence = 'high';
  else if (urlShaped.length) confidence = 'medium';
  const reasons = [];
  if (named.length) reasons.push(`Param names matching SSRF pattern: ${named.map((p) => `${p.name}@${p.location}`).join(', ')}.`);
  if (urlShaped.length) reasons.push(`URL-shaped values on: ${urlShaped.map((p) => `${p.name}=${p.sampleValue || ''}`).join(', ')}.`);
  return {
    id: 'API7_SSRF',
    category: 'API7:2023',
    title: 'Server-Side Request Forgery (SSRF)',
    confidence,
    rationale: reasons.join(' '),
    probes: [
      'Loopback: http://127.0.0.1/, http://127.0.0.1:22/, http://localhost/',
      'Cloud metadata: http://169.254.169.254/latest/meta-data/, metadata.google.internal, Azure IMDS',
      'Schemes: file:///etc/passwd, dict://127.0.0.1:11211/stats, gopher://...',
      'OOB canary (Burp Collaborator / Interactsh) to confirm outbound traffic'
    ],
    impact: 'Internal network reach, cloud-credential theft, port scanning, sometimes RCE via gopher:/file:.',
    poc: `# Replace the SSRF param and watch the response body:\ncurl -i '${ep.sampleUrl || ep.url}'   # after editing ?<param>=http://127.0.0.1:22/`
  };
}

function api8Misconfig(ep) {
  // Every response is testable for header hygiene; surface as low-priority
  // always-on, plus boost confidence if any Origin header was observed in the
  // captured request (indicates CORS is in play).
  const sawOrigin = lowerHeaderKeys(ep.sampleHeaders).has('origin');
  return {
    id: 'API8_Misconfig',
    category: 'API8:2023',
    title: 'Security Misconfiguration (headers, CORS, errors)',
    confidence: sawOrigin ? 'medium' : 'low',
    rationale: sawOrigin
      ? 'Request was observed to carry an Origin header — CORS policy is actively being evaluated.'
      : 'Baseline response can be checked for missing security headers (CSP, HSTS, X-Frame-Options), CORS wildcards, and verbose error pages.',
    probes: [
      'Read response headers for missing CSP / HSTS / X-Content-Type-Options / X-Frame-Options',
      'Test Origin: https://attacker.example.com and Origin: null for reflection + credentials',
      'Trigger an error (bad method, bad payload) and look for stack traces'
    ],
    impact: 'Secondary vulnerabilities (XSS via missing CSP, clickjacking, CORS exfil, info disclosure).'
  };
}

function api9Inventory(ep) {
  const path = ep.path || '';
  const versionMatch = path.match(/\/v(\d+)(\/|$)/i);
  const isApi = path.startsWith('/api/');
  if (!versionMatch && !isApi) return null;
  const reasons = [];
  const probes = [];
  let confidence = 'medium';
  if (versionMatch) {
    confidence = 'high';
    const n = Number(versionMatch[1]);
    reasons.push(`Path is versioned (/v${n}/). Older or neighboring versions may still be online with weaker auth.`);
    const neighbors = new Set([0, 1, n - 1, n + 1].filter((x) => x >= 0 && x !== n));
    for (const v of neighbors) probes.push(`Swap /v${n}/ → /v${v}/`);
  }
  if (isApi) {
    reasons.push('Path is under /api/ — "shadow" siblings (dev, debug, internal, beta) are common.');
    for (const alt of ['/api/internal', '/api/dev', '/api/debug', '/api/old', '/api/beta']) {
      probes.push(`Mirror request under ${alt}${path.replace(/^\/api/, '')}`);
    }
  }
  return {
    id: 'API9_Inventory',
    category: 'API9:2023',
    title: 'Improper Inventory Management',
    confidence,
    rationale: reasons.join(' '),
    probes,
    impact: 'Access to deprecated or internal endpoints with weaker authz, different validation, or exposed debug features.'
  };
}

function authzCors(ep) {
  // A dedicated surface card pointing at the auto-run quick-check already
  // wired into the app. Shows up alongside OWASP items so the operator sees
  // the full roster.
  if (!hasAuthMarker(ep.sampleHeaders || {})) return null;
  return {
    id: 'AUTHZ_CORS',
    category: 'Quick-check',
    title: 'Authorization + CORS (auto-run)',
    confidence: 'high',
    rationale: 'Endpoint authenticates; the Authz/CORS quick-check automatically strips auth headers, replaces tokens with invalid values, and probes four Origin variants — producing ready-to-run PoCs for any hit.',
    probes: [
      'Strip Authorization / Cookie / X-API-Key',
      'Invalid-token replay',
      'Origin: https://attacker.example.com',
      'Origin: null (via sandboxed iframe)',
      'Suffix/prefix origin confusion'
    ],
    impact: 'Full authentication bypass OR cross-origin data theft on any browser where the victim is signed in.'
  };
}

// ---- Entry point -----------------------------------------------------------

function analyze(endpoint) {
  const surfaces = [
    api1Bola(endpoint),
    api2BrokenAuth(endpoint),
    authzCors(endpoint),
    api3Bopla(endpoint),
    api5Bfla(endpoint),
    api7Ssrf(endpoint),
    api9Inventory(endpoint),
    api8Misconfig(endpoint),
    api4RateLimit()
  ].filter(Boolean);

  const rank = { high: 0, medium: 1, low: 2 };
  surfaces.sort((a, b) => (rank[a.confidence] ?? 9) - (rank[b.confidence] ?? 9));
  return surfaces;
}

function analyzeAll(endpoints) {
  return endpoints.map((ep) => ({ ...ep, attackSurface: analyze(ep) }));
}

module.exports = { analyze, analyzeAll };
