// Dedupe Burp traffic into API endpoints and score each for SSRF candidacy.

const SSRF_PARAM_RE = /(url|uri|src|dest|destination|redirect|redirect_uri|callback|feed|host|hostname|path|target|proxy|image|img|file|document|fetch|load|next|return|return_url|continue|data|site|domain|link|resource|endpoint|webhook|avatar|thumbnail|preview)/i;
const URL_VAL_RE = /^\s*(https?:\/\/|ftp:\/\/|\/\/|\/)/i;
const IP_VAL_RE = /^\s*\d{1,3}(\.\d{1,3}){3}\b/;
const HOST_VAL_RE = /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const IGNORE_EXTS = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.map'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function inScope(host, scope) {
  if (!scope || scope.length === 0) return true;
  const h = (host || '').toLowerCase().split(':')[0];  // drop :port if present
  return scope.some((raw) => {
    if (!raw) return false;
    const s = raw.toLowerCase().split(':')[0];
    return h === s || h.endsWith('.' + s);
  });
}

function templatePath(p) {
  return p
    .split('/')
    .map((seg) => {
      if (!seg) return seg;
      if (/^\d+$/.test(seg)) return '{id}';
      if (UUID_RE.test(seg)) return '{id}';
      if (seg.length >= 16 && /^[0-9a-f]+$/i.test(seg)) return '{id}';
      return seg;
    })
    .join('/');
}

function* flatten(obj, prefix = '') {
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object') yield* flatten(v, key);
      else yield [key, v];
    }
  } else if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const v = obj[i];
      const key = `${prefix}[${i}]`;
      if (v && typeof v === 'object') yield* flatten(v, key);
      else yield [key, v];
    }
  } else {
    yield [prefix || 'value', obj];
  }
}

function extractParams(req) {
  const specs = [];
  let u;
  try { u = new URL(req.url); } catch { u = null; }
  if (u) {
    for (const [k, v] of u.searchParams) specs.push({ name: k, location: 'query', sampleValue: v });
  }
  const ctype = (req.headers['Content-Type'] || req.headers['content-type'] || '').toLowerCase();
  const body = req.body || '';
  if (body) {
    if (ctype.includes('application/json')) {
      try {
        const obj = JSON.parse(body);
        for (const [k, v] of flatten(obj)) {
          specs.push({ name: k, location: 'body-json', sampleValue: String(v).slice(0, 200) });
        }
      } catch {}
    } else if (ctype.includes('application/x-www-form-urlencoded') || (body.includes('=') && !body.slice(0, 200).includes('\n'))) {
      try {
        const params = new URLSearchParams(body);
        for (const [k, v] of params) specs.push({ name: k, location: 'body-form', sampleValue: v });
      } catch {}
    }
  }
  for (const h of ['Referer', 'X-Forwarded-Host', 'X-Forwarded-For', 'Host', 'X-Original-URL']) {
    if (req.headers[h]) specs.push({ name: h, location: 'header', sampleValue: req.headers[h] });
  }
  return specs;
}

function scoreParams(params) {
  let score = 0;
  for (const p of params) {
    const nameHit = SSRF_PARAM_RE.test(p.name);
    const val = p.sampleValue || '';
    const valHit = URL_VAL_RE.test(val) || IP_VAL_RE.test(val) || HOST_VAL_RE.test(val);
    if (nameHit && valHit) score += 5;
    else if (nameHit) score += 3;
    else if (valHit && p.location !== 'header') score += 2;
  }
  return score;
}

function enumerate(requests, scope = []) {
  const seen = new Map();
  const stats = { input: requests.length, outOfScope: 0, staticAssets: 0, deduped: 0 };
  for (const r of requests) {
    let host = r.host || '';
    let parsed = null;
    try { parsed = new URL(r.url); host = (host || parsed.hostname || '').split(':')[0]; } catch {}
    if (!inScope(host, scope)) { stats.outOfScope++; continue; }
    const path = (parsed && parsed.pathname) || r.path || '/';
    if (IGNORE_EXTS.some((ext) => path.toLowerCase().endsWith(ext))) { stats.staticAssets++; continue; }
    const templated = templatePath(path);
    const params = extractParams(r);
    const pkey = [...new Set(params.map((p) => p.name))].sort().join(',');
    const key = `${(r.method || 'GET').toUpperCase()}|${host}|${templated}|${pkey}`;
    if (seen.has(key)) { stats.deduped++; continue; }
    const scheme = (parsed && parsed.protocol?.replace(':', '')) || 'https';
    seen.set(key, {
      method: (r.method || 'GET').toUpperCase(),
      url: `${scheme}://${host}${templated}`,
      host,
      path: templated,
      params,
      sampleUrl: r.url,
      sampleBody: r.body || '',
      sampleHeaders: r.headers || {},
      score: scoreParams(params)
    });
  }
  const endpoints = [...seen.values()].sort((a, b) => b.score - a.score || a.host.localeCompare(b.host));
  return { endpoints, stats };
}

module.exports = { enumerate };
