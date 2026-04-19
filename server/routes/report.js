const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const db = require('../db');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

function h(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function renderHtml({ auth, target, endpoints, findings, counts, byCategory, generatedAt }) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>SSRF Report</title>
<style>body{font:14px/1.45 system-ui, sans-serif;margin:24px;color:#222}
h1{margin-top:0}.auth{background:#fff7d9;border:1px solid #e0c667;padding:12px 16px;border-radius:6px}
.meta{color:#666;font-size:12px}table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}th{background:#f6f6f6}
.sev-Confirmed{background:#fde4e4}.sev-Likely{background:#fff1dc}.sev-Possible{background:#eef5ff}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;background:#f5f5f5;padding:2px 5px;border-radius:3px}
pre{padding:10px;white-space:pre-wrap;word-break:break-all}.tag{display:inline-block;padding:1px 6px;border-radius:10px;background:#eef;font-size:11px;margin-right:4px}
</style></head><body>
<h1>SSRF Explorer — Report</h1>
<div class="auth"><b>Authorization</b><br>
Operator: <code>${h(auth?.operator)}</code><br>
Reference: <code>${h(auth?.engagementRef)}</code><br>
Attested at: <code>${h(auth?.attestedAt)}</code></div>
<p class="meta">Target: <code>${h(target?.url)}</code><br>
Scope: ${(target?.scopeHosts || []).map((x) => `<span class="tag">${h(x)}</span>`).join('')}<br>
Generated: <code>${h(generatedAt)}</code></p>
<h2>Summary</h2>
<ul><li>Endpoints: <b>${endpoints.length}</b></li>
<li>Confirmed: <b>${counts.Confirmed}</b> · Likely: <b>${counts.Likely}</b> · Possible: <b>${counts.Possible}</b></li>
<li>By category: ${Object.entries(byCategory || {}).map(([c, n]) => `<span class="tag">${h(c)}: ${n}</span>`).join(' ') || '—'}</li></ul>
<h2>Findings</h2>
${findings.length === 0 ? '<p><i>No security signals observed.</i></p>' : `
<table><thead><tr><th>Severity</th><th>Category</th><th>Endpoint</th><th>Param</th><th>Payload</th><th>Status</th><th>Signals</th></tr></thead><tbody>
${findings.map((f) => `
<tr class="sev-${h(f.severity)}"><td><b>${h(f.severity)}</b></td>
<td><span class="tag">${h(f.category)}</span></td>
<td><code>${h(f.endpoint)}</code></td><td><code>${h(f.param)}</code></td>
<td><code>${h(f.payload)}</code> <span class="tag">${h(f.payloadCategory)}</span></td>
<td>${h(f.status)}</td><td>${(f.signals || []).map((s) => `<span class="tag">${h(s)}</span>`).join('')}</td></tr>
<tr class="sev-${h(f.severity)}"><td colspan="6">
${f.redirect ? `<div>Redirect: <code>${h(f.redirect)}</code></div>` : ''}
${f.error ? `<div>Error: <code>${h(f.error)}</code></div>` : ''}
<pre>${h(f.bodyExcerpt)}</pre></td></tr>`).join('')}
</tbody></table>`}
<h2>Endpoint inventory</h2>
<table><thead><tr><th>Method</th><th>URL</th><th>Params</th><th>Score</th></tr></thead><tbody>
${endpoints.map((e) => `<tr><td><code>${h(e.method)}</code></td><td><code>${h(e.url)}</code></td>
<td>${(e.params || []).map((p) => `<span class="tag">${h(p.name)}@${h(p.location)}</span>`).join('')}</td>
<td>${h(e.score)}</td></tr>`).join('')}
</tbody></table></body></html>`;
}

router.post('/generate', async (req, res) => {
  const { targetId, endpoints, findings } = req.body || {};
  const Target = db.model('Target');
  const Authorization = db.model('Authorization');
  const target = targetId ? await Target.findById(targetId) : (req.body.target || {});
  const auth = targetId ? await Authorization.findOne({ targetId }) : (req.body.auth || {});
  const counts = { Confirmed: 0, Likely: 0, Possible: 0 };
  const byCategory = {};
  for (const f of findings || []) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    const c = f.category || 'unknown';
    byCategory[c] = (byCategory[c] || 0) + 1;
  }
  const html = renderHtml({
    auth, target, endpoints: endpoints || [], findings: findings || [],
    counts, byCategory, generatedAt: new Date().toISOString()
  });
  const dir = path.join(process.cwd(), 'reports');
  await fs.mkdir(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const htmlPath = path.join(dir, `ssrf-report-${stamp}.html`);
  const jsonPath = path.join(dir, `ssrf-report-${stamp}.json`);
  await fs.writeFile(htmlPath, html, 'utf8');
  await fs.writeFile(jsonPath, JSON.stringify({ auth, target, endpoints, findings, counts }, null, 2), 'utf8');
  res.json({ htmlPath, jsonPath });
});

module.exports = router;
