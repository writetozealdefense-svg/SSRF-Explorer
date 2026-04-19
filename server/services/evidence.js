// Evidence builder — turns a finding (from quickcheck or OWASP scan) into a
// self-contained HTML evidence page that Electron can render off-screen and
// screenshot. Each page shows: vulnerability banner, target endpoint, the
// exact request that was sent, the actual response received, which signal
// triggered detection, impact, and the PoC content. A ready-to-hand-off
// artifact for a pentest report.

function h(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function sevColor(severity) {
  return {
    Confirmed: { bg: '#fde4e4', border: '#d13a3a', text: '#7a1e1e' },
    Likely:    { bg: '#fff1dc', border: '#c7791f', text: '#6b3f10' },
    Possible:  { bg: '#eef5ff', border: '#4178d6', text: '#1a3a6e' }
  }[severity] || { bg: '#eef', border: '#777', text: '#333' };
}

function prettyJsonOrRaw(text) {
  try {
    const parsed = JSON.parse(text);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return text;
  }
}

function headersTable(headers) {
  if (!headers || Object.keys(headers).length === 0) return '<i>(none captured)</i>';
  return `<table class="kv">${Object.entries(headers)
    .map(([k, v]) => `<tr><th>${h(k)}</th><td>${h(v)}</td></tr>`)
    .join('')}</table>`;
}

// Reduce a finding + its PoC + its live response into a single page. The page
// is self-contained (inline CSS) so it renders correctly in any environment.
function buildEvidenceHtml({ finding, target, auth, requestSent, responseReceived, generatedAt }) {
  const sev = sevColor(finding.severity);
  const bodyText = responseReceived?.body_excerpt || finding.bodyExcerpt || '';
  const bodyPretty = prettyJsonOrRaw(bodyText).slice(0, 4096);

  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Evidence — ${h(finding.category)} — ${h(finding.endpoint)}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px 36px; background: #f6f7fa; color: #1e2230;
         font: 13px/1.55 -apple-system, 'Segoe UI', system-ui, sans-serif; }
  h1 { margin: 0 0 4px; font-size: 20px; }
  h2 { font-size: 14px; margin: 24px 0 6px; color: #333; letter-spacing: .3px; text-transform: uppercase; }
  .sev {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    background: ${sev.bg}; border: 1px solid ${sev.border}; color: ${sev.text};
    font-weight: 700; font-size: 11px; letter-spacing: .6px; text-transform: uppercase;
  }
  .cat { display: inline-block; padding: 3px 10px; border-radius: 4px; background: #e6eaf2; color: #334; font-size: 11px; margin-left: 6px; }
  .meta { color: #667; font-size: 12px; margin-top: 4px; }
  .card { background: white; border: 1px solid #dfe3ea; border-radius: 6px; padding: 14px 18px; margin-top: 10px; }
  .label { color: #556; font-size: 11px; letter-spacing: .4px; text-transform: uppercase; }
  code, pre { font-family: ui-monospace, Consolas, 'Courier New', monospace; font-size: 12px; }
  pre { background: #1b1f27; color: #d6dde8; padding: 12px 14px; border-radius: 4px;
        white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto;
        margin: 6px 0 0; }
  table.kv { border-collapse: collapse; width: 100%; font-size: 12px; }
  table.kv th { text-align: left; font-weight: 600; padding: 4px 10px 4px 0; color: #334; width: 32%; vertical-align: top; }
  table.kv td { padding: 4px 0; color: #1e2230; vertical-align: top; word-break: break-all; }
  .signals span { display: inline-block; padding: 2px 8px; margin: 2px 4px 2px 0; background: ${sev.bg}; color: ${sev.text}; border-radius: 10px; font-size: 11px; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 900px) { .row { grid-template-columns: 1fr; } }
  .stamp { margin-top: 22px; color: #889; font-size: 11px; }
  .auth-line { margin: 4px 0; font-size: 11px; color: #556; }
</style></head><body>

<div>
  <h1>${h(finding.category)} — ${h(finding.param || '')}</h1>
  <div class="meta">
    <span class="sev">${h(finding.severity)}</span>
    <span class="cat">${h(finding.category)}</span>
    <span class="cat">${h(finding.scenario || '')}</span>
    <span class="cat">Status ${h(responseReceived?.status ?? finding.status ?? '?')}</span>
  </div>
  <div class="meta"><b>Endpoint:</b> <code>${h(finding.endpoint)}</code></div>
</div>

<div class="card">
  <div class="auth-line"><b>Operator:</b> ${h(auth?.operator || '(n/a)')} &nbsp;·&nbsp; <b>Engagement:</b> ${h(auth?.engagementRef || '(n/a)')} &nbsp;·&nbsp; <b>Attested:</b> ${h(auth?.attestedAt || '(n/a)')}</div>
  <div class="auth-line"><b>Target:</b> <code>${h(target?.url || '')}</code></div>
</div>

<h2>Detection signals</h2>
<div class="card signals">
  ${(finding.signals || []).map((s) => `<span>${h(s)}</span>`).join('') || '<i>(none)</i>'}
</div>

<h2>Request sent by the probe</h2>
<div class="card">
  <div class="label">Method / URL</div>
  <pre>${h(requestSent?.method || '')} ${h(requestSent?.url || '')}</pre>
  <div class="label" style="margin-top:10px">Headers</div>
  ${headersTable(requestSent?.headers)}
  ${requestSent?.body ? `<div class="label" style="margin-top:10px">Body</div><pre>${h(prettyJsonOrRaw(requestSent.body).slice(0, 2048))}</pre>` : ''}
  <div class="label" style="margin-top:10px">Mutation</div>
  <div>${h(finding.param || '')} <span class="cat">${h(finding.scenario || '')}</span></div>
  ${finding.payload ? `<div class="label" style="margin-top:8px">Payload value</div><pre>${h(String(finding.payload))}</pre>` : ''}
</div>

<h2>Response received</h2>
<div class="card">
  <div class="label">Status / redirect</div>
  <div><code>${h(responseReceived?.status ?? finding.status ?? '?')}</code>${responseReceived?.redirect ? ` → <code>${h(responseReceived.redirect)}</code>` : ''}</div>
  <div class="label" style="margin-top:10px">Response headers</div>
  ${headersTable(responseReceived?.headers || finding.responseHeaders)}
  <div class="label" style="margin-top:10px">Response body (first 4 KB)</div>
  <pre>${h(bodyPretty)}</pre>
</div>

${finding.poc ? `
<h2>Proof of concept</h2>
<div class="card">
  <div class="label">${h(finding.poc.kind?.toUpperCase() || 'POC')} — ${h(finding.poc.title || '')}</div>
  <div class="meta" style="margin:6px 0 10px">${h(finding.poc.description || '')}</div>
  <pre>${h(finding.poc.content || '')}</pre>
</div>` : ''}

<div class="stamp">
  Generated by SSRF Explorer on ${h(generatedAt)} — this evidence was produced with written authorization attested above.
</div>

</body></html>`;
}

module.exports = { buildEvidenceHtml };
