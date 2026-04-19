// Best-effort Burp REST API client. Falls back to XML parsing if the build
// of Burp you're running doesn't expose proxy history over REST.

const { parseRequestBytes } = require('./burpParser');

async function fetchHistoryFromRest(baseUrl, apiKey, scopeHosts = []) {
  const paths = ['proxy/history', 'history'];
  const base = baseUrl.replace(/\/?$/, '/');
  let lastErr;
  for (const p of paths) {
    const url = base + p + (scopeHosts.length ? `?scope=${encodeURIComponent(scopeHosts.join(','))}` : '');
    try {
      const r = await fetch(url, {
        headers: apiKey ? { 'X-API-Key': apiKey } : {}
      });
      if (!r.ok) continue;
      const ct = r.headers.get('content-type') || '';
      if (!ct.includes('application/json')) continue;
      const data = await r.json();
      const items = Array.isArray(data) ? data : data.items || [];
      return items.map((it) => {
        const raw = it.request || it.raw_request || '';
        const parsed = parseRequestBytes(raw);
        const u = it.url || it.request_url || '';
        return {
          method: it.method || parsed.method,
          url: u,
          host: (() => {
            try { return new URL(u).host; } catch { return ''; }
          })(),
          path: parsed.path,
          headers: parsed.headers,
          body: parsed.body,
          status: it.status ?? null,
          responseLength: Number(it.response_length) || 0,
          raw
        };
      });
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`Burp REST unreachable (${lastErr?.message || 'no matching endpoint'})`);
}

module.exports = { fetchHistoryFromRest };
