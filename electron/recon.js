// Automatic recon after login.
//
// Runs in a hidden BrowserWindow that shares the user's session (cookies +
// localStorage) with the visible customized browser. Two stages happen in
// parallel via the same queue:
//
//   1. DOM spider — extract <a href> and <form action> from each loaded page;
//      BFS-visit same-scope links up to maxPages.
//   2. Dictionary fuzz — seed the queue with a wordlist of common API /
//      admin / debug paths.
//
// Every request the hidden window makes flows through the shared session, so
// cookies from login are attached, and through the Burp proxy for visibility.
// CDP captures request and response bodies into the partition's traffic store.

const { BrowserWindow } = require('electron');
const path = require('path');

const { attachCdpCapture } = require('./cdpCapture');

// Small, deliberate dictionary — meant for finding hidden surface, not for
// noise. Full wordlists belong in dedicated tools like ffuf.
const DICT_WORDLIST = [
  '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
  '/admin', '/admin/', '/administrator', '/admin/login',
  '/api', '/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/api/internal/', '/api/private/',
  '/swagger', '/swagger/', '/swagger.json', '/swagger-ui.html', '/swagger-ui/',
  '/api-docs', '/api-docs/', '/openapi.json', '/openapi.yaml', '/v3/api-docs',
  '/graphql', '/graphiql', '/playground',
  '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
  '/actuator/mappings', '/actuator/beans', '/actuator/httptrace',
  '/debug', '/debug/', '/health', '/healthz', '/status', '/metrics', '/ping',
  '/.env', '/.git/config', '/.git/HEAD', '/.DS_Store',
  '/backup', '/backup.zip', '/.bak',
  '/login', '/logout', '/register', '/signup', '/signin',
  '/users', '/user', '/me', '/profile', '/account', '/settings',
  '/dashboard', '/internal', '/private',
  '/phpinfo.php', '/server-status', '/server-info', '/config.json', '/config'
];

function inScope(urlStr, scopeHosts) {
  try {
    const host = new URL(urlStr).hostname.toLowerCase();
    if (!scopeHosts || scopeHosts.length === 0) return true;
    return scopeHosts.some((raw) => {
      const s = (raw || '').toLowerCase().split(':')[0];
      return host === s || host.endsWith('.' + s);
    });
  } catch { return false; }
}

function normalize(urlStr) {
  try {
    const u = new URL(urlStr);
    u.hash = '';
    return u.toString();
  } catch { return urlStr; }
}

async function runRecon({ partition, startUrl, scopeHosts, store, onProgress, onLog }, opts = {}) {
  const maxPages = opts.maxPages || 60;
  const maxMs = opts.maxMs || 240_000;
  const perPageSettleMs = opts.perPageSettleMs || 700;

  const log = (m) => { onLog && onLog(m); };

  const reconWin = new BrowserWindow({
    show: false,
    webPreferences: {
      partition,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  const cdp = attachCdpCapture(reconWin.webContents, store);
  if (!cdp.ok) log(`[recon] CDP attach failed: ${cdp.error}`);

  // Seed the queue with the starting URL and every dictionary path under it.
  const queue = [];
  const visited = new Set();
  const pushed = new Set();

  const push = (u) => {
    const norm = normalize(u);
    if (!norm || pushed.has(norm) || !inScope(norm, scopeHosts)) return;
    pushed.add(norm);
    queue.push(norm);
  };

  push(startUrl);
  for (const p of DICT_WORDLIST) {
    try { push(new URL(p, startUrl).toString()); } catch {}
  }

  const start = Date.now();
  let pagesCrawled = 0;
  let dictionaryHits = 0;

  while (queue.length && visited.size < maxPages && Date.now() - start < maxMs) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    const isDict = DICT_WORDLIST.some((p) => url.endsWith(p) || url.includes(p + '/') || url.includes(p + '?'));

    try {
      await reconWin.loadURL(url, { timeout: 15000 });
      await new Promise((r) => setTimeout(r, perPageSettleMs));

      // Harvest links for further crawling.
      const links = await reconWin.webContents.executeJavaScript(`
        (() => {
          const out = new Set();
          for (const el of document.querySelectorAll('a[href], form[action], link[rel="canonical"], [data-href]')) {
            const v = el.href || el.action || el.getAttribute('data-href');
            if (v) out.add(v);
          }
          return Array.from(out);
        })()
      `).catch(() => []);

      for (const link of links) {
        try { push(new URL(link, url).toString()); } catch {}
      }
      pagesCrawled++;
      if (isDict) dictionaryHits++;
    } catch (e) {
      // Network / navigation failure on this URL. Continue; CDP may have
      // captured the request+error anyway.
    }

    onProgress && onProgress({
      crawled: visited.size,
      queued: queue.length,
      pages: pagesCrawled,
      dictHits: dictionaryHits,
      lastUrl: url
    });
  }

  log(`[recon] done — ${visited.size} URLs visited, ${queue.length} skipped (cap/timeout)`);

  try { reconWin.webContents.debugger.detach(); } catch {}
  try { reconWin.close(); } catch {}

  return {
    visited: [...visited],
    stats: {
      crawled: visited.size,
      remaining: queue.length,
      dictionaryHits,
      elapsedMs: Date.now() - start
    }
  };
}

module.exports = { runRecon, DICT_WORDLIST };
