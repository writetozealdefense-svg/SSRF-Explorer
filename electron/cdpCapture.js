// Chrome DevTools Protocol-based HTTP capture.
//
// Unlike session.webRequest, CDP gives us the *response body* in addition to
// status and headers — essential for "complete recon" output. We attach to a
// webContents, enable the Network domain, and mirror every request/response
// pair into a shared partition-keyed store.

function safeUrl(url) {
  try { return new URL(url); } catch { return null; }
}

function attachCdpCapture(webContents, store) {
  const dbg = webContents.debugger;
  try {
    if (!dbg.isAttached()) dbg.attach('1.3');
  } catch (e) {
    return { ok: false, error: e.message };
  }
  const wcId = webContents.id;
  const keyOf = (requestId) => `${wcId}:${requestId}`;

  dbg.on('message', async (_event, method, params) => {
    try {
      if (method === 'Network.requestWillBeSent') {
        const { requestId, request } = params;
        if (!/^https?:/i.test(request.url)) return;
        const u = safeUrl(request.url);
        store.set(keyOf(requestId), {
          method: request.method,
          url: request.url,
          host: u ? u.hostname : '',
          path: u ? u.pathname : '',
          headers: request.headers || {},
          body: request.postData || '',
          status: null,
          responseLength: 0,
          responseHeaders: {},
          responseBody: ''
        });
      } else if (method === 'Network.responseReceived') {
        const r = store.get(keyOf(params.requestId));
        if (!r) return;
        r.status = (params.response && params.response.status) || null;
        r.responseHeaders = (params.response && params.response.headers) || {};
      } else if (method === 'Network.loadingFinished') {
        const r = store.get(keyOf(params.requestId));
        if (!r) return;
        try {
          const res = await dbg.sendCommand('Network.getResponseBody', {
            requestId: params.requestId
          });
          const text = res.base64Encoded
            ? Buffer.from(res.body || '', 'base64').toString('utf8')
            : (res.body || '');
          // Cap any one response body at 64 KB — anything bigger bloats memory
          // and rarely adds signal for enumeration / reporting.
          r.responseBody = text.slice(0, 65536);
          r.responseLength = text.length;
        } catch {
          // Some requests (e.g. redirects, 304s, blocked) have no fetchable
          // body. Silent; we still have status + headers.
        }
      }
    } catch {
      // Debugger messages arrive asynchronously; swallow all to keep capture
      // resilient even if one request errors.
    }
  });

  try { dbg.sendCommand('Network.enable'); } catch {}

  return { ok: true };
}

module.exports = { attachCdpCapture };
