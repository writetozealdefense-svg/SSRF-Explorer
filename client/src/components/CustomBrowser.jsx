import React, { useEffect, useState } from 'react';

// Opens the customized browser window (separate BrowserWindow) routed through
// Burp. Auto-fills credentials once it detects a login form on the target.
export default function CustomBrowser({ target, authorized, reconStatus }) {
  const [state, setState] = useState('idle');
  const [err, setErr] = useState('');

  const launch = async () => {
    setErr(''); setState('launching');
    try {
      const r = await window.api.openBrowser({
        targetUrl: target.url,
        proxyHost: target.burp.proxyHost,
        proxyPort: target.burp.proxyPort,
        username: target.username,
        password: target.password,
        scopeHosts: target.scopeHosts || []
      });
      setState(r.reused ? 'reused' : 'open');
    } catch (e) {
      setErr(String(e.message || e));
      setState('idle');
    }
  };

  return (
    <div className="card">
      <h2>3 · Customized browser {!authorized && <span className="muted">(requires attestation)</span>}</h2>
      <p className="muted">
        Opens a separate stateful Chromium window routed through
        <span className="code"> {target.burp.proxyHost}:{target.burp.proxyPort}</span>.
        Session state persists per target. Every HTTP request is recorded in-process;
        when you <b>close the window</b>, the captured traffic is automatically fed
        into API enumeration and the view jumps to the Endpoints tab.
      </p>
      <div style={{ display: 'flex', gap: 10 }}>
        <button className="primary" onClick={launch} disabled={!authorized}>
          Launch browser
        </button>
        <span className="muted">Close the window to finish the crawl and enumerate.</span>
      </div>
      {state !== 'idle' && <div className="banner" style={{ marginTop: 12 }}>Browser: {state}</div>}
      {reconStatus && (
        <div className="banner" style={{ marginTop: 12 }}>
          <b>Auto-recon:</b>{' '}
          {reconStatus.phase === 'started' && <span>login detected → crawling…</span>}
          {reconStatus.phase === 'progress' && (
            <span>
              pages {reconStatus.pages || 0} · queue {reconStatus.queued || 0} · dict-hits {reconStatus.dictHits || 0}
              {reconStatus.lastUrl && <><br /><span className="code">{reconStatus.lastUrl}</span></>}
            </span>
          )}
          {reconStatus.phase === 'done' && (
            <span>finished — {reconStatus.stats?.crawled} URLs visited in {Math.round((reconStatus.stats?.elapsedMs || 0) / 1000)}s</span>
          )}
          {reconStatus.phase === 'error' && <span className="code">{reconStatus.message}</span>}
        </div>
      )}
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
    </div>
  );
}
