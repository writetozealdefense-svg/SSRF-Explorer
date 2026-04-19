import React, { useState } from 'react';

// Opens the customized browser window (separate BrowserWindow) routed through
// Burp. Auto-fills credentials once it detects a login form on the target.
export default function CustomBrowser({ target, authorized }) {
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
        password: target.password
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
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
    </div>
  );
}
