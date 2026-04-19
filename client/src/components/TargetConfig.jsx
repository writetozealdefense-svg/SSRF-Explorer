import React, { useState } from 'react';
import { api } from '../api.js';

const DEFAULT = {
  url: '',
  username: '',
  password: '',
  scopeHosts: '',
  burp: { proxyHost: '127.0.0.1', proxyPort: 8080, restUrl: '', restKey: '', historyPath: '' },
  scan: { concurrency: 5, timeoutSec: 10, oobCanary: '' }
};

export default function TargetConfig({ onSaved, current }) {
  const [form, setForm] = useState(current || DEFAULT);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const set = (path, v) => {
    setForm((p) => {
      const next = structuredClone(p);
      const parts = path.split('.');
      let cur = next;
      for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]];
      cur[parts.at(-1)] = v;
      return next;
    });
  };

  const save = async (e) => {
    e.preventDefault();
    setErr(''); setBusy(true);
    try {
      const hosts = (form.scopeHosts || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (!form.url) throw new Error('Target URL required.');
      if (!hosts.length) {
        try { hosts.push(new URL(form.url).host); } catch {}
      }
      const saved = await api.createTarget({ ...form, scopeHosts: hosts });
      onSaved(saved);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <form className="card" onSubmit={save}>
      <h2>1 · Target + Burp + Scan</h2>
      <div className="row">
        <div>
          <label>Target URL</label>
          <input value={form.url} onChange={(e) => set('url', e.target.value)} placeholder="https://target.example.com/login" />
        </div>
        <div>
          <label>In-scope hosts (comma-separated)</label>
          <input value={form.scopeHosts} onChange={(e) => set('scopeHosts', e.target.value)} placeholder="target.example.com, api.example.com" />
        </div>
      </div>
      <div className="row">
        <div>
          <label>Username (for stateful browser auto-login)</label>
          <input value={form.username} onChange={(e) => set('username', e.target.value)} />
        </div>
        <div>
          <label>Password</label>
          <input type="password" value={form.password} onChange={(e) => set('password', e.target.value)} />
        </div>
      </div>

      <h3 style={{ marginTop: 18 }}>Burp proxy</h3>
      <div className="row">
        <div>
          <label>Proxy host</label>
          <input value={form.burp.proxyHost} onChange={(e) => set('burp.proxyHost', e.target.value)} />
        </div>
        <div>
          <label>Proxy port</label>
          <input type="number" value={form.burp.proxyPort} onChange={(e) => set('burp.proxyPort', Number(e.target.value))} />
        </div>
      </div>
      <div className="row">
        <div>
          <label>REST API URL (optional)</label>
          <input value={form.burp.restUrl} onChange={(e) => set('burp.restUrl', e.target.value)} placeholder="http://127.0.0.1:1337/v0.1/" />
        </div>
        <div>
          <label>REST API key</label>
          <input type="password" value={form.burp.restKey} onChange={(e) => set('burp.restKey', e.target.value)} />
        </div>
      </div>
      <label>Proxy history XML path (fallback)</label>
      <input value={form.burp.historyPath} onChange={(e) => set('burp.historyPath', e.target.value)} placeholder="C:\\path\\to\\burp-history.xml" />

      <h3 style={{ marginTop: 18 }}>Scan</h3>
      <div className="row">
        <div>
          <label>Concurrency</label>
          <input type="number" min="1" max="32" value={form.scan.concurrency} onChange={(e) => set('scan.concurrency', Number(e.target.value))} />
        </div>
        <div>
          <label>Request timeout (s)</label>
          <input type="number" min="1" max="120" value={form.scan.timeoutSec} onChange={(e) => set('scan.timeoutSec', Number(e.target.value))} />
        </div>
      </div>
      <label>OOB canary URL (Interactsh / Collaborator — optional)</label>
      <input value={form.scan.oobCanary} onChange={(e) => set('scan.oobCanary', e.target.value)} placeholder="https://xxxx.oast.fun" />

      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      <div style={{ marginTop: 14 }}>
        <button className="primary" type="submit" disabled={busy}>Save target</button>
      </div>
    </form>
  );
}
