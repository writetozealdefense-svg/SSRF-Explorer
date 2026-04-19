import React, { useState } from 'react';
import { api } from '../api.js';

export default function ReportView({ target, endpoints, findings }) {
  const [saved, setSaved] = useState(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setErr(''); setBusy(true);
    try {
      const r = await api.report({ targetId: target._id, endpoints, findings });
      setSaved(r);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div className="card">
      <h2>6 · Report</h2>
      <p className="muted">Writes HTML + JSON into <span className="code">./reports/</span>.</p>
      <button className="primary" onClick={save} disabled={busy}>Generate report</button>
      {saved && (
        <div className="banner" style={{ marginTop: 12 }}>
          Saved: <div className="code">{saved.htmlPath}</div>
          <div className="code">{saved.jsonPath}</div>
        </div>
      )}
      {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
    </div>
  );
}
