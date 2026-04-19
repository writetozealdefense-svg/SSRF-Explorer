import React, { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';

// Renders the OWASP API Top 10 scan view. SSRF (API7) is one of eight
// categories tested against every enumerated endpoint.
export default function SsrfResults({ target, authorized, endpoints, findings, setFindings, log }) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState(null);
  const [err, setErr] = useState('');
  const [categories, setCategories] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [filter, setFilter] = useState('all');
  const pollRef = useRef(null);

  useEffect(() => () => pollRef.current && clearInterval(pollRef.current), []);

  useEffect(() => {
    api.categories().then((cats) => {
      setCategories(cats);
      setSelected(new Set(cats.map((c) => c.id)));
    }).catch((e) => setErr(e.message));
  }, []);

  const toggle = (id) => setSelected((prev) => {
    const n = new Set(prev);
    n.has(id) ? n.delete(id) : n.add(id);
    return n;
  });

  const run = async () => {
    if (endpoints.length === 0) return;
    const chosen = [...selected];
    if (chosen.length === 0) { setErr('Pick at least one category.'); return; }
    const ok = window.confirm(
      `About to run ${chosen.length} OWASP API category test(s) against ${endpoints.length} endpoints. ` +
      `Scope: ${(target.scopeHosts || []).join(', ')}. Proceed?`
    );
    if (!ok) return;
    setErr(''); setBusy(true); setFindings([]);
    try {
      const { jobId } = await api.startScan({
        endpoints,
        targetId: target._id,
        categories: chosen,
        config: {
          concurrency: target.scan.concurrency,
          timeoutSec: target.scan.timeoutSec,
          oobCanary: target.scan.oobCanary,
          proxy: `http://${target.burp.proxyHost}:${target.burp.proxyPort}`
        }
      });
      log(`[scan] job ${jobId} started — ${chosen.length} categories`);
      pollRef.current = setInterval(async () => {
        try {
          const s = await api.scanStatus(jobId);
          setStatus(s);
          if (s.finished) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setBusy(false);
            setFindings(s.findings);
            log(`[scan] done — ${s.findings.length} findings`);
          }
        } catch (e) { setErr(e.message); }
      }, 1500);
    } catch (e) { setErr(e.message); setBusy(false); }
  };

  const visible = filter === 'all' ? findings : findings.filter((f) => f.category === filter);
  const countBy = (cat) => findings.filter((f) => f.category === cat).length;

  return (
    <div>
      <div className="card">
        <h2>5 · OWASP API Top 10 scan</h2>
        <p className="muted">
          Every enumerated endpoint is probed. Probes run via PowerShell
          <span className="code"> Invoke-WebRequest</span> through your Burp proxy, reusing the
          auth headers and cookies captured from your browser session.
        </p>
        <div className="grid2" style={{ marginTop: 10 }}>
          {categories.map((c) => (
            <label key={c.id} className="muted" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input
                type="checkbox"
                checked={selected.has(c.id)}
                onChange={() => toggle(c.id)}
                style={{ width: 'auto' }}
              />
              <span className="tag">{c.number}</span>
              <span>{c.name}</span>
            </label>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 14 }}>
          <button className="primary" onClick={run} disabled={busy || !authorized || endpoints.length === 0}>
            {busy ? 'Scanning...' : `Run scan (${endpoints.length} endpoints × ${selected.size} categories)`}
          </button>
          {status && !status.finished && (
            <span className="muted">Progress: {status.done}/{status.total || '?'}</span>
          )}
        </div>
        {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <h3 style={{ margin: 0, flex: 1 }}>Findings ({findings.length})</h3>
          <label className="muted" style={{ margin: 0 }}>Filter</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 320 }}>
            <option value="all">All categories</option>
            {categories.map((c) => (
              <option key={c.id} value={c.id}>
                {c.number} — {c.name} ({countBy(c.id)})
              </option>
            ))}
          </select>
        </div>
        {visible.length === 0 ? (
          <p className="muted" style={{ marginTop: 10 }}>No findings in this view.</p>
        ) : (
          <div style={{ maxHeight: 520, overflow: 'auto', marginTop: 10 }}>
            <table>
              <thead>
                <tr>
                  <th>Sev</th><th>Category</th><th>Endpoint</th><th>Param / Mutation</th>
                  <th>Payload</th><th>Status</th><th>Signals</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((f, i) => (
                  <tr key={i}>
                    <td><span className={`tag sev-${f.severity}`}>{f.severity}</span></td>
                    <td><span className="tag">{f.category}</span></td>
                    <td className="code">{f.endpoint}</td>
                    <td className="code">{f.param}</td>
                    <td className="code">{f.payload}</td>
                    <td>{f.status}</td>
                    <td>{(f.signals || []).map((s, j) => <span className="tag" key={j}>{s}</span>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
