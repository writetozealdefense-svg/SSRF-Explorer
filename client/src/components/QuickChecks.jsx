import React, { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';

// Shows the focused Authorization + CORS findings with expandable PoCs.
// Auto-runs once when endpoints are populated; a manual re-run button is
// available too.
export default function QuickChecks({ target, authorized, endpoints, findings, setFindings, log }) {
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState(null);
  const [err, setErr] = useState('');
  const [expanded, setExpanded] = useState({});
  const [filter, setFilter] = useState('all');
  const [captured, setCaptured] = useState({});   // key -> { pngPath, htmlPath }
  const [capturing, setCapturing] = useState(null); // index currently capturing
  const [captureProgress, setCaptureProgress] = useState(null); // { done, total }
  const pollRef = useRef(null);
  const autoRanRef = useRef(false);

  const endpointByFinding = (finding) => {
    // finding.endpoint is "METHOD URL"; match on the templated url we stored.
    const [m, u] = String(finding.endpoint).split(' ');
    return (endpoints || []).find((ep) => ep.method === m && ep.url === u) || null;
  };

  const captureOne = async (finding, idx) => {
    const key = `${finding.category}-${idx}`;
    setCapturing(idx);
    try {
      const ep = endpointByFinding(finding);
      const { html } = await api.buildEvidence({
        finding,
        endpoint: ep,
        targetId: target._id,
        config: {
          timeoutSec: target.scan?.timeoutSec || 10,
          proxy: `http://${target.burp.proxyHost}:${target.burp.proxyPort}`
        }
      });
      const filename = `${finding.severity}-${finding.category}-${(finding.endpoint || '').replace(/\s+/g, '_')}-${idx}`;
      const result = await window.api.captureEvidence({
        html, filename,
        meta: { finding, endpointSummary: ep ? { method: ep.method, url: ep.url } : null, capturedAt: new Date().toISOString() }
      });
      if (!result.ok) throw new Error(result.error || 'capture failed');
      await api.recordEvidence({
        targetId: target._id, finding,
        pngPath: result.pngPath, htmlPath: result.htmlPath
      }).catch(() => {});
      setCaptured((prev) => ({ ...prev, [key]: result }));
      log(`[evidence] captured ${result.pngPath}`);
      return result;
    } catch (e) {
      log(`[evidence] capture failed: ${e.message}`);
      setErr(`Capture failed: ${e.message}`);
      return null;
    } finally {
      setCapturing(null);
    }
  };

  const captureAllConfirmed = async () => {
    if (!window.api?.captureEvidence) {
      setErr('Screenshot capture requires the Electron shell.');
      return;
    }
    const worklist = findings
      .map((f, i) => ({ f, i }))
      .filter(({ f }) => f.severity === 'Confirmed' || f.severity === 'Likely');
    if (worklist.length === 0) {
      log('[evidence] no Confirmed/Likely findings to capture');
      return;
    }
    setCaptureProgress({ done: 0, total: worklist.length });
    for (let idx = 0; idx < worklist.length; idx++) {
      const { f, i } = worklist[idx];
      await captureOne(f, i);
      setCaptureProgress({ done: idx + 1, total: worklist.length });
    }
    log(`[evidence] batch done — ${worklist.length} artifacts saved`);
    setTimeout(() => setCaptureProgress(null), 1500);
  };

  useEffect(() => () => pollRef.current && clearInterval(pollRef.current), []);

  const run = async () => {
    if (endpoints.length === 0) return;
    setErr(''); setBusy(true); setFindings([]);
    try {
      const { jobId } = await api.startQuickCheck({
        endpoints,
        targetId: target._id,
        config: {
          concurrency: target.scan?.concurrency || 5,
          timeoutSec: target.scan?.timeoutSec || 10,
          proxy: `http://${target.burp.proxyHost}:${target.burp.proxyPort}`
        }
      });
      log(`[quickcheck] job ${jobId} started`);
      pollRef.current = setInterval(async () => {
        try {
          const s = await api.quickCheckStatus(jobId);
          setStatus(s);
          if (s.finished) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setBusy(false);
            setFindings(s.findings || []);
            log(`[quickcheck] done — ${(s.findings || []).length} findings`);
          }
        } catch (e) { setErr(e.message); }
      }, 1500);
    } catch (e) { setErr(e.message); setBusy(false); }
  };

  useEffect(() => {
    if (autoRanRef.current) return;
    if (authorized && endpoints.length > 0 && findings.length === 0 && !busy) {
      autoRanRef.current = true;
      run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoints.length, authorized]);

  const visible = filter === 'all' ? findings : findings.filter((f) => f.category === filter);
  const copy = async (text) => {
    try { await navigator.clipboard.writeText(text); log('[quickcheck] PoC copied to clipboard'); }
    catch (e) { log(`[quickcheck] copy failed: ${e.message}`); }
  };

  return (
    <div>
      <div className="card">
        <h2>Quick checks · Authorization + CORS</h2>
        <p className="muted">
          For every endpoint that carries an auth marker, we verify the server actually requires it.
          For every endpoint we send crafted Origin headers to detect CORS reflection / null-origin /
          wildcard-with-credentials. Each positive finding ships with a ready-to-run PoC (<b>curl</b>
          for auth, <b>HTML</b> for CORS).
        </p>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button className="primary" onClick={run} disabled={busy || !authorized || endpoints.length === 0}>
            {busy ? 'Running...' : 'Re-run quick checks'}
          </button>
          {status && !status.finished && (
            <span className="muted">Progress: {status.done}/{status.total || '?'}</span>
          )}
          <button
            className="secondary"
            onClick={captureAllConfirmed}
            disabled={findings.length === 0 || !!captureProgress}
            title="Re-run each Confirmed/Likely finding and save a PNG screenshot of the evidence page"
          >
            {captureProgress
              ? `Capturing ${captureProgress.done}/${captureProgress.total}...`
              : 'Capture all Confirmed/Likely → PNG'}
          </button>
          <span style={{ flex: 1 }} />
          <label className="muted" style={{ margin: 0 }}>Filter</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 240 }}>
            <option value="all">All</option>
            <option value="AUTHZ_AuthStrip">Auth — stripped headers</option>
            <option value="AUTHZ_InvalidToken">Auth — invalid token</option>
            <option value="CORS_Misconfig">CORS misconfiguration</option>
          </select>
        </div>
        {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Findings ({findings.length})</h3>
        {visible.length === 0 ? (
          <p className="muted">
            {findings.length === 0 && !busy
              ? 'No authorization / CORS findings. Run the full API scan for the rest of OWASP API Top 10.'
              : 'Nothing in this filter.'}
          </p>
        ) : (
          <div style={{ maxHeight: 620, overflow: 'auto' }}>
            {visible.map((f, i) => {
              const key = `${f.category}-${i}`;
              const open = !!expanded[key];
              return (
                <div key={key} style={{ borderTop: '1px solid #242a35', paddingTop: 10, marginTop: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span className={`tag sev-${f.severity}`}>{f.severity}</span>
                    <span className="tag">{f.category}</span>
                    <span className="code" style={{ flex: 1 }}>{f.endpoint}</span>
                    <span className="muted">status {f.status}</span>
                    <button className="secondary" onClick={() => setExpanded((p) => ({ ...p, [key]: !open }))}>
                      {open ? 'Hide' : 'View PoC'}
                    </button>
                    <button
                      className="secondary"
                      onClick={() => captureOne(f, i)}
                      disabled={capturing === i}
                      title="Re-run the probe, render the evidence page, save a PNG screenshot"
                    >
                      {capturing === i ? 'Capturing...' : (captured[key] ? 'Re-capture' : 'Capture evidence')}
                    </button>
                  </div>
                  {captured[key] && (
                    <div className="muted" style={{ marginTop: 4, fontSize: 11 }}>
                      Saved: <span className="code">{captured[key].pngPath}</span>
                    </div>
                  )}
                  <div className="muted" style={{ marginTop: 4 }}>
                    {f.param} {f.scenario && <span className="tag">{f.scenario}</span>}
                    {(f.signals || []).map((s, j) => <span key={j} className="tag">{s}</span>)}
                  </div>
                  {open && (
                    <div style={{ marginTop: 10 }}>
                      {f.poc ? (
                        <>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <b>{f.poc.title}</b>
                            <span className="tag">{f.poc.kind}</span>
                            <span style={{ flex: 1 }} />
                            <button className="secondary" onClick={() => copy(f.poc.content)}>Copy PoC</button>
                          </div>
                          <p className="muted" style={{ margin: '6px 0' }}>{f.poc.description}</p>
                          <pre style={{
                            background: '#0e1014', padding: 12, borderRadius: 4,
                            maxHeight: 320, overflow: 'auto', fontSize: 12,
                            fontFamily: 'ui-monospace, Consolas, monospace', color: '#c2cad8',
                            whiteSpace: 'pre-wrap', wordBreak: 'break-all'
                          }}>{f.poc.content}</pre>
                        </>
                      ) : (
                        <pre style={{
                          background: '#0e1014', padding: 12, borderRadius: 4,
                          maxHeight: 220, overflow: 'auto', fontSize: 12, color: '#9db0c7'
                        }}>{f.bodyExcerpt || '(no body excerpt)'}</pre>
                      )}
                      {f.responseHeaders && Object.keys(f.responseHeaders).length > 0 && (
                        <details style={{ marginTop: 8 }}>
                          <summary className="muted">Response headers</summary>
                          <pre style={{
                            background: '#0e1014', padding: 12, borderRadius: 4, marginTop: 6,
                            maxHeight: 180, overflow: 'auto', fontSize: 12, color: '#9db0c7'
                          }}>
                            {Object.entries(f.responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}
                          </pre>
                        </details>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
