import React, { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';

// Prefers browser-captured traffic over Burp sources. Auto-runs the loader
// whenever there's new data and no endpoints yet, so the user never has to
// click unless they actually want to re-enumerate.
export default function EndpointsView({ target, authorized, endpoints, setEndpoints, capturedRequests, log }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [stats, setStats] = useState(null);
  const [ignoreScope, setIgnoreScope] = useState(false);
  const autoRanRef = useRef(false);

  const hasCaptured = (capturedRequests || []).length > 0;
  const hasRest = !!(target.burp && target.burp.restUrl);
  const hasXml  = !!(target.burp && target.burp.historyPath);
  const noSource = !hasCaptured && !hasRest && !hasXml;

  const load = async (opts = {}) => {
    setErr(''); setBusy(true); setStats(null);
    try {
      let requests = [];
      let sourceLabel = '';

      if (hasCaptured) {
        requests = capturedRequests;
        sourceLabel = `browser-captured (${requests.length} requests)`;
      } else if (hasRest || hasXml) {
        const burp = await api.loadBurp({
          historyPath: target.burp.historyPath || null,
          restUrl: target.burp.restUrl || null,
          restKey: target.burp.restKey || null,
          scopeHosts: target.scopeHosts
        });
        requests = burp.requests;
        sourceLabel = hasRest ? `Burp REST (${requests.length} req)` : `Burp XML (${requests.length} req)`;
      } else {
        throw new Error('No traffic source. Launch the customized browser (step 3) or set a Burp source on Target.');
      }

      log(`[source] ${sourceLabel}`);
      const scopeHosts = (opts.ignoreScope || ignoreScope) ? [] : (target.scopeHosts || []);
      const enumRes = await api.enumerate({ requests, scopeHosts, targetId: target._id });
      setStats(enumRes.stats || null);
      setEndpoints(enumRes.endpoints);
      log(`[enum] ${enumRes.count} endpoints · ${enumRes.candidates} candidates · stats=${JSON.stringify(enumRes.stats)}`);
    } catch (e) {
      setErr(e.message);
      log(`[err] ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  // Auto-run exactly once on mount when captured data is waiting and we
  // haven't produced endpoints yet. Prevents the "captured: 66, table empty"
  // limbo state that required clicking the button.
  useEffect(() => {
    if (autoRanRef.current) return;
    if (authorized && hasCaptured && endpoints.length === 0 && !busy) {
      autoRanRef.current = true;
      load();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const zeroAfterFilter =
    stats && stats.input > 0 && endpoints.length === 0 && stats.outOfScope === stats.input;

  return (
    <div>
      <div className="card">
        <h2>4 · API enumeration</h2>
        <p className="muted">
          Sources tried in order: <b>browser capture</b> → <b>Burp REST</b> → <b>Burp XML</b>.
          Deduped by <span className="code">(method, host, path-template, param-set)</span> and scored for SSRF candidacy.
        </p>
        <div style={{ margin: '6px 0 12px' }}>
          <span className={`tag ${hasCaptured ? 'sev-Likely' : ''}`}>captured: {hasCaptured ? capturedRequests.length : 0}</span>
          <span className={`tag ${hasRest ? 'sev-Possible' : ''}`}>Burp REST: {hasRest ? 'on' : 'off'}</span>
          <span className={`tag ${hasXml ? 'sev-Possible' : ''}`}>Burp XML: {hasXml ? 'on' : 'off'}</span>
          <span className="tag">scope: {(target.scopeHosts || []).join(', ') || '(none)'}</span>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button className="primary" onClick={() => load()} disabled={busy || !authorized || noSource}>
            {busy ? 'Loading...' : 'Load traffic + enumerate'}
          </button>
          <label className="muted" style={{ margin: 0 }}>
            <input type="checkbox" style={{ width: 'auto', marginRight: 4 }}
              checked={ignoreScope} onChange={(e) => setIgnoreScope(e.target.checked)} />
            ignore scope filter
          </label>
        </div>
        {noSource && (
          <div className="banner" style={{ marginTop: 12 }}>
            No traffic yet. Go to <b>step 3</b>, click <b>Launch browser</b>, crawl the app for a minute, then close the window.
          </div>
        )}
        {stats && (
          <div className="muted" style={{ marginTop: 10 }}>
            <span className="tag">input: {stats.input}</span>
            <span className="tag">out-of-scope: {stats.outOfScope}</span>
            <span className="tag">static assets: {stats.staticAssets}</span>
            <span className="tag">deduped: {stats.deduped}</span>
            <span className="tag">unique endpoints: {endpoints.length}</span>
          </div>
        )}
        {zeroAfterFilter && (
          <div className="banner" style={{ marginTop: 12 }}>
            All {stats.input} requests were filtered out of scope. Your scope is
            <span className="code"> {(target.scopeHosts || []).join(', ') || '(empty)'}</span>
            but the browser talked to different hosts. Tick <b>ignore scope filter</b> above and re-enumerate,
            or edit the scope on the Target tab.
          </div>
        )}
        {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Endpoints ({endpoints.length})</h3>
        {endpoints.length === 0 ? (
          <p className="muted">Nothing loaded yet.</p>
        ) : (
          <div style={{ maxHeight: 520, overflow: 'auto' }}>
            <table>
              <thead>
                <tr><th>Method</th><th>URL</th><th>Params</th><th>Score</th><th>Candidate</th></tr>
              </thead>
              <tbody>
                {endpoints.map((e, i) => (
                  <tr key={i}>
                    <td className="code">{e.method}</td>
                    <td className="code">{e.url}</td>
                    <td>{(e.params || []).map((p, j) => <span key={j} className="tag">{p.name}@{p.location}</span>)}</td>
                    <td>{e.score}</td>
                    <td>{e.score > 0 ? <span className="tag sev-Possible">YES</span> : ''}</td>
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
