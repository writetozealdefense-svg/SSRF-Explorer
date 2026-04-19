import React, { useMemo, useState } from 'react';

// Dedicated view that shows, per endpoint, exactly which vulnerabilities are
// worth exploring — with the reasoning the server used to decide, the exact
// probes it would fire, the impact if the finding is real, and a minimal PoC
// snippet. Zero network traffic is generated here; all of this was computed
// server-side during enumeration and is attached to each endpoint as
// `attackSurface: [...]`.

const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 };
const SEV_CLASS = { high: 'sev-Confirmed', medium: 'sev-Likely', low: 'sev-Possible' };

function countByCategory(endpoints) {
  const m = new Map();
  for (const ep of endpoints || []) {
    for (const s of ep.attackSurface || []) {
      const key = s.id;
      const prev = m.get(key) || { id: s.id, title: s.title, category: s.category, total: 0, high: 0, medium: 0, low: 0 };
      prev.total++;
      prev[s.confidence] = (prev[s.confidence] || 0) + 1;
      m.set(key, prev);
    }
  }
  return [...m.values()].sort((a, b) =>
    (b.high - a.high) || (b.medium - a.medium) || (b.total - a.total)
  );
}

export default function AttackSurface({ endpoints, log, onJumpToScan }) {
  const [filter, setFilter] = useState('all');
  const [confidenceFilter, setConfidenceFilter] = useState('all');
  const [expanded, setExpanded] = useState({});

  const summary = useMemo(() => countByCategory(endpoints), [endpoints]);

  const visibleEndpoints = useMemo(() => {
    return (endpoints || [])
      .map((ep) => {
        const surfaces = (ep.attackSurface || []).filter((s) => {
          if (filter !== 'all' && s.id !== filter) return false;
          if (confidenceFilter !== 'all' && s.confidence !== confidenceFilter) return false;
          return true;
        });
        return { ...ep, surfaces };
      })
      .filter((ep) => ep.surfaces.length > 0);
  }, [endpoints, filter, confidenceFilter]);

  const copy = async (text) => {
    try { await navigator.clipboard.writeText(text); log && log('[surface] PoC copied'); }
    catch (e) { log && log(`[surface] copy failed: ${e.message}`); }
  };

  return (
    <div>
      <div className="card">
        <h2>Attack surface · what to try per endpoint</h2>
        <p className="muted">
          Static analysis of the enumerated traffic — no probes fired yet. For each endpoint
          the app lists every OWASP API Top 10 category worth exploring, <b>why</b>, what
          probes would confirm it, and a minimal PoC you can paste. Use this to pick a focused
          scan instead of running everything.
        </p>

        {summary.length === 0 ? (
          <p className="muted">No endpoints loaded yet.</p>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
            {summary.map((s) => (
              <button
                key={s.id}
                className={filter === s.id ? 'primary' : 'secondary'}
                onClick={() => setFilter(filter === s.id ? 'all' : s.id)}
                title={s.title}
                style={{ fontSize: 12 }}
              >
                {s.category} · {s.title}
                {' '}
                <span className="tag sev-Confirmed">H:{s.high || 0}</span>
                <span className="tag sev-Likely">M:{s.medium || 0}</span>
                <span className="tag sev-Possible">L:{s.low || 0}</span>
              </button>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 12 }}>
          <label className="muted" style={{ margin: 0 }}>Confidence:</label>
          <select value={confidenceFilter} onChange={(e) => setConfidenceFilter(e.target.value)}>
            <option value="all">all</option>
            <option value="high">high only</option>
            <option value="medium">medium+</option>
            <option value="low">low only</option>
          </select>
          <span style={{ flex: 1 }} />
          <button className="secondary" onClick={() => { setFilter('all'); setConfidenceFilter('all'); }}>
            Reset filters
          </button>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>
          Endpoints with testable surface ({visibleEndpoints.length})
          {filter !== 'all' && <span className="muted" style={{ fontSize: 12, marginLeft: 8 }}>· filtered by {filter}</span>}
        </h3>
        {visibleEndpoints.length === 0 ? (
          <p className="muted">No endpoints match the current filter.</p>
        ) : (
          <div style={{ maxHeight: 680, overflow: 'auto' }}>
            {visibleEndpoints.map((ep, i) => (
              <div key={i} style={{ borderTop: '1px solid #242a35', paddingTop: 12, marginTop: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span className="code" style={{ fontSize: 13 }}><b>{ep.method}</b> {ep.url}</span>
                  <span style={{ flex: 1 }} />
                  {(ep.surfaces || [])
                    .slice()
                    .sort((a, b) => CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence])
                    .map((s, j) => (
                      <span
                        key={j}
                        className={`tag ${SEV_CLASS[s.confidence] || ''}`}
                        title={s.title}
                      >
                        {s.category} · {s.confidence}
                      </span>
                    ))}
                </div>

                {ep.surfaces.map((s, j) => {
                  const key = `${i}-${s.id}`;
                  const open = !!expanded[key];
                  return (
                    <div key={key} style={{
                      marginTop: 8, padding: 10, background: '#1a1d24', borderRadius: 4,
                      borderLeft: `3px solid ${s.confidence === 'high' ? '#ff7070' : s.confidence === 'medium' ? '#ffb84c' : '#5e8dd6'}`
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span className={`tag ${SEV_CLASS[s.confidence]}`}>{s.confidence}</span>
                        <b>{s.category}</b> <span>{s.title}</span>
                        <span style={{ flex: 1 }} />
                        <button
                          className="secondary"
                          onClick={() => setExpanded((p) => ({ ...p, [key]: !open }))}
                        >
                          {open ? 'Collapse' : 'Details'}
                        </button>
                      </div>
                      <div className="muted" style={{ marginTop: 6 }}>{s.rationale}</div>
                      {open && (
                        <div style={{ marginTop: 8 }}>
                          <div>
                            <b style={{ fontSize: 12 }}>Probes this would fire:</b>
                            <ul style={{ margin: '4px 0 0 18px', color: '#b0bacb' }}>
                              {(s.probes || []).map((p, k) => <li key={k} className="code" style={{ fontSize: 12 }}>{p}</li>)}
                            </ul>
                          </div>
                          {s.impact && (
                            <div style={{ marginTop: 8 }}>
                              <b style={{ fontSize: 12 }}>Impact if confirmed:</b>
                              <div className="muted" style={{ marginTop: 2 }}>{s.impact}</div>
                            </div>
                          )}
                          {s.poc && (
                            <div style={{ marginTop: 8 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <b style={{ fontSize: 12 }}>Quick PoC:</b>
                                <span style={{ flex: 1 }} />
                                <button className="secondary" onClick={() => copy(s.poc)}>Copy</button>
                              </div>
                              <pre style={{
                                background: '#0e1014', padding: 10, borderRadius: 4, marginTop: 4,
                                fontSize: 12, color: '#c2cad8', overflow: 'auto',
                                whiteSpace: 'pre-wrap', wordBreak: 'break-all'
                              }}>{s.poc}</pre>
                            </div>
                          )}
                          {onJumpToScan && (
                            <div style={{ marginTop: 8 }}>
                              <button className="primary" onClick={() => onJumpToScan(s.id)}>
                                Run the full {s.category} scan →
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
