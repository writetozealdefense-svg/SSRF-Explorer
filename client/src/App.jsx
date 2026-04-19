import React, { useEffect, useRef, useState } from 'react';
import { api } from './api.js';
import LoginView from './components/LoginView.jsx';
import TargetConfig from './components/TargetConfig.jsx';
import AuthGate from './components/AuthGate.jsx';
import CustomBrowser from './components/CustomBrowser.jsx';
import EndpointsView from './components/EndpointsView.jsx';
import SsrfResults from './components/SsrfResults.jsx';
import QuickChecks from './components/QuickChecks.jsx';
import AttackSurface from './components/AttackSurface.jsx';
import ReportView from './components/ReportView.jsx';

const TABS = [
  { id: 'target',   label: '1. Target' },
  { id: 'auth',     label: '2. Authorize' },
  { id: 'browser',  label: '3. Browser' },
  { id: 'enum',     label: '4. Enumerate' },
  { id: 'surface',  label: '5. Attack Surface' },
  { id: 'quick',    label: '6. Authz / CORS (auto)' },
  { id: 'scan',     label: '7. API Security Scan' },
  { id: 'report',   label: '8. Report' }
];

export default function App() {
  const [user, setUser] = useState(null);
  const [target, setTarget] = useState(null);
  const [authorized, setAuthorized] = useState(false);
  const [endpoints, setEndpoints] = useState([]);
  const [findings, setFindings] = useState([]);
  const [quickFindings, setQuickFindings] = useState([]);
  // Kept across tabs so the Enumerate tab can reuse browser-captured traffic
  // even if the user navigates elsewhere after closing the browser window.
  const [capturedRequests, setCapturedRequests] = useState([]);
  const [reconStatus, setReconStatus] = useState(null);
  const [tab, setTab] = useState('target');
  const [logLines, setLogLines] = useState([]);

  const log = (line) => {
    const ts = new Date().toISOString().slice(11, 19);
    setLogLines((ls) => [...ls, `${ts}  ${line}`]);
  };

  // Keep the latest target/authorized in refs so the traffic listener (wired
  // once at mount) always reads current values.
  const targetRef = useRef(null);
  const authedRef = useRef(false);
  useEffect(() => { targetRef.current = target; }, [target]);
  useEffect(() => { authedRef.current = authorized; }, [authorized]);

  // When the customized browser closes, Electron pushes the captured traffic
  // here. We filter to scope, feed it to /api/enumerate, and jump to the
  // Endpoints tab so the user sees results immediately.
  useEffect(() => {
    if (!window.api || !window.api.onTraffic) return;
    // Recon lifecycle — driven by the Electron main process after login
    // detection. Phases: started → progress* → done.
    const unsubStart = window.api.onReconStarted?.((payload) => {
      setReconStatus({ phase: 'started', ...payload });
      log(`[recon] started after login @ ${payload?.loggedInAt || 'unknown'}`);
    });
    const unsubProg = window.api.onReconProgress?.((p) => {
      setReconStatus({ phase: 'progress', ...p });
    });
    const unsubReconLog = window.api.onReconLog?.((m) => log(`[recon] ${m}`));
    const unsubErr = window.api.onReconError?.((p) => {
      setReconStatus({ phase: 'error', message: p.message });
      log(`[recon] error: ${p.message}`);
    });
    const unsubDone = window.api.onReconDone?.(async ({ stats, requests }) => {
      setReconStatus({ phase: 'done', stats });
      setCapturedRequests(requests || []);
      log(`[recon] done — ${stats?.crawled} URLs, ${requests?.length || 0} captured requests`);
      const t = targetRef.current;
      if (!t || !authedRef.current || !requests || requests.length === 0) return;
      try {
        const r = await api.enumerate({
          requests, scopeHosts: t.scopeHosts || [], targetId: t._id
        });
        setEndpoints(r.endpoints);
        log(`[auto] ${r.count} endpoints (${r.candidates} SSRF candidates) from recon`);
        setQuickFindings([]);
        setTab('surface');
      } catch (e) { log(`[auto] enumerate failed: ${e.message}`); }
    });

    const unsub = window.api.onTraffic(async ({ requests, targetUrl }) => {
      const t = targetRef.current;
      if (!t) { log(`[browser] closed with ${requests.length} requests — no target saved, discarded`); return; }
      log(`[browser] closed — recorded ${requests.length} requests from ${targetUrl}`);
      // Always buffer, regardless of attestation state, so the manual
      // "Load traffic + enumerate" button on the Enumerate tab can reuse them.
      setCapturedRequests(requests);
      if (!authedRef.current) { log('[enum] skipped — attestation missing'); return; }
      if (requests.length === 0) return;
      try {
        const r = await api.enumerate({
          requests, scopeHosts: t.scopeHosts || [], targetId: t._id
        });
        setEndpoints(r.endpoints);
        log(`[enum] ${r.count} endpoints (${r.candidates} SSRF candidates) from browser capture`);
        setQuickFindings([]);
        setTab('surface');
      } catch (e) {
        log(`[enum] auto-enumerate failed: ${e.message}`);
      }
    });
    return () => {
      unsub && unsub();
      unsubStart && unsubStart();
      unsubProg && unsubProg();
      unsubReconLog && unsubReconLog();
      unsubErr && unsubErr();
      unsubDone && unsubDone();
    };
  }, []);

  if (!user) return <LoginView onAuthed={setUser} />;

  return (
    <div className="app">
      <aside className="sidebar">
        <h1>SSRF EXPLORER</h1>
        <div className="muted" style={{ marginBottom: 12 }}>Signed in as <b>{user.username}</b></div>
        <nav className="nav">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={tab === t.id ? 'active' : ''}
              onClick={() => setTab(t.id)}
              disabled={
                (t.id !== 'target' && !target) ||
                (['enum', 'scan', 'browser', 'quick', 'surface'].includes(t.id) && !authorized)
              }
            >
              {t.label}
            </button>
          ))}
        </nav>
        <div style={{ marginTop: 16 }}>
          <div className="muted" style={{ marginBottom: 4 }}>Session log</div>
          <div className="log">
            {logLines.length === 0 ? <span className="muted">(empty)</span> :
              logLines.slice(-150).map((l, i) => <div key={i}>{l}</div>)}
          </div>
        </div>
      </aside>

      <main className="main">
        {tab === 'target' && (
          <TargetConfig current={target} onSaved={(t) => {
            setTarget(t); setAuthorized(false); setTab('auth'); log(`[cfg] target saved: ${t.url}`);
          }} />
        )}
        {tab === 'auth' && target && (
          <AuthGate target={target} onAttested={async (r) => {
            setAuthorized(true);
            log(`[auth] attested by ${r.operator}`);
            // As soon as the operator attests, try to auto-pull traffic from
            // whichever Burp source is configured (REST API or XML history).
            // This happens under the signed-in session's auth token and runs
            // before the user even opens the browser.
            const hasRest = !!(target.burp && target.burp.restUrl);
            const hasXml  = !!(target.burp && target.burp.historyPath);
            if (hasRest || hasXml) {
              try {
                log('[auto] pulling Burp traffic...');
                const burp = await api.loadBurp({
                  historyPath: target.burp.historyPath || null,
                  restUrl: target.burp.restUrl || null,
                  restKey: target.burp.restKey || null,
                  scopeHosts: target.scopeHosts
                });
                log(`[auto] ${burp.count} requests pulled`);
                const e = await api.enumerate({
                  requests: burp.requests,
                  scopeHosts: target.scopeHosts,
                  targetId: target._id
                });
                setEndpoints(e.endpoints);
                log(`[auto] ${e.count} endpoints (${e.candidates} SSRF candidates)`);
                setQuickFindings([]);
                setTab('surface');
                return;
              } catch (err) {
                log(`[auto] Burp auto-load failed: ${err.message}. Launch the browser instead.`);
              }
            }
            setTab('browser');
          }} />
        )}
        {tab === 'browser' && target && (
          <CustomBrowser target={target} authorized={authorized} reconStatus={reconStatus} />
        )}
        {tab === 'enum' && target && (
          <EndpointsView
            target={target}
            authorized={authorized}
            endpoints={endpoints}
            setEndpoints={setEndpoints}
            capturedRequests={capturedRequests}
            log={log}
          />
        )}
        {tab === 'surface' && target && (
          <AttackSurface
            endpoints={endpoints}
            log={log}
            onJumpToScan={() => setTab('scan')}
          />
        )}
        {tab === 'quick' && target && (
          <QuickChecks
            target={target}
            authorized={authorized}
            endpoints={endpoints}
            findings={quickFindings}
            setFindings={setQuickFindings}
            log={log}
          />
        )}
        {tab === 'scan' && target && (
          <SsrfResults
            target={target}
            authorized={authorized}
            endpoints={endpoints}
            findings={findings}
            setFindings={setFindings}
            log={log}
          />
        )}
        {tab === 'report' && target && (
          <ReportView target={target} endpoints={endpoints} findings={findings} />
        )}
      </main>
    </div>
  );
}
