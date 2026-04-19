import React, { useEffect, useState } from 'react';
import { api, setToken } from '../api.js';

export default function LoginView({ onAuthed }) {
  const [needsBootstrap, setNeeds] = useState(false);
  const [username, setUser] = useState('');
  const [password, setPwd] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [store, setStore] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const h = await api.health();
        setStore(h.store);
        const s = await api.authStatus();
        setNeeds(s.needsBootstrap);
      } catch (e) { setErr(e.message); }
    })();
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setErr(''); setBusy(true);
    try {
      const fn = needsBootstrap ? api.register : api.login;
      const r = await fn({ username, password });
      setToken(r.token);
      onAuthed(r.user);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  };

  return (
    <div className="center">
      <form className="card" onSubmit={submit}>
        <h2>SSRF Explorer {needsBootstrap ? '· Create admin' : '· Sign in'}</h2>
        <p className="muted">
          Storage: <span className="tag">{store || '...'}</span>
          {store === 'memory' && <span className="muted"> — MongoDB not connected; session will not persist.</span>}
        </p>
        <label>Username</label>
        <input value={username} onChange={(e) => setUser(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPwd(e.target.value)} />
        {err && <div className="banner err" style={{ marginTop: 12 }}>{err}</div>}
        <div style={{ marginTop: 14 }}>
          <button className="primary" disabled={busy} type="submit">
            {needsBootstrap ? 'Create account' : 'Sign in'}
          </button>
        </div>
      </form>
    </div>
  );
}
