// Tiny fetch wrapper. Stores JWT in memory for the lifetime of the window.

let token = null;
export const setToken = (t) => { token = t; };
export const getToken = () => token;

async function request(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(`/api${path}`, { ...opts, headers });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

export const api = {
  health:       () => request('/health'),
  authStatus:   () => request('/auth/status'),
  register:     (body) => request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login:        (body) => request('/auth/login',    { method: 'POST', body: JSON.stringify(body) }),
  createTarget: (body) => request('/targets',       { method: 'POST', body: JSON.stringify(body) }),
  listTargets:  () => request('/targets'),
  authorize:    (id, body) => request(`/targets/${id}/authorize`, { method: 'POST', body: JSON.stringify(body) }),
  getAuthorization: (id) => request(`/targets/${id}/authorization`),
  loadBurp:     (body) => request('/burp/load',     { method: 'POST', body: JSON.stringify(body) }),
  enumerate:    (body) => request('/enumerate',     { method: 'POST', body: JSON.stringify(body) }),
  categories:   () => request('/ssrf/categories'),
  startScan:    (body) => request('/ssrf/scan',     { method: 'POST', body: JSON.stringify(body) }),
  scanStatus:   (id) => request(`/ssrf/status/${id}`),
  report:       (body) => request('/report/generate', { method: 'POST', body: JSON.stringify(body) }),
  startQuickCheck: (body) => request('/quickcheck/run', { method: 'POST', body: JSON.stringify(body) }),
  quickCheckStatus: (id) => request(`/quickcheck/status/${id}`)
};
