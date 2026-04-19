// Electron main process.
//
// Responsibilities:
//   1. Boot the Express backend in-process (same Node runtime).
//   2. Create the primary BrowserWindow that loads the React UI.
//   3. Handle IPC for opening the "customized browser" — a separate
//      BrowserWindow whose session is forced through the Burp proxy.

const { app, BrowserWindow, ipcMain, session, Menu, shell } = require('electron');
const path = require('path');

const { startServer } = require('../server/index.js');

const isDev = process.env.VITE_DEV === '1';
if (isDev) process.env.NODE_ENV = 'development';
let mainWindow = null;
let browserWindows = new Map(); // partition -> BrowserWindow
let trafficByPartition = new Map(); // partition -> Map<requestId, capturedRequest>
let recorderAttached = new Set();   // partitions we've already wired webRequest listeners on

// Intercept every HTTP(S) request the customized browser makes and capture
// what the enumerator needs: method, URL, headers, body, status. Buffers are
// decoded as UTF-8 (best-effort — binary POSTs get lossy, that's fine).
function attachRecorder(sess, partition) {
  if (recorderAttached.has(partition)) return;
  recorderAttached.add(partition);

  sess.webRequest.onBeforeRequest((details, cb) => {
    if (!/^https?:/i.test(details.url)) return cb({});
    let body = '';
    if (details.uploadData && details.uploadData.length) {
      body = details.uploadData
        .map((d) => (d.bytes ? Buffer.from(d.bytes).toString('utf8') : ''))
        .join('');
    }
    let host = '', pathname = '';
    // Use hostname, not host — the enumerator matches scope on hostname and
    // host would include the port, breaking `endsWith('.example.com')` checks.
    try { const u = new URL(details.url); host = u.hostname; pathname = u.pathname; } catch {}
    const store = trafficByPartition.get(partition);
    if (store) {
      store.set(details.id, {
        method: details.method,
        url: details.url,
        host,
        path: pathname,
        headers: {},
        body,
        status: null,
        responseLength: 0
      });
    }
    cb({});
  });

  // Electron 29 exposes this as a sync listener — no callback.
  sess.webRequest.onBeforeSendHeaders((details, cb) => {
    const store = trafficByPartition.get(partition);
    const r = store && store.get(details.id);
    if (r) r.headers = { ...details.requestHeaders };
    cb({ requestHeaders: details.requestHeaders });
  });

  sess.webRequest.onCompleted((details) => {
    const store = trafficByPartition.get(partition);
    const r = store && store.get(details.id);
    if (r) r.status = details.statusCode || null;
  });
}

async function createMainWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    title: 'SSRF Explorer',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  // Dev: React served by Vite. Prod: served statically by Express.
  const url = isDev ? 'http://127.0.0.1:5173' : `http://127.0.0.1:${port}`;
  mainWindow.loadURL(url);
  if (isDev) mainWindow.webContents.openDevTools({ mode: 'detach' });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Strip default menu — the UI provides all controls.
  Menu.setApplicationMenu(null);
}

// IPC: open a stateful browser window routed through Burp.
// Called from renderer with { targetUrl, proxyHost, proxyPort, username, password }.
ipcMain.handle('browser:open', async (_evt, opts) => {
  const partition = `persist:target-${encodeURIComponent(opts.targetUrl || 'default')}`;
  if (browserWindows.has(partition)) {
    const w = browserWindows.get(partition);
    if (!w.isDestroyed()) {
      w.focus();
      return { ok: true, reused: true };
    }
    browserWindows.delete(partition);
  }

  const sess = session.fromPartition(partition);
  await sess.setProxy({
    proxyRules: `http=${opts.proxyHost}:${opts.proxyPort};https=${opts.proxyHost}:${opts.proxyPort}`,
    proxyBypassRules: '<-loopback>'
  });

  // Trust Burp's CA transparently (dev-only; real cert pinning would be stricter).
  sess.setCertificateVerifyProc((_req, cb) => cb(0));

  // Fresh traffic store per launch, and wire the recorder once per partition.
  trafficByPartition.set(partition, new Map());
  attachRecorder(sess, partition);

  const win = new BrowserWindow({
    width: 1200,
    height: 820,
    title: `Customized Browser — ${opts.targetUrl}`,
    webPreferences: {
      partition,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'browserPreload.js')
    }
  });

  browserWindows.set(partition, win);
  win.on('closed', () => {
    browserWindows.delete(partition);
    const store = trafficByPartition.get(partition);
    const requests = store ? [...store.values()] : [];
    // Free memory for this partition; next launch starts a fresh recording.
    trafficByPartition.set(partition, new Map());
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('browser:traffic', { partition, targetUrl: opts.targetUrl, requests });
    }
  });

  // Force every external link inside the customized browser to open in the
  // same window, never a native OS browser — keeps session contained.
  win.webContents.setWindowOpenHandler(({ url }) => {
    win.loadURL(url);
    return { action: 'deny' };
  });

  await win.loadURL(opts.targetUrl);

  if (opts.username && opts.password) {
    // Stage creds for the preload to pick up when login form renders.
    win.webContents.send('stage-credentials', {
      username: opts.username,
      password: opts.password
    });
  }

  return { ok: true, reused: false, partition };
});

ipcMain.handle('browser:close', async (_evt, partition) => {
  const w = browserWindows.get(partition);
  if (w && !w.isDestroyed()) w.close();
  browserWindows.delete(partition);
  return { ok: true };
});

app.whenReady().then(async () => {
  const port = await startServer();
  await createMainWindow(port);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
});
