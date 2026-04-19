// Preload for the main UI window. Exposes a tiny surface to the renderer
// via contextBridge — no direct node/electron access from React.

const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, cb) {
  const handler = (_evt, payload) => cb(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

contextBridge.exposeInMainWorld('api', {
  openBrowser: (opts) => ipcRenderer.invoke('browser:open', opts),
  closeBrowser: (partition) => ipcRenderer.invoke('browser:close', partition),
  // Subscribe to traffic recorded by the customized browser. The callback is
  // invoked once per window-close event with { partition, targetUrl, requests }.
  onTraffic: (cb) => subscribe('browser:traffic', cb),
  // Recon lifecycle events fired when auto-crawl runs after login detection.
  onReconStarted: (cb) => subscribe('recon:started', cb),
  onReconProgress: (cb) => subscribe('recon:progress', cb),
  onReconLog: (cb) => subscribe('recon:log', cb),
  onReconDone: (cb) => subscribe('recon:done', cb),
  onReconError: (cb) => subscribe('recon:error', cb),
  platform: process.platform
});
