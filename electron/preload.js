// Preload for the main UI window. Exposes a tiny surface to the renderer
// via contextBridge — no direct node/electron access from React.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  openBrowser: (opts) => ipcRenderer.invoke('browser:open', opts),
  closeBrowser: (partition) => ipcRenderer.invoke('browser:close', partition),
  // Subscribe to traffic recorded by the customized browser. The callback is
  // invoked once per window-close event with { partition, targetUrl, requests }.
  onTraffic: (cb) => {
    const handler = (_evt, payload) => cb(payload);
    ipcRenderer.on('browser:traffic', handler);
    return () => ipcRenderer.removeListener('browser:traffic', handler);
  },
  platform: process.platform
});
