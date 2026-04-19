// Off-screen HTML → PNG capture. Loads the given HTML in a hidden
// BrowserWindow sized for good evidence-report layout, waits for the page to
// finish rendering, captures the whole viewport via webContents.capturePage(),
// and writes the PNG + companion HTML + JSON metadata to
// reports/evidence/<session>/.

const { BrowserWindow } = require('electron');
const fs = require('fs/promises');
const path = require('path');

function safeFilename(s) {
  return String(s || 'evidence').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 120);
}

async function captureHtml({ html, filename, meta, sessionDir, width = 1280, height = 1600 }) {
  const win = new BrowserWindow({
    show: false,
    width, height,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, offscreen: false }
  });

  try {
    const dataUrl = 'data:text/html;charset=utf-8;base64,' + Buffer.from(html, 'utf8').toString('base64');
    await win.loadURL(dataUrl);
    // Small settle window so images / fonts (none here, but future-proof)
    // finish layout before the capture.
    await new Promise((r) => setTimeout(r, 350));

    // Expand the viewport to the document height so the screenshot covers
    // the whole evidence page without scrollbars.
    const docHeight = await win.webContents.executeJavaScript(
      'Math.min(5000, Math.max(document.documentElement.scrollHeight, document.body.scrollHeight))'
    ).catch(() => height);
    if (docHeight && docHeight > height) {
      win.setContentSize(width, docHeight);
      await new Promise((r) => setTimeout(r, 200));
    }

    const image = await win.webContents.capturePage();
    const png = image.toPNG();

    await fs.mkdir(sessionDir, { recursive: true });
    const base = safeFilename(filename);
    const pngPath = path.join(sessionDir, `${base}.png`);
    const htmlPath = path.join(sessionDir, `${base}.html`);
    const jsonPath = path.join(sessionDir, `${base}.json`);

    await fs.writeFile(pngPath, png);
    await fs.writeFile(htmlPath, html, 'utf8');
    await fs.writeFile(jsonPath, JSON.stringify(meta || {}, null, 2), 'utf8');

    return { pngPath, htmlPath, jsonPath };
  } finally {
    try { win.close(); } catch {}
  }
}

module.exports = { captureHtml };
