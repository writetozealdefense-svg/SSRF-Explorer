// /api/evidence/build — given a finding, re-run the probe to get a FRESH
// request/response pair (so the evidence page matches reality at capture
// time, not some stale earlier probe) and compose an evidence HTML page.
//
// Screenshotting is done in the renderer side via window.api.captureEvidence
// because only Electron can render HTML off-screen and capture it reliably.

const express = require('express');
const fs = require('fs/promises');
const path = require('path');

const db = require('../db');
const { buildEvidenceHtml } = require('../services/evidence');
const {
  pocAuthBypass,
  pocInvalidToken,
  pocCorsReflected,
  pocCorsNull,
  pocCorsWildcardCreds
} = require('../services/pocGenerator');
const { requireAuth } = require('./auth');
const { spawn } = require('child_process');

const router = express.Router();
router.use(requireAuth);

const PROBE_SCRIPT = path.join(__dirname, '..', 'scripts', 'ssrf_probe.ps1');
function resolvePwsh() {
  return process.env.PWSH_BIN || (process.platform === 'win32' ? 'powershell.exe' : 'pwsh');
}

function runProbe(payloadJson, timeoutMs) {
  return new Promise((resolve) => {
    const bin = resolvePwsh();
    const args = ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', PROBE_SCRIPT];
    let proc;
    try { proc = spawn(bin, args, { windowsHide: true }); }
    catch (e) {
      return resolve({ status: 0, elapsed_ms: 0, headers: {}, body_excerpt: '', error: `spawn: ${e.message}` });
    }
    let out = '', err = '';
    const killer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, timeoutMs);
    proc.stdout.on('data', (d) => (out += d.toString()));
    proc.stderr.on('data', (d) => (err += d.toString()));
    proc.on('close', () => {
      clearTimeout(killer);
      const last = out.trim().split(/\r?\n/).reverse().find((l) => l.startsWith('{') && l.endsWith('}'));
      if (!last) return resolve({ status: 0, elapsed_ms: 0, headers: {}, body_excerpt: '', error: err || 'no json' });
      try { resolve(JSON.parse(last)); }
      catch (e) { resolve({ status: 0, elapsed_ms: 0, headers: {}, body_excerpt: '', error: `parse: ${e.message}` }); }
    });
    proc.stdin.write(payloadJson);
    proc.stdin.end();
  });
}

// Re-create the probe input that originally produced the finding, so the
// re-run matches exactly and the evidence page is a true capture.
function reconstructProbe({ finding, endpoint, config }) {
  const timeout = config.timeoutSec || 10;
  const proxy = config.proxy || '';
  const category = finding.category;
  const headers = endpoint?.sampleHeaders || {};
  const url = endpoint?.sampleUrl || finding.endpoint.split(' ')[1] || '';
  const method = endpoint?.method || finding.endpoint.split(' ')[0] || 'GET';
  const body = endpoint?.sampleBody || '';

  if (category === 'AUTHZ_AuthStrip') {
    return {
      input: JSON.stringify({
        method, url, headers, body,
        param: { name: 'Authorization,Cookie,X-API-Key,X-Auth-Token,X-CSRF-Token', location: 'header-remove' },
        payload: '<stripped>', timeout, proxy
      }),
      poc: endpoint ? pocAuthBypass({ endpoint, sample: { url, body, headers } }) : null
    };
  }
  if (category === 'AUTHZ_InvalidToken') {
    return {
      input: JSON.stringify({
        method, url, headers, body,
        param: { name: 'Authorization', location: 'header' },
        payload: 'Bearer invalid-token-for-poc-only', timeout, proxy
      }),
      poc: endpoint ? pocInvalidToken({ endpoint, sample: { url, body, headers } }) : null
    };
  }
  if (category === 'CORS_Misconfig') {
    // Scenario is the Origin we sent; find it from the finding.
    const scenarioToOrigin = {
      'arbitrary-attacker-origin': 'https://attacker.example.com',
      'null-origin': 'null',
      'suffix-confusion': `https://${endpoint?.host || 'target'}.attacker.example.com`,
      'prefix-confusion': `https://attacker-${endpoint?.host || 'target'}`
    };
    const origin = scenarioToOrigin[finding.scenario] || 'https://attacker.example.com';
    let poc = null;
    if (endpoint) {
      if ((finding.signals || []).some((s) => s.startsWith('reflected-origin'))) poc = pocCorsReflected({ endpoint, sample: { url }, attackerOrigin: 'https://attacker.example.com' });
      else if ((finding.signals || []).includes('null-origin-accepted')) poc = pocCorsNull({ endpoint, sample: { url } });
      else poc = pocCorsWildcardCreds({ endpoint, sample: { url } });
    }
    return {
      input: JSON.stringify({
        method, url, headers, body,
        param: { name: 'Origin', location: 'header' },
        payload: origin, timeout, proxy
      }),
      poc
    };
  }
  // For OWASP categories, just re-run the baseline so we still have a real
  // response in the evidence page. Signals carry the original detection.
  return {
    input: JSON.stringify({
      method, url, headers, body,
      param: { name: '_baseline', location: 'none' }, payload: '<baseline>', timeout, proxy
    }),
    poc: null
  };
}

router.post('/build', async (req, res) => {
  const { finding, endpoint, config, targetId } = req.body || {};
  if (!finding) return res.status(400).json({ error: 'finding required' });

  const Target = db.model('Target');
  const Authorization = db.model('Authorization');
  const target = targetId ? await Target.findById(targetId) : (req.body.target || {});
  const auth = targetId ? await Authorization.findOne({ targetId }) : (req.body.auth || {});
  if (!auth || !auth.attested) {
    return res.status(403).json({ error: 'authorization attestation missing' });
  }

  const { input, poc } = reconstructProbe({ finding, endpoint: endpoint || {}, config: config || {} });
  const timeoutMs = ((config?.timeoutSec || 10) * 1000) + 15000;
  const resp = await runProbe(input, timeoutMs);

  let requestSent;
  try {
    const parsed = JSON.parse(input);
    requestSent = {
      method: parsed.method,
      url: parsed.url,
      headers: parsed.headers,
      body: parsed.body
    };
    // Surface the mutation on the request view so the reader sees exactly
    // what the probe changed.
    if (parsed.param.location === 'header-remove') {
      const drop = (parsed.param.name || '').split(',').map((s) => s.trim().toLowerCase());
      requestSent.headers = Object.fromEntries(
        Object.entries(requestSent.headers || {}).filter(([k]) => !drop.includes(k.toLowerCase()))
      );
    } else if (parsed.param.location === 'header') {
      requestSent.headers = { ...requestSent.headers, [parsed.param.name]: parsed.payload };
    }
  } catch {
    requestSent = { method: '', url: '', headers: {}, body: '' };
  }

  const html = buildEvidenceHtml({
    finding: { ...finding, poc: finding.poc || poc },
    target, auth,
    requestSent,
    responseReceived: {
      status: resp.status, headers: resp.headers || {},
      body_excerpt: resp.body_excerpt || '', redirect: resp.redirect || ''
    },
    generatedAt: new Date().toISOString()
  });

  res.json({ html, requestSent, responseReceived: resp });
});

// Finalize on disk: the renderer posts { pngPath, htmlPath, json } after
// Electron has saved the screenshot. We just echo — the artifacts are on
// the user's disk under reports/evidence/.
router.post('/record', async (req, res) => {
  const { pngPath, htmlPath, finding } = req.body || {};
  if (!pngPath && !htmlPath) return res.status(400).json({ error: 'pngPath or htmlPath required' });
  const Finding = db.model('Finding');
  try {
    await Finding.create({
      targetId: req.body.targetId || '',
      category: finding?.category || '',
      severity: finding?.severity || '',
      endpoint: finding?.endpoint || '',
      param: finding?.param || '',
      signals: finding?.signals || [],
      bodyExcerpt: (finding?.bodyExcerpt || '').slice(0, 1024),
      redirect: `evidence-png:${pngPath}`
    });
  } catch {}
  res.json({ ok: true });
});

module.exports = router;
