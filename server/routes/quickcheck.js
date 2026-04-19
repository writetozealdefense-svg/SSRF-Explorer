// Fast authz + CORS check, designed to fire automatically right after
// enumeration so the operator gets actionable PoCs before the heavier OWASP
// scan has even started.

const express = require('express');
const db = require('../db');
const { runQuickCheck } = require('../services/authzCors');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

const jobs = new Map(); // jobId -> progress state

router.post('/run', async (req, res) => {
  const { endpoints, config, targetId } = req.body || {};
  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    return res.status(400).json({ error: 'endpoints[] required' });
  }
  if (targetId) {
    const Authorization = db.model('Authorization');
    const existing = await Authorization.findOne({ targetId });
    if (!existing || !existing.attested) {
      return res.status(403).json({ error: 'authorization attestation missing' });
    }
  }

  const jobId = 'qc-' + String(Date.now());
  jobs.set(jobId, { done: 0, total: 0, findings: [], finished: false });

  (async () => {
    try {
      const { findings } = await runQuickCheck({
        endpoints,
        config: config || {},
        onProgress: (d, t) => {
          const s = jobs.get(jobId);
          if (s) { s.done = d; s.total = t; }
        },
        onHit: (f) => {
          const s = jobs.get(jobId);
          if (s) s.findings.push(f);
        }
      });
      const s = jobs.get(jobId);
      if (s) { s.findings = findings; s.finished = true; s.finishedAt = new Date().toISOString(); }
      if (targetId) {
        const Finding = db.model('Finding');
        for (const f of findings) await Finding.create({ targetId, ...f, poc: undefined });
      }
    } catch (e) {
      const s = jobs.get(jobId);
      if (s) { s.error = e.message; s.finished = true; }
    }
  })();

  res.json({ jobId });
});

router.get('/status/:jobId', (req, res) => {
  const s = jobs.get(req.params.jobId);
  if (!s) return res.status(404).json({ error: 'unknown job' });
  res.json(s);
});

module.exports = router;
