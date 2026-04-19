// Kick off an SSRF scan. Blocks until finished (MVP); progress is visible
// via repeated GET /api/ssrf/status/:id while the client polls.

const express = require('express');
const db = require('../db');
const { scan } = require('../services/ssrfRunner');
const { CATEGORY_META, ALL_CATEGORIES } = require('../services/owaspProbes');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

router.get('/categories', (_req, res) => {
  res.json(ALL_CATEGORIES.map((id) => ({ id, ...CATEGORY_META[id] })));
});

const jobState = new Map(); // jobId -> { done, total, findings, finishedAt }

router.post('/scan', async (req, res) => {
  const { endpoints, config, targetId, categories } = req.body || {};
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

  const jobId = String(Date.now());
  jobState.set(jobId, { done: 0, total: 0, findings: [], finishedAt: null });

  // Fire-and-forget background scan.
  (async () => {
    try {
      const { findings } = await scan({
        endpoints,
        config: config || {},
        categories: Array.isArray(categories) ? categories : null,
        onProgress: (d, t) => {
          const s = jobState.get(jobId);
          if (s) { s.done = d; s.total = t; }
        },
        onHit: (f) => {
          const s = jobState.get(jobId);
          if (s) s.findings.push(f);
        }
      });
      const s = jobState.get(jobId);
      if (s) {
        s.findings = findings;
        s.finishedAt = new Date().toISOString();
      }
      if (targetId) {
        const Finding = db.model('Finding');
        for (const f of findings) await Finding.create({ targetId, ...f });
      }
    } catch (e) {
      const s = jobState.get(jobId);
      if (s) { s.error = e.message; s.finishedAt = new Date().toISOString(); }
    }
  })();

  res.json({ jobId });
});

router.get('/status/:jobId', (req, res) => {
  const s = jobState.get(req.params.jobId);
  if (!s) return res.status(404).json({ error: 'unknown job' });
  res.json({
    done: s.done,
    total: s.total,
    finished: !!s.finishedAt,
    finishedAt: s.finishedAt,
    error: s.error || null,
    findings: s.findings
  });
});

module.exports = router;
