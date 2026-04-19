const express = require('express');
const { enumerate } = require('../services/enumerator');
const { analyzeAll } = require('../services/attackSurface');
const db = require('../db');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

router.post('/', async (req, res) => {
  const { requests, scopeHosts, targetId } = req.body || {};
  if (!Array.isArray(requests)) return res.status(400).json({ error: 'requests[] required' });
  const { endpoints, stats } = enumerate(requests, scopeHosts || []);
  // Annotate every endpoint with its predicted attack surface — no network
  // calls, pure heuristics on method/path/params/headers — so the UI can
  // show "this endpoint is testable for API1, API2, API7" the instant
  // enumeration finishes.
  const annotated = analyzeAll(endpoints);
  if (targetId) {
    const Endpoint = db.model('Endpoint');
    await Endpoint.deleteMany({ targetId });
    for (const e of annotated) {
      await Endpoint.create({ targetId, ...e });
    }
  }
  res.json({
    count: annotated.length,
    candidates: annotated.filter((e) => e.score > 0).length,
    stats,
    endpoints: annotated
  });
});

module.exports = router;
