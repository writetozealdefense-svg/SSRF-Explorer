const express = require('express');
const { enumerate } = require('../services/enumerator');
const db = require('../db');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

router.post('/', async (req, res) => {
  const { requests, scopeHosts, targetId } = req.body || {};
  if (!Array.isArray(requests)) return res.status(400).json({ error: 'requests[] required' });
  const { endpoints, stats } = enumerate(requests, scopeHosts || []);
  if (targetId) {
    const Endpoint = db.model('Endpoint');
    await Endpoint.deleteMany({ targetId });
    for (const e of endpoints) {
      await Endpoint.create({ targetId, ...e });
    }
  }
  res.json({
    count: endpoints.length,
    candidates: endpoints.filter((e) => e.score > 0).length,
    stats,
    endpoints
  });
});

module.exports = router;
