// Burp integration: load traffic from an XML export or (optionally) REST API.

const express = require('express');
const fs = require('fs/promises');

const { parseHistory } = require('../services/burpParser');
const { fetchHistoryFromRest } = require('../services/burpRest');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

router.post('/load', async (req, res) => {
  const { historyPath, restUrl, restKey, scopeHosts } = req.body || {};
  try {
    let requests = [];
    if (restUrl) {
      requests = await fetchHistoryFromRest(restUrl, restKey, scopeHosts || []);
    } else if (historyPath) {
      const xml = await fs.readFile(historyPath, 'utf8');
      requests = parseHistory(xml);
    } else {
      return res.status(400).json({ error: 'Supply historyPath or restUrl' });
    }
    res.json({ count: requests.length, requests });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
