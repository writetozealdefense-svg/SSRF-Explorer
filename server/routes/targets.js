const express = require('express');
const db = require('../db');
const { requireAuth } = require('./auth');

const router = express.Router();
router.use(requireAuth);

router.post('/', async (req, res) => {
  const Target = db.model('Target');
  const t = await Target.create(req.body || {});
  res.json(t);
});

router.get('/', async (_req, res) => {
  const Target = db.model('Target');
  const items = await Target.find();
  res.json(items);
});

router.get('/:id', async (req, res) => {
  const Target = db.model('Target');
  const t = await Target.findById(req.params.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  res.json(t);
});

// Authorization attestation — required before any scan action.
router.post('/:id/authorize', async (req, res) => {
  const Authorization = db.model('Authorization');
  const { operator, engagementRef, attested } = req.body || {};
  if (!attested || !operator || !engagementRef) {
    return res.status(400).json({ error: 'attestation incomplete' });
  }
  const record = await Authorization.create({
    targetId: req.params.id,
    operator,
    engagementRef,
    attested: true
  });
  res.json(record);
});

router.get('/:id/authorization', async (req, res) => {
  const Authorization = db.model('Authorization');
  const list = await Authorization.find({ targetId: req.params.id });
  res.json(list.sort((a, b) => +new Date(b.attestedAt) - +new Date(a.attestedAt))[0] || null);
});

module.exports = router;
