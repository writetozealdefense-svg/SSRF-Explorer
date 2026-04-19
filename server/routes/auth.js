// App-level user login. First user registered becomes admin.

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('../db');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'ssrf-explorer-local-dev';

router.get('/status', async (_req, res) => {
  const User = db.model('User');
  const count = await User.count();
  res.json({ needsBootstrap: count === 0 });
});

router.post('/register', async (req, res) => {
  const User = db.model('User');
  const { username, password } = req.body || {};
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'username + 8+ char password required' });
  }
  const existing = await User.count();
  const role = existing === 0 ? 'admin' : 'operator';
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await User.create({ username, passwordHash, role });
  const token = jwt.sign({ sub: user._id, role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { username, role } });
});

router.post('/login', async (req, res) => {
  const User = db.model('User');
  const { username, password } = req.body || {};
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password || '', user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: '12h'
  });
  res.json({ token, user: { username: user.username, role: user.role } });
});

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'auth required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'bad token' });
  }
}

router.requireAuth = requireAuth;
module.exports = router;
module.exports.requireAuth = requireAuth;
