// Express server, booted in-process by Electron main.
//
// MongoDB is optional: if MONGODB_URI is set, we use Mongoose and persist.
// Otherwise we fall back to an in-memory store so the app is still usable
// for one-off scans without any external deps.

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const db = require('./db');
const authRoutes = require('./routes/auth');
const targetRoutes = require('./routes/targets');
const burpRoutes = require('./routes/burp');
const enumerateRoutes = require('./routes/enumerate');
const ssrfRoutes = require('./routes/ssrf');
const reportRoutes = require('./routes/report');
const quickcheckRoutes = require('./routes/quickcheck');

async function startServer() {
  await db.connect(process.env.MONGODB_URI);

  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  app.use(express.json({ limit: '64mb' }));
  app.use(morgan('tiny'));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, store: db.mode(), version: '0.2.0' });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/targets', targetRoutes);
  app.use('/api/burp', burpRoutes);
  app.use('/api/enumerate', enumerateRoutes);
  app.use('/api/ssrf', ssrfRoutes);
  app.use('/api/report', reportRoutes);
  app.use('/api/quickcheck', quickcheckRoutes);

  // Serve built React UI in production.
  const clientDist = path.join(__dirname, '..', 'client', 'dist');
  app.use(express.static(clientDist));
  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.sendFile(path.join(clientDist, 'index.html'));
  });

  const wantPort = process.env.NODE_ENV === 'development' ? 3000 : 0;
  return new Promise((resolve) => {
    const server = app.listen(wantPort, '127.0.0.1', () => {
      const { port } = server.address();
      // eslint-disable-next-line no-console
      console.log(`[ssrf-explorer] API listening on http://127.0.0.1:${port}  (${db.mode()})`);
      resolve(port);
    });
  });
}

module.exports = { startServer };

// Support `node server/index.js` for standalone dev.
if (require.main === module) {
  startServer();
}
