// Optional Mongoose persistence with in-memory fallback.
//
// Every model we need is exposed via collections.*; if Mongo is connected,
// these delegate to Mongoose models. Otherwise they wrap a plain Map so the
// rest of the app never branches on "do we have a DB".

const mongoose = require('mongoose');

const schemas = {
  User: new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: 'operator' },
    createdAt: { type: Date, default: Date.now }
  }),
  Target: new mongoose.Schema({
    url: String,
    username: String,
    password: String,
    scopeHosts: [String],
    burp: {
      proxyHost: String,
      proxyPort: Number,
      restUrl: String,
      restKey: String,
      historyPath: String
    },
    scan: {
      concurrency: { type: Number, default: 5 },
      timeoutSec: { type: Number, default: 10 },
      oobCanary: String
    },
    createdAt: { type: Date, default: Date.now }
  }),
  Authorization: new mongoose.Schema({
    targetId: String,
    operator: String,
    engagementRef: String,
    attested: Boolean,
    attestedAt: { type: Date, default: Date.now }
  }),
  Endpoint: new mongoose.Schema({
    targetId: String,
    method: String,
    url: String,
    host: String,
    path: String,
    params: [Object],
    score: Number,
    sampleRaw: String
  }),
  Finding: new mongoose.Schema({
    targetId: String,
    category: String,        // OWASP API Top 10 bucket (e.g. API7_SSRF)
    severity: String,
    endpoint: String,
    param: String,
    payload: String,
    payloadCategory: String,
    description: String,
    status: Number,
    elapsedMs: Number,
    redirect: String,
    bodyExcerpt: String,
    error: String,
    signals: [String],
    createdAt: { type: Date, default: Date.now }
  })
};

let mode = 'memory';
let memStore = null;
const models = {};

function makeMemoryCollection(name) {
  const map = new Map();
  let idSeq = 1;
  return {
    async create(doc) {
      const _id = String(idSeq++);
      const rec = { _id, ...doc, createdAt: doc.createdAt || new Date() };
      map.set(_id, rec);
      return rec;
    },
    async find(filter = {}) {
      return [...map.values()].filter((d) =>
        Object.entries(filter).every(([k, v]) => d[k] === v)
      );
    },
    async findOne(filter = {}) {
      return (await this.find(filter))[0] || null;
    },
    async findById(id) {
      return map.get(String(id)) || null;
    },
    async updateOne(filter, patch) {
      const existing = await this.findOne(filter);
      if (!existing) return null;
      Object.assign(existing, patch);
      return existing;
    },
    async deleteMany(filter = {}) {
      const keep = [...map.entries()].filter(
        ([, d]) => !Object.entries(filter).every(([k, v]) => d[k] === v)
      );
      map.clear();
      for (const [k, v] of keep) map.set(k, v);
      return { deletedCount: map.size };
    },
    async count(filter = {}) {
      return (await this.find(filter)).length;
    },
    _name: name
  };
}

async function connect(uri) {
  if (uri) {
    try {
      await mongoose.connect(uri, { serverSelectionTimeoutMS: 3000 });
      mode = 'mongo';
      for (const [name, schema] of Object.entries(schemas)) {
        models[name] = mongoose.model(name, schema);
      }
      // eslint-disable-next-line no-console
      console.log('[db] connected to MongoDB');
      return;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('[db] MongoDB unavailable, falling back to memory:', e.message);
    }
  }
  mode = 'memory';
  memStore = {};
  for (const name of Object.keys(schemas)) {
    memStore[name] = makeMemoryCollection(name);
    models[name] = memStore[name];
  }
}

module.exports = {
  connect,
  mode: () => mode,
  model: (name) => models[name],
  models
};
