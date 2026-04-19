// Parse Burp Suite proxy history XML into normalized request objects.

const { XMLParser } = require('fast-xml-parser');

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseAttributeValue: false,
  textNodeName: '#text'
});

function decode(node) {
  if (node == null) return '';
  const text = typeof node === 'object' ? node['#text'] ?? '' : String(node);
  const b64 = typeof node === 'object' && node['@_base64'] === 'true';
  if (b64) {
    try {
      return Buffer.from(text, 'base64').toString('utf8');
    } catch {
      return '';
    }
  }
  return text;
}

function parseRequestBytes(raw) {
  if (!raw) return { method: '', path: '', headers: {}, body: '' };
  const sep = raw.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
  const [head, ...rest] = raw.split(sep);
  const body = rest.join(sep);
  const lines = head.split(/\r?\n/);
  const line0 = lines.shift() || '';
  const [method = '', path = ''] = line0.split(' ');
  const headers = {};
  for (const line of lines) {
    const i = line.indexOf(':');
    if (i === -1) continue;
    headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return { method, path, headers, body };
}

function parseHistory(xml) {
  const doc = parser.parse(xml);
  const items = doc?.items?.item;
  const arr = Array.isArray(items) ? items : items ? [items] : [];
  return arr.map((item) => {
    const rawReq = decode(item.request);
    const parsed = parseRequestBytes(rawReq);
    const url = String(item.url ?? '').trim();
    return {
      method: String(item.method ?? parsed.method).trim(),
      url,
      host: String(item.host?.['#text'] ?? item.host ?? '').trim(),
      path: String(item.path ?? parsed.path).trim(),
      headers: parsed.headers,
      body: parsed.body,
      status: Number(item.status) || null,
      responseLength: Number(item.responselength) || 0,
      raw: rawReq
    };
  });
}

module.exports = { parseHistory, parseRequestBytes };
