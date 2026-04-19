// Classify a probe response into an SSRF severity bucket.

const META = ['ami-id', 'instance-identity', 'iam/security-credentials', 'computeMetadata', 'Metadata-Flavor', 'securityCredentials'];
const BANNER = ['SSH-2.0', 'SSH-1.99', '220 ', 'Redis', 'MEMCACHED', 'Server: gunicorn'];
const FILE = ['root:x:0:0', '[extensions]', '[fonts]', 'for 16-bit app support'];

function classify({ category, status, body, elapsedMs, baselineMs, oobHit }) {
  const signals = [];
  const b = body || '';
  if (META.some((m) => b.includes(m))) signals.push('cloud-metadata-content');
  if (BANNER.some((m) => b.includes(m))) signals.push('service-banner');
  if (FILE.some((m) => b.includes(m))) signals.push('local-file-content');
  if (status && status >= 200 && status < 400 && (category === 'loopback' || category === 'private')) {
    signals.push(`internal-reachable-${status}`);
  }
  if (baselineMs != null && elapsedMs - baselineMs > 1500) {
    signals.push(`timing-delta-${elapsedMs - baselineMs}ms`);
  }
  if (oobHit) signals.push('oob-callback');

  let severity;
  if (signals.includes('oob-callback') || signals.includes('cloud-metadata-content') || signals.includes('local-file-content')) {
    severity = 'Confirmed';
  } else if (signals.includes('service-banner') || signals.some((s) => s.startsWith('internal-reachable-'))) {
    severity = 'Likely';
  } else if (signals.length) {
    severity = 'Possible';
  } else {
    severity = 'None';
  }
  return { severity, signals };
}

module.exports = { classify };
