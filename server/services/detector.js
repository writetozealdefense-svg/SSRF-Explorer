// Classify a probe response into an SSRF severity bucket.

const META = ['ami-id', 'instance-identity', 'iam/security-credentials', 'computeMetadata', 'Metadata-Flavor', 'securityCredentials'];
const BANNER = ['SSH-2.0', 'SSH-1.99', '220 ', 'Redis', 'MEMCACHED', 'Server: gunicorn'];
const FILE = ['root:x:0:0', '[extensions]', '[fonts]', 'for 16-bit app support'];

// Near-identity check that tolerates small per-request differences (CSRF
// tokens, timestamps, request IDs) but still catches "the response is the
// same as the authenticated baseline" — which is the clearest proof that the
// server ignored our payload and there's no SSRF.
function bodiesEffectivelyEqual(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  if (Math.abs(a.length - b.length) / Math.max(a.length, b.length) > 0.05) return false;
  const strip = (s) => s
    .replace(/[0-9a-f]{16,}/gi, '')                 // long hex tokens
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.+-Z]+/g, '')   // ISO timestamps
    .replace(/\b\d{10,}\b/g, '')                    // epoch-like integers
    .replace(/\s+/g, ' ')
    .trim();
  return strip(a) === strip(b);
}

function classify({ category, status, body, elapsedMs, baselineMs, baselineBody, oobHit }) {
  const signals = [];
  const b = body || '';
  const bb = baselineBody || '';
  const unchanged = bodiesEffectivelyEqual(b, bb);

  if (META.some((m) => b.includes(m))) signals.push('cloud-metadata-content');
  if (BANNER.some((m) => b.includes(m))) signals.push('service-banner');
  if (FILE.some((m) => b.includes(m))) signals.push('local-file-content');

  // Only call an endpoint "internal-reachable" when its response actually
  // CHANGED vs the baseline. A 200 with an unchanged body means the server
  // returned its normal answer and silently dropped our payload — no SSRF.
  if (status && status >= 200 && status < 400 && (category === 'loopback' || category === 'private')) {
    if (unchanged) {
      signals.push('response-unchanged-vs-baseline');
    } else {
      signals.push(`internal-reachable-${status}-body-changed`);
    }
  }

  if (baselineMs != null && elapsedMs - baselineMs > 1500 && !unchanged) {
    signals.push(`timing-delta-${elapsedMs - baselineMs}ms`);
  }

  if (oobHit) signals.push('oob-callback');

  let severity;
  if (
    signals.includes('oob-callback') ||
    signals.includes('cloud-metadata-content') ||
    signals.includes('local-file-content')
  ) {
    severity = 'Confirmed';
  } else if (signals.includes('service-banner')) {
    severity = 'Likely';
  } else if (signals.some((s) => s.startsWith('internal-reachable-'))) {
    // "Body changed + status 2xx on a loopback payload" is a real but weak
    // signal — could also be a WAF page or a generic error handler. Report
    // as Possible, let the operator drill in. Combined with a timing delta
    // we raise to Likely.
    severity = signals.some((s) => s.startsWith('timing-delta-')) ? 'Likely' : 'Possible';
  } else if (signals.length && !signals.includes('response-unchanged-vs-baseline')) {
    severity = 'Possible';
  } else {
    severity = 'None';
  }
  return { severity, signals };
}

module.exports = { classify };
