// Helper: wrap a live-upstream probe in sandbox detection + skip logic.
// Usage:
//   import { liveProbeOrSkip } from '../helpers/live-probe.js';
//   await liveProbeOrSkip({ url: 'https://example.com', label: 'Example' }, async () => {
//     // your live test code here — skipped automatically when egress is blocked
//   });

const SANDBOX_ERRORS = /ENETUNREACH|ECONNREFUSED|EAI_AGAIN|ENOTFOUND|fetch failed|EACCES|proxy|tunnel/i;

export async function liveProbeOrSkip({ url, label }, fn, testContext) {
  // testContext is optional — pass `{ skip }` from Vitest context if available
  try {
    await fn();
  } catch (err) {
    const msg = String(err?.message || err?.cause?.message || err);
    if (SANDBOX_ERRORS.test(msg) || (err?.status && err.status === 403)) {
      const skipMsg = `[live-probe] ${label || url} unreachable in this environment — skipping`;
      if (testContext?.skip) {
        testContext.skip(skipMsg);
      } else {
        console.warn(skipMsg);
        return; // soft skip — test passes silently
      }
    }
    throw err; // re-throw non-network errors
  }
}
