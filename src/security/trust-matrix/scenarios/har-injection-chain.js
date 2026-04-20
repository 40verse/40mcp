/**
 * har-injection-chain — malicious HAR input attempts injection across
 * the full conversion chain.
 *
 * Threat: a HAR file dropped into the loader is hostile. It contains:
 *   - cloud-metadata baseUrl in entries
 *   - sensitive credential headers (Authorization, Cookie, X-API-Key)
 *   - sensitive parameter names (password, api_key, access_token)
 *   - chrome-extension scheme URLs
 *   - 20 001 entries (over the hard ceiling)
 *
 * Defense: `loadHarFile` blocks browser-extension schemes, refuses
 * SSRF-shaped baseUrls, never embeds credential headers in tool defs,
 * never infers sensitive param names as tool inputs, and refuses
 * over-sized programmatic HAR objects.
 */

import { loadHarFile } from '../../../loaders/har.js';

export default {
  id: 'har-injection-chain',
  boundary: 'har-loader',
  story:
    'Hostile HAR file attempts SSRF baseUrl, credential header reflection, ' +
    'sensitive param inference, browser-extension scheme injection, and ' +
    'cumulative param overflow. Each attack must be neutralized.',

  async run() {
    const findings = [];

    // Attack 1: SSRF baseUrl from cloud metadata
    try {
      await loadHarFile({
        log: {
          version: '1.2',
          entries: [
            { request: { method: 'GET', url: 'http://169.254.169.254/latest/meta-data/' }, response: { status: 200 } },
            { request: { method: 'GET', url: 'http://169.254.169.254/latest/user-data' }, response: { status: 200 } },
          ],
        },
      }, { allowPrivate: true });
      findings.push('cloud-metadata baseUrl accepted (allowPrivate=true should not unlock metadata hosts)');
    } catch (err) {
      if (!/metadata|169\.254|ssrf|safe|private/i.test(err.message)) {
        findings.push(`SSRF refusal threw with unexpected message: ${err.message.slice(0, 80)}`);
      }
    }

    // Attack 2: credential headers in recorded request
    try {
      const { tools } = await loadHarFile({
        log: {
          version: '1.2',
          entries: [
            {
              request: {
                method: 'GET',
                url: 'https://api.example.com/me',
                headers: [
                  { name: 'Authorization', value: 'Bearer sk-live-LEAKED-TOKEN' },
                  { name: 'Cookie', value: 'session=EXFIL-SESSION' },
                  { name: 'X-API-Key', value: 'LEAKED-KEY' },
                ],
              },
              response: { status: 200 },
            },
          ],
        },
      });
      const dump = JSON.stringify(tools);
      if (dump.includes('sk-live-LEAKED-TOKEN')) findings.push('Authorization bearer reflected in tool defs');
      if (dump.includes('EXFIL-SESSION')) findings.push('Cookie value reflected in tool defs');
      if (dump.includes('LEAKED-KEY')) findings.push('X-API-Key value reflected in tool defs');
    } catch (err) {
      findings.push(`credential header attack threw unexpectedly: ${err.message.slice(0, 80)}`);
    }

    // Attack 3: sensitive parameter names in postData
    try {
      const { tools } = await loadHarFile({
        log: {
          version: '1.2',
          entries: [
            {
              request: {
                method: 'POST',
                url: 'https://api.example.com/login',
                postData: {
                  mimeType: 'application/json',
                  text: '{"username":"alice","password":"s3cret","api_key":"sk-live","access_token":"tok-yyy","secret":"x","normal":"ok"}',
                },
              },
              response: { status: 200 },
            },
          ],
        },
      });
      for (const t of tools) {
        const props = Object.keys(t.inputSchema?.properties || {});
        const leaky = props.filter((p) => /password|api_?key|access_?token|secret|credentials/i.test(p));
        if (leaky.length > 0) findings.push(`sensitive params inferred as tool inputs: ${leaky.join(',')}`);
      }
    } catch (err) {
      findings.push(`sensitive param attack threw unexpectedly: ${err.message.slice(0, 80)}`);
    }

    // Attack 4: chrome-extension scheme URL
    try {
      const { tools } = await loadHarFile({
        log: {
          version: '1.2',
          entries: [
            { request: { method: 'GET', url: 'chrome-extension://xyz/api/data' }, response: { status: 200 } },
          ],
        },
      });
      if (tools.length > 0) findings.push(`chrome-extension URL produced ${tools.length} tools`);
    } catch (err) {
      // Extension URLs may produce zero tools (filtered) — that's fine, no throw needed
      findings.push(`extension URL threw (acceptable): ${err.message.slice(0, 80)}`);
    }

    // Attack 5: programmatic HAR with > 20 000 entries (hard ceiling)
    try {
      const huge = {
        log: {
          version: '1.2',
          entries: Array.from({ length: 20_001 }, (_, i) => ({
            request: { method: 'GET', url: `https://api.example.com/path/${i}` },
            response: { status: 200 },
          })),
        },
      };
      await loadHarFile(huge);
      findings.push('20 001-entry HAR was accepted (hard ceiling not enforced)');
    } catch (err) {
      if (!/hard ceiling|exceeds|too large|max/i.test(err.message)) {
        findings.push(`hard-ceiling refusal threw with unexpected message: ${err.message.slice(0, 80)}`);
      }
    }

    // Filter out the "extension URL threw" non-finding from finding count.
    const real = findings.filter((f) => !f.startsWith('extension URL threw'));
    if (real.length === 0) {
      return { verdict: 'pass', detail: '5 HAR attack shapes neutralized (SSRF, credential headers, sensitive params, extension URL, hard-ceiling)' };
    }
    return { verdict: 'fail', detail: real.join('; ') };
  },
};
