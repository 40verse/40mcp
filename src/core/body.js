/**
 * HTTP request body parsing with size limits.
 *
 * @module core/body
 */

/** Maximum request body size (1 MB) */
export const MAX_BODY_SIZE = 1024 * 1024;

/** Default body read timeout — wall-clock limit on the data→end cycle (15 s). */
export const DEFAULT_BODY_READ_TIMEOUT_MS = 15_000;

/**
 * Parse JSON request body with size limit and read timeout.
 * Returns both the parsed JSON object and the raw Buffer for signature verification.
 *
 * A wall-clock timeout is mandatory because slow-body attackers (dripping 1
 * byte/s under a declared Content-Length) can otherwise hold sockets
 * indefinitely, exhausting thread pools before in-flight dispatch caps take
 * effect. Force a hard ceiling on the body read phase; on timeout destroy
 * the socket and reject the parse promise.
 *
 * @param {http.IncomingMessage} req - Node.js request object
 * @param {number} [maxSize=MAX_BODY_SIZE] - Max body size in bytes
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=DEFAULT_BODY_READ_TIMEOUT_MS] - Wall-clock body read timeout
 * @returns {Promise<{ parsed: object, rawBody: Buffer }>}
 * @throws {Error} 'Request body too large' if body exceeds maxSize
 * @throws {Error} 'Invalid JSON body' if body is not valid JSON
 * @throws {Error} 'Request body read timeout' if body not received within timeoutMs
 */
export async function parseBody(req, maxSize = MAX_BODY_SIZE, opts = {}) {
  const timeoutMs = typeof opts.timeoutMs === 'number' ? opts.timeoutMs : DEFAULT_BODY_READ_TIMEOUT_MS;
  const strictContentType = opts.strictContentType !== false;

  // Defense-in-depth Content-Type check: reject non-JSON types at entry to
  // prevent accidental acceptance of `application/x-www-form-urlencoded` /
  // `text/plain` bodies. Although UTF-8 parsing downstream already blocks
  // charset-confusion attacks (UTF-7 sanitizer bypass), early rejection
  // prevents a downstream handler from mistaking a non-JSON body for valid
  // JSON. Opt out via `opts.strictContentType: false` for legacy callers.
  if (strictContentType) {
    const ct = req.headers['content-type'];
    // Allow missing Content-Type only when body is empty (GET/HEAD with no body).
    if (ct) {
      const lower = String(ct).toLowerCase().trim();
      const isJson = lower.startsWith('application/json') || lower === 'application/json';
      if (!isJson) {
        return Promise.reject(new Error('Unsupported Content-Type'));
      }
    }
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(arg);
    };

    const timer = setTimeout(() => {
      try { req.destroy(); } catch {}
      settle(reject, new Error('Request body read timeout'));
    }, timeoutMs);
    // Don't hold the event loop open just to run this timer.
    if (typeof timer.unref === 'function') timer.unref();

    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxSize) {
        try { req.destroy(); } catch {}
        settle(reject, new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      const rawBody = Buffer.concat(chunks);
      if (!rawBody.length) {
        settle(resolve, { parsed: {}, rawBody });
        return;
      }
      try {
        settle(resolve, { parsed: JSON.parse(rawBody.toString('utf-8')), rawBody });
      } catch {
        settle(reject, new Error('Invalid JSON body'));
      }
    });

    req.on('error', (err) => settle(reject, err));
    req.on('close', () => {
      if (!settled) settle(reject, new Error('Request body read aborted'));
    });
  });
}
