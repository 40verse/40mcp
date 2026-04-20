/**
 * Structured security event emitter.
 *
 * Emits `[40mcp:event] <JSON>` to stderr — parallel to the existing
 * `[40mcp:audit]` channel in bridge.js. Log aggregators can grep on the
 * `[40mcp:event]` prefix and parse the JSON body for SIEM ingest.
 *
 * Used for security-relevant lifecycle signals (vault unseal/rotate,
 * webhook hmac failures, sse session activity, tenant ACL outcomes, etc.)
 * that are NOT per-tool-call audit entries but are operationally critical
 * for incident response.
 *
 * @module core/events
 */

/**
 * Scrub an arbitrary string before interpolating it into a stderr line.
 * Multiple call sites used to write raw attacker/upstream-controlled strings
 * (API error bodies, tool names, filenames, err.message) directly into
 * `process.stderr.write(...)` with newline terminators — a classic log-forgery
 * primitive. An attacker embedding `\n[40mcp:audit] {"fake":"entry"}\n` in the
 * controlled string would inject a fully-forged audit entry.
 *
 * This helper:
 *   1. Truncates at `max` characters (default 500)
 *   2. Replaces `\n`, `\r`, `\t`, and C0/C1 control characters + DEL with
 *      a single `?` (preserves length context without preserving the byte)
 *   3. Coerces non-strings via `String()` but never returns `undefined`
 *      or `null` literal text
 *
 * Call sites should use `safeLog(userControlledValue)` anywhere a
 * user/attacker/upstream-controlled string is interpolated into a
 * plain-text stderr line. Structured JSON lines are already protected
 * by `JSON.stringify`.
 */
export function safeLog(value, max = 500) {
  if (value == null) return '';
  const str = typeof value === 'string' ? value : String(value);
  const truncated = str.length > max ? str.slice(0, max) : str;
  // Replace C0 (0x00-0x1F), DEL (0x7F), C1 (0x80-0x9F), plus U+2028 LINE
  // SEPARATOR and U+2029 PARAGRAPH SEPARATOR. Several log renderers
  // (browser-based SIEM front-ends, JS-based JSON-line viewers) treat
  // U+2028/U+2029 as line breaks, so the log-forgery primitive survives
  // for those consumers without this additional scrub. ESC (0x1B) in the
  // C0 range is the lead byte for ANSI escape sequences that would
  // otherwise clobber operator terminals tailing stderr.
  return truncated.replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, '?');
}

/**
 * Telemetry config — set by the CLI from `40mcp.settings.json`
 * `frontdoor.telemetry.{audit, events}`. Call sites:
 *   - `emitEvent` here honors `.events`
 *   - `emitAuditLog` in bridge.js honors `.audit`
 * Default is "on" for both so library consumers outside the CLI keep full
 * visibility unless they explicitly opt out.
 */
const telemetryConfig = { audit: true, events: true };

export function setTelemetryConfig(next) {
  if (next && typeof next === 'object') {
    if (typeof next.audit === 'boolean') telemetryConfig.audit = next.audit;
    if (typeof next.events === 'boolean') telemetryConfig.events = next.events;
  }
}

export function getTelemetryConfig() {
  return { ...telemetryConfig };
}

/**
 * Instance metadata — set by the CLI from `settings.instance.*`.
 * When set, the `instance` field is folded into every `[40mcp:event]` and
 * `[40mcp:audit]` entry so the audit trail carries a friendly name and
 * tags alongside the canonical identifiers. Library consumers that never
 * call `setInstanceMetadata` see unchanged wire format (no `instance`
 * key at all) so existing parsers remain compatible.
 */
const instanceMetadata = { name: null, tags: [] };

export function setInstanceMetadata(next) {
  if (!next || typeof next !== 'object') return;
  if (typeof next.name === 'string' && next.name.length > 0) {
    instanceMetadata.name = next.name;
  } else if (next.name === null) {
    instanceMetadata.name = null;
  }
  if (Array.isArray(next.tags)) {
    instanceMetadata.tags = next.tags.filter((t) => typeof t === 'string');
  }
}

export function getInstanceMetadata() {
  return { name: instanceMetadata.name, tags: [...instanceMetadata.tags] };
}

/**
 * Build the `instance` field for inclusion in a telemetry entry.
 * Returns `undefined` when no metadata is set, so the caller can spread
 * conditionally (`...(buildInstanceField() ? { instance: ... } : {})`).
 */
export function buildInstanceField() {
  if (!instanceMetadata.name && instanceMetadata.tags.length === 0) return undefined;
  const out = {};
  if (instanceMetadata.name) out.name = instanceMetadata.name;
  if (instanceMetadata.tags.length > 0) out.tags = [...instanceMetadata.tags];
  return out;
}

/**
 * Format a `[<name> tag1,tag2]` suffix for stderr startup banners. Returns
 * the empty string when no metadata is configured so existing banner shapes
 * stay intact for library consumers and tests that never set instance data.
 */
export function instanceBannerSuffix() {
  if (!instanceMetadata.name && instanceMetadata.tags.length === 0) return '';
  const parts = [];
  if (instanceMetadata.name) parts.push(instanceMetadata.name);
  if (instanceMetadata.tags.length > 0) parts.push(instanceMetadata.tags.join(','));
  return ` [${parts.join(' ')}]`;
}

/**
 * Emit a structured event to stderr.
 * @param {string} type - Event type (e.g. 'vault.unseal', 'webhook.hmac_fail')
 * @param {object} [fields] - Additional structured fields
 */
export function emitEvent(type, fields = {}) {
  if (!telemetryConfig.events) return;
  try {
    const inst = buildInstanceField();
    const entry = {
      ts: new Date().toISOString(),
      event: type,
      ...(inst ? { instance: inst } : {}),
      ...fields,
    };
    process.stderr.write(`[40mcp:event] ${JSON.stringify(entry)}\n`);
  } catch {
    // Telemetry must never crash the host. Swallow serialization or stderr errors.
  }
}
