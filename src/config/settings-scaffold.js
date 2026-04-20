/**
 * Produce a starter `40mcp.settings.json` string.
 *
 * The validator rejects unknown top-level keys, so the scaffold is a fully
 * valid settings tree pre-populated with sensible defaults. Operators edit
 * in place; `40mcp settings --show` shows which keys are active vs. falling
 * through to defaults.
 *
 * @module config/settings-scaffold
 */

/**
 * @param {object} [opts]
 * @param {string} [opts.instanceName] - Display label for `instance.name`.
 * @returns {string}
 */
export function buildSettingsScaffold({ instanceName = 'my-instance' } = {}) {
  const scaffold = {
    instance: {
      name: instanceName,
      tags: [],
    },
    bridge: {
      transport: { type: 'stdio' },
      limits: {
        dispatch: { maxConcurrent: 50, requestTimeoutMs: 30000 },
        request: { maxBytes: '1MB' },
        response: { maxBytes: '10MB' },
      },
      network: { allowPrivate: true, strictSsrf: false },
    },
    frontdoor: {
      transport: { type: 'stdio' },
      auth: { requireBearerEnv: null, bearerFile: null },
      network: { allowedOrigins: [] },
      limits: {
        sse: {
          maxConnections: 100,
          maxSessionsPerIp: 10,
          maxSessionsPerPrincipal: 5,
          idleTimeoutMs: 120000,
        },
      },
      surface: { allowTools: [], denyTools: [], healthDetail: false },
      telemetry: { audit: true, events: true },
    },
  };
  return JSON.stringify(scaffold, null, 2) + '\n';
}
