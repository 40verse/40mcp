/**
 * @typedef {object} ToolDef
 * @property {string} name - MCP tool name (snake_case recommended)
 * @property {string} description - Human-readable description for the agent
 * @property {string} method - HTTP method: GET, POST, PUT, PATCH, DELETE
 * @property {string} path - URL path with :param placeholders
 * @property {object} [queryMap] - Rename map: { toolArg: 'apiQueryParam' }
 * @property {object} [bodyMap] - Rename map: { toolArg: 'apiBodyField' }
 * @property {object} inputSchema - JSON Schema for the tool's input
 * @property {ResponseTransform} [response] - Response transform config
 * @property {ChainStep[]} [chain] - Compound tool chain steps (mutually exclusive with method/path)
 */

/**
 * @typedef {object} ResponseTransform
 * @property {string[]} [pick] - Keep only these fields (dot-notation supported)
 * @property {string[]} [omit] - Remove these fields
 * @property {number} [limit] - If array, keep first N items
 * @property {boolean} [flatten] - Convert nested objects to dot-notation keys
 * @property {boolean|string} [summary] - Add _summary metadata if truncated (string = custom template with {shown}/{total})
 * @property {number} [tokenBudget] - Max token estimate (chars/4 heuristic); truncates intelligently
 * @property {string} [template] - Format string for each item: '{name} ({email})'
 */

/**
 * @typedef {object} ChainStep
 * @property {string} call - Tool name to dispatch
 * @property {string} as - Key in merged result
 * @property {object} [args] - Arguments; supports $ref: '$args.field' or '$stepName.field.path'
 * @property {boolean} [optional=false] - If true, errors don't fail the chain
 */

/**
 * @typedef {object} ToolVersioning
 * @property {string} [version] - Tool version string (e.g., '1.0')
 * @property {boolean|string} [deprecated] - true or deprecation message
 * @property {string} [successor] - Name of replacement tool
 * @property {string} [removedIn] - Version when tool will be removed
 */

/**
 * @typedef {object} AuthConfig
 * @property {string} type - 'header' | 'bearer' | 'basic' | 'oauth2'
 * @property {string} [header] - Header name (for type='header')
 * @property {string} [envVar] - Env var holding the credential
 * @property {string} [value] - Static credential value (prefer envVar)
 * @property {string} [tokenUrl] - OAuth2 token endpoint (for type='oauth2')
 * @property {string} [clientId] - OAuth2 client ID (for type='oauth2')
 * @property {string} [clientIdEnv] - Env var for client ID (for type='oauth2')
 * @property {string} [clientSecret] - OAuth2 client secret (for type='oauth2')
 * @property {string} [clientSecretEnv] - Env var for client secret (for type='oauth2')
 * @property {string} [scope] - OAuth2 scope (for type='oauth2')
 * @property {string} [grantType] - OAuth2 grant type (default: 'client_credentials')
 */

/**
 * @typedef {object} BridgeConfig
 * @property {string} [name='rest-bridge'] - Server name (shown to MCP clients)
 * @property {string} [version='1.0.0'] - Server version
 * @property {string} baseUrl - REST API base URL (env vars interpolated: ${VAR})
 * @property {AuthConfig} [auth] - Auth config
 * @property {object} [hooks] - Lifecycle hooks
 * @property {Function} [hooks.beforeRequest] - Modify request before sending
 * @property {number} [hooks.timeoutMs] - Request timeout in ms (default: 30000)
 * @property {object} [transport] - Transport config
 * @property {string} [transport.type='stdio'] - 'stdio' | 'sse'
 * @property {number} [transport.port=8080] - SSE port
 * @property {Array<ToolDef>} tools - Tool definitions
 */

export {};
