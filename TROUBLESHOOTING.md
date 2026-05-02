# 40mcp Troubleshooting Guide

A comprehensive guide to diagnosing and fixing common issues with the 40mcp universal API-to-MCP bridge.

> For the hardening rationale behind the defaults referenced below (SSRF guard, URL validation, prototype-pollution refusal, credential-logging prevention, sealed-vault invariants), see [docs/SAFE-DEFAULTS.md](docs/SAFE-DEFAULTS.md).

## Authentication Issues

### AUTH_MISSING / AUTH_EXPIRED / AUTH_INVALID

**Symptom:** Tool calls fail with "Authentication failed" or "Forbidden".

**Causes:**
- Environment variable is not set or is empty
- OAuth2 token has expired and cannot be refreshed
- API key format is incorrect or revoked
- Vault passphrase is wrong (sealed credentials)

**Fixes:**

**Missing auth env var:**

> **Important:** Never use `echo $API_KEY` — it prints the plaintext secret to your terminal and shell history. Use the vault instead (see [Sealed Vault](#sealed-vault-errors) below).

```bash
# Check if the env var is SET without revealing the value
[[ -z "${API_KEY}" ]] && echo "NOT SET" || echo "SET (value hidden)"

# Preferred: seal the key in the vault and reference it via seal:// ID
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.set('API_KEY', 'your-api-key').then(id => console.log('Sealed as:', id));
"
# Then update your config to use: { \"auth\": { \"type\": \"bearer\", \"value\": \"seal://<id>\" } }
```

**OAuth2 token refresh failure:**
```bash
# Verify client credentials are correct
npx 40mcp validate your-config.json | grep -A 5 "oauth2"

# Check network connectivity to token endpoint
curl -X POST https://oauth.provider.com/token \
  -d grant_type=client_credentials \
  -d client_id=$CLIENT_ID \
  -d client_secret=$CLIENT_SECRET
```

**Vault passphrase error:**
```bash
# The vault passphrase must be set before bridge startup
export VAULT_PASSPHRASE="<your-strong-passphrase-16+chars>"

# If you get "Vault integrity check failed", the vault file is corrupted
# Backup and delete .vault.json, then re-seal your secrets:
rm .vault.json.backup && mv .vault.json .vault.json.backup
# Re-run your vault setup code to reseal all secrets
```

**Config with sealed credentials:**
```json
{
  "auth": {
    "type": "bearer",
    "envVar": "GITHUB_TOKEN"
  }
}
```

If you're using `vault.unsealConfig()`, ensure the config references `seal://` IDs:
```json
{
  "auth": {
    "type": "bearer",
    "value": "seal://github-token-a1b2c3d4"
  }
}
```

**What is a `seal://` ID?** When you call `vault.set('MY_KEY', 'plaintext-value')`, the vault encrypts the secret and returns an opaque identifier like `seal://my-key-a1b2c3d4`. This ID is safe to commit, log, or share — it is a reference, not the secret. The plaintext is only decrypted in-memory at request time via `vault.unsealConfig()` or `vault.createAuthHook()`, and is never written anywhere after that.

---

## Sealed Vault Errors

### Seal ID Not Found

**Symptom:** `vault.unsealConfig()` throws "Seal ID not found: seal://..."

**Causes:**
- `.vault.json` file was deleted or is at a different path
- Vault was recreated and old seal IDs are no longer valid
- Wrong vault file is loaded (e.g., dev vault in production)

**Fix:**

```bash
# Verify the vault file exists at the expected path
ls -lh .vault.json

# Check which vault path your bridge config is using
# If vault file is missing, re-seal all secrets from your secure store
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.list().then(secrets => console.log(secrets.map(s => s.name)));
"
```

### Vault Integrity Check Failed

**Symptom:** `"Vault integrity check failed"` error on startup.

**Cause:** The vault file is corrupted or was tampered with. The HMAC over the ciphertext no longer matches.

**Fix:**

```bash
# Backup the corrupted vault first
cp .vault.json .vault.json.corrupted

# Wipe the vault (secrets are lost — recover from your secure store)
rm .vault.json

# Re-seal all secrets from scratch
node scripts/init-vault.js

# Restore config seal:// references to newly generated IDs
```

**Prevention:** Store vault passphrases in a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault). Never derive the passphrase from the secret itself.

### Wrong Passphrase

**Symptom:** Vault opens but `vault.get()` returns garbage or throws a decryption error.

**Cause:** `VAULT_PASSPHRASE` does not match the passphrase used when secrets were sealed.

**Fix:**

```bash
# Verify the correct passphrase is loaded
[[ -n "$VAULT_PASSPHRASE" ]] && echo "VAULT_PASSPHRASE is SET (value hidden)" || echo "VAULT_PASSPHRASE is NOT SET"

# If running in CI/CD, ensure the secret is injected correctly
# AWS example:
export VAULT_PASSPHRASE=$(aws secretsmanager get-secret-value \
  --secret-id vault-passphrase --query SecretString --output text)
```

### Debugging Vault Operations

```bash
DEBUG=40mcp:vault npx 40mcp serve config.json
```

This logs every vault operation (seal, unseal, token issue, token verify) without revealing plaintext values.

---

## Startup Failures

### CONFIG_INVALID / CONFIG_MISSING_FIELD

**Symptom:** Bridge fails to start; error mentions missing field or invalid schema.

**Common issues:**
- Missing required `baseUrl` or `tools` array
- Tool definitions missing required fields: `name`, `method`, `path`, `inputSchema`
- Invalid HTTP method (must be GET, POST, PUT, PATCH, DELETE)
- Transport config has conflicting settings

**Fixes:**

**Validate your config before starting:**
```bash
npx 40mcp validate ./your-config.json
```

**Minimal valid config:**
```json
{
  "baseUrl": "https://api.example.com",
  "tools": [
    {
      "name": "get_status",
      "method": "GET",
      "path": "/status",
      "inputSchema": {
        "type": "object",
        "properties": {},
        "required": []
      }
    }
  ]
}
```

**All required tool fields:**
```json
{
  "name": "list_users",
  "method": "GET",
  "path": "/users",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": { "type": "integer" },
      "offset": { "type": "integer" }
    },
    "required": []
  }
}
```

### Port Conflicts

**Symptom:** SSE transport fails with "EADDRINUSE" or "Address already in use".

**Fix:**

```bash
# Find the process using the port (default 3000 for SSE)
lsof -i :3000

# Kill the process
kill -9 <PID>

# Or use a different port in config
{
  "transport": {
    "type": "sse",
    "port": 3001
  }
}
```

### Node.js Version Incompatibility

**Symptom:** "Unexpected token" errors during import; Missing crypto APIs.

**Fix:**
```bash
# Check your Node version (requires >= 18)
node --version

# Upgrade if needed (use nvm or download from nodejs.org)
nvm install 20
nvm use 20
```

---

## Tool Execution Errors

### TOOL_NOT_FOUND

**Symptom:** "Tool 'xyz' not found in bridge" error.

**Causes:**
- Tool name misspelled in tool call
- Tool was not included in the bridge config
- Tool was dynamically removed or filtered

**Fix:**

```bash
# List available tools
npx 40mcp inspect ./your-config.json | grep "name:"

# Verify the tool name matches exactly (case-sensitive)
```

### TOOL_DEPRECATED

**Symptom:** Tool call succeeds but returns deprecation warning.

**Meaning:** The tool is scheduled for removal. Use the `successor` tool instead.

**Fix:**

```json
{
  "name": "old_api_call",
  "deprecated": "2026-01-01",
  "successor": "new_api_call",
  "method": "GET",
  "path": "/old"
}
```

Check your tool config for the `successor` field and migrate to it:
```bash
# Before (deprecated)
dispatch('old_api_call', args)

# After (use successor)
dispatch('new_api_call', args)
```

### API_TIMEOUT

**Symptom:** Tool call hangs or fails after ~30 seconds.

**Causes:**
- API endpoint is slow or unreachable
- Network connectivity issue
- API server is overloaded

**Fix:**

```bash
# Test API endpoint directly
curl -v https://api.example.com/users

# Increase timeout in config
{
  "hooks": {
    "timeoutMs": 60000
  }
}
```

### API_RATE_LIMIT (HTTP 429)

**Symptom:** Tool returns "Too many requests" after several calls.

**Causes:**
- API has a rate limit; you've exceeded it
- Rate limit window hasn't reset
- Multiple requests sent in parallel

**Fix:**

```js
// Add exponential backoff to your client code
async function callWithBackoff(bridge, tool, args, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await bridge.dispatch(tool, args);
    } catch (err) {
      if (err.bridgeCode === 'API_RATE_LIMIT' && i < maxRetries - 1) {
        const delay = Math.pow(2, i) * 1000; // 1s, 2s, 4s...
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
}
```

### API_SERVER_ERROR (HTTP 5xx)

**Symptom:** Tool call fails with "Server error 500/502/503".

**Causes:**
- API server is down or restarting
- API returned an error due to internal server state
- Request is malformed in a way the server doesn't handle gracefully

**Fix:**

```bash
# Check the API status page
curl -i https://status.example.com

# Retry with backoff (same as rate limit above)
# Monitor the API status and wait for recovery
```

---

## Token Budget / Response Transform Issues

### Truncated Responses

**Symptom:** Large responses are cut off; data ends with "..." or partial JSON.

**Cause:** Response transforms (`tokenBudget`, `limit`, `summary`) are truncating output to save context window.

**Fix:**

**Increase token budget in tool config:**
```json
{
  "response": {
    "tokenBudget": 8000
  }
}
```

**Use `pick` to select only needed fields:**
```json
{
  "response": {
    "pick": ["id", "name", "email"]
  }
}
```

**Use `limit` to cap array size:**
```json
{
  "response": {
    "limit": 10
  }
}
```

**Disable truncation for a specific tool:**
```json
{
  "response": {
    "tokenBudget": 0
  }
}
```

### Pick/Omit Not Working

**Symptom:** `pick` or `omit` transforms don't filter fields as expected.

**Causes:**
- Field names don't exist in the response
- Using wrong dot-notation for nested fields
- Transform is applied to wrong tool

**Fix:**

```bash
# First, see the actual response structure
npx 40mcp inspect ./config.json | grep -A 20 "tool_name"

# Use correct dot-notation for nested fields
{
  "response": {
    "pick": ["user.id", "user.name", "user.email"]
  }
}

# Check that transform is on the right tool definition
```

---

## Chain Errors

### CHAIN_DEPTH_EXCEEDED (max depth is 10)

**Symptom:** Chain execution fails with "depth exceeded" error.

**Cause:** A chain has more than 10 steps, or contains infinite recursion via `$references`.

**Fix:**

**Reduce chain steps to <= 10:**
```json
{
  "name": "long_chain",
  "chain": [
    { "call": "step1", "as": "s1" },
    { "call": "step2", "args": { "id": "$s1.id" }, "as": "s2" },
    { "call": "step3", "args": { "id": "$s2.id" }, "as": "s3" }
  ]
}
```

**Break into multiple tools instead:**
```js
// Instead of one 20-step chain, create 2 ten-step chains
const userWithDetails = await bridge.dispatch('get_user_with_details', { id: 123 });
const userWithActivity = await bridge.dispatch('get_user_activity', { id: userWithDetails.id });
```

### CHAIN_CIRCULAR_DEPENDENCY

**Symptom:** Chain execution fails with "circular dependency" error.

**Cause:** A step references its own output via `$references`, creating a loop.

**Example:**
```json
{
  "call": "get_thing",
  "args": { "thing_id": "$output.id" },
  "as": "output"
}
```

**Fix:** Ensure each step's `as` name is used only in *later* steps, never in earlier ones.

### CHAIN_STEP_FAILED

**Symptom:** Chain stops partway through with "step failed" error; partial results available.

**Cause:** One of the steps in the chain failed (nested tool error).

**Fix:**

```json
{
  "call": "optional_step",
  "optional": true,
  "as": "opt"
}
```

Use `optional: true` to allow the chain to continue even if a step fails.

**View partial results in error details:**
```js
try {
  await bridge.dispatch('my_chain', args);
} catch (err) {
  if (err.bridgeCode === 'CHAIN_STEP_FAILED') {
    console.log('Partial results:', err.details.partialResults);
  }
}
```

### CHAIN_REF_UNDEFINED

**Symptom:** Chain fails with "undefined reference" error.

**Cause:** A step references an earlier step output that doesn't exist.

**Example:**
```json
{
  "call": "step2",
  "args": { "user_id": "$nonexistent_step.id" },
  "as": "s2"
}
```

**Fix:** Verify the referenced step name matches exactly and is declared before this step.

---

## SSE Transport Issues

### Connection Refused

**Symptom:** "Cannot connect to server" or "ECONNREFUSED".

**Causes:**
- Bridge is not running
- Bridge is listening on a different port/host
- Network firewall is blocking the port

**Fix:**

```bash
# Start the bridge with explicit host/port
npx 40mcp serve config.json --port 3000 --host 0.0.0.0

# Verify bridge is listening
lsof -i :3000

# Test connection
curl http://localhost:3000/status
```

### CORS Errors

**Symptom:** Browser console shows "Cross-Origin Request Blocked" or 403 errors.

**Cause:** SSE server's `allowedOrigins` doesn't include your client's origin.

**Fix:**

```json
{
  "transport": {
    "type": "sse",
    "port": 3000,
    "allowedOrigins": ["http://localhost:3000", "https://app.example.com"]
  }
}
```

### maxSessions Limit Reached

**Symptom:** New client connections fail with "max sessions exceeded".

**Cause:** Too many concurrent SSE clients are connected.

**Fix:**

```json
{
  "transport": {
    "type": "sse",
    "maxSessions": 100
  }
}
```

**Increase limit or close idle sessions:**
```js
// Browsers should implement automatic cleanup for closed tabs
// Manually close a session by disconnecting the SSE client
client.close();
```

### "Already connected to a transport" (single-session SSE on `serve`)

**Symptom:** Second concurrent SSE client connection fails with `"Already connected to a transport"`.

**Cause:** `cmdServe` uses one shared `Server` instance across SSE sessions; the MCP SDK's `Server.connect(transport)` rejects a second attachment while the first is active.

**Workarounds:**

1. **Use `link` instead of `serve`** — `cmdLink` mints a fresh `Server` per session:
   ```bash
   40mcp link .mcp.json --sse 8080 --host 0.0.0.0
   ```

2. **Front multiple `serve` instances behind a reverse proxy** — balance load across processes:
   ```bash
   # Terminal 1
   40mcp serve config.json --sse 3001
   # Terminal 2
   40mcp serve config.json --sse 3002
   # Then use nginx/HAProxy to load-balance across both
   ```

### Session Cleanup Issues

**Symptom:** Memory usage grows; old sessions don't disconnect.

**Cause:** Client disconnected but server didn't detect it; sessions accumulate.

**Fix:**

```bash
# Monitor active sessions (check bridge logs)
# Sessions auto-cleanup after inactivity (default: 5 minutes)

# Force restart bridge to clear all sessions
pkill -f "40mcp serve"
npx 40mcp serve config.json
```

---

## HAR Loader Issues

### Low Confidence Tools

**Symptom:** Some tools marked "confidence: low" or not generated at all.

**Cause:** Tool was observed only once or twice in the HAR; signature varies.

**Fix:**

```bash
# Increase minObservations to require more evidence
npx 40mcp from-har recording.har --min-observations 5
```

### minObservations Filtering

**Symptom:** Tools you expected are missing from the generated config.

**Cause:** Tool signature appeared fewer than `minObservations` times.

**Fix:**

```bash
# Lower the threshold (default: 3)
npx 40mcp from-har recording.har --min-observations 1

# Check the HAR for duplicate calls
# Make sure you're capturing the API usage you care about
```

### Auth Headers in HAR

**Symptom:** Your API key is visible in the generated config or HAR export.

**Importance:** HAR files and configs should NEVER be committed with plaintext secrets. The moment a key appears in plaintext in git history, treat it as compromised and rotate it.

**Fix:**

```bash
# Step 1: Redact auth headers from the HAR before committing or sharing
# (jq strips Authorization headers in-place)
jq 'del(.log.entries[].request.headers[] | select(.name | test("^[Aa]uthorization$|^[Xx]-[Aa][Pp][Ii]-[Kk]ey$")))' \
  recording.har > recording.redacted.har

# Step 2: Seal the real credentials in the vault
# Note: VAULT_PASSPHRASE via env var is local/dev only.
# In production, use the vault daemon instead (40mcp vault daemon start).
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.set('GITHUB_TOKEN', process.env.GITHUB_TOKEN_PLAINTEXT)
    .then(id => console.log('Sealed:', id));
"

# Step 3: In the generated config, replace the plaintext auth value
# Before (generated from HAR — DO NOT COMMIT):
#   "auth": { "type": "bearer", "value": "<your-github-token>" }
#
# After (safe to commit):
#   "auth": { "type": "bearer", "value": "seal://github-token-a1b2c3d4" }
```

---

## Webhook Issues

### HMAC Validation Failures

**Symptom:** Webhook route rejects all requests with "Secret validation failed".

**Causes:**
- Webhook secret doesn't match the API provider's secret
- HMAC header format is wrong (missing "sha256=" prefix)
- Request body is modified between verification and parsing

**Fix:**

```js
// Webhook secret must match the provider (e.g., GitHub, Stripe)
const routes = [
  {
    path: '/webhooks/github',
    method: 'POST',
    tool: 'github_event_dispatch',
    secret: {
      type: 'hmac',
      envVar: 'GITHUB_WEBHOOK_SECRET',
      header: 'X-Hub-Signature-256'  // GitHub uses this header
    }
  }
];

// Set the secret from GitHub webhook settings
export GITHUB_WEBHOOK_SECRET="<your-webhook-secret>"
```

**Verify HMAC calculation locally:**
```bash
# Generate the same signature as the provider
echo -n '{"action":"opened"}' | \
  openssl dgst -sha256 -hmac "your-secret" -hex
```

### Async vs Sync Response Modes

**Symptom:** Webhook provider times out; your tool takes too long to respond.

**Solution:** Use async mode for long-running tools.

**Sync mode (default, blocks webhook response):**
```js
{
  path: '/webhooks/quick-action',
  tool: 'fast_operation',
  async: false  // Wait for tool result before responding
}
```

**Async mode (fire-and-forget):**
```js
{
  path: '/webhooks/slow-action',
  tool: 'slow_operation',
  async: true  // Respond immediately, execute in background
}
```

### Port Conflicts

Same as SSE transport port conflicts (see above).

---

## Policy Gate Issues

### Approval Timeouts

**Symptom:** Tool call fails with "Approval timed out" error.

**Cause:** Human didn't respond within the timeout window (default: 60 seconds).

**Fix:**

```js
const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  approvalHandler: createStdinApprovalHandler(),
  approvalTimeoutMs: 120_000  // Increase to 2 minutes
});
```

**Or use a callback handler with notification:**
```js
const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  approvalHandler: createCallbackApprovalHandler(async (context) => {
    // Send Slack notification
    await notifySlack({
      text: `Approval required for ${context.tool}`,
      approve_url: '...'
    });
    // Wait for response
    return await waitForApprovalWebhook();
  }),
  approvalTimeoutMs: 300_000  // 5 minutes
});
```

### Stdin Approval Not Showing

**Symptom:** No approval prompt appears; tool call fails immediately.

**Causes:**
- stdin is not connected (running in background)
- No approval handler configured
- Tool policy is `deny` not `require_approval`

**Fix:**

```bash
# Run with stdin connected
npx 40mcp serve config.json < /dev/tty

# Or use a callback-based approval handler instead of stdin
```

**Verify tool has correct policy:**
```json
{
  "name": "delete_user",
  "policy": "require_approval",
  "method": "DELETE",
  "path": "/users/{user_id}"
}
```

### Deny Policies Blocking Expected Calls

**Symptom:** Safe tools are blocked by deny policy.

**Cause:** Tool or action type is in the deny list.

**Fix:**

```js
const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  toolPolicies: {
    'list_users': 'allow',      // Safe read
    'create_user': 'require_approval',  // Needs approval
    'delete_user': 'deny',      // Never allow
  }
});
```

**Or use action type policies:**
```js
const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  dangerousActions: ['delete', 'destroy', 'purge'],
  defaultPolicy: 'allow'
});
```

---

## Debug Tips

### Enable Debug Output

**Via environment variable:**
```bash
DEBUG=40mcp:* npx 40mcp serve config.json
DEBUG=40mcp:bridge npx 40mcp serve config.json  # Just bridge logs
DEBUG=40mcp:vault npx 40mcp serve config.json   # Just vault logs
```

**Via code:**
```js
import { debug } from 'util';
process.env.DEBUG = '40mcp:*';

// Or use the library's internal logger
import { createRestBridge } from '40mcp';
const bridge = await createRestBridge({
  // ... config
  hooks: {
    beforeRequest: async (req) => {
      console.log('[DEBUG]', req.method, req.url);
      return null;
    }
  }
});
```

### Use `40mcp inspect` Command

**List all tools with full definitions:**
```bash
npx 40mcp inspect config.json
```

**Filter to specific tool:**
```bash
npx 40mcp inspect config.json | grep -A 30 "name.*get_user"
```

### Use `40mcp validate` Command

**Comprehensive config validation:**
```bash
npx 40mcp validate config.json --verbose
```

**Fixes validation errors systematically:**
```bash
npx 40mcp validate config.json 2>&1 | head -20
# Fix errors in config.json
npx 40mcp validate config.json  # Verify
```

### Capture Error Details

**In JavaScript:**
```js
try {
  await bridge.dispatch('tool_name', args);
} catch (err) {
  // BridgeError object
  console.log('Code:', err.bridgeCode);
  console.log('Message:', err.message);
  console.log('Details:', err.details);
  
  // If API error
  if (err.details.statusCode) {
    console.log('HTTP Status:', err.details.statusCode);
    console.log('Method:', err.details.method);
    console.log('Path:', err.details.path);
  }
}
```

### Test OAuth2 Token Refresh

**Manually verify OAuth2 is working:**
```bash
# Get a token using your client credentials
curl -X POST https://oauth.provider.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET"

# Use the token in a request
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/protected
```

### Monitor Network Requests

**Use tools like mitmproxy to intercept and inspect:**
```bash
# Install mitmproxy
brew install mitmproxy

# Start proxy
mitmproxy --listen-port 8888

# Point 40mcp through the proxy (via environment)
# This requires custom beforeRequest hook
```

---

## Common Patterns and Solutions

### Pattern: Config Validation Before Deploy

Always validate before production:
```bash
set -e
npx 40mcp validate config.prod.json
npx 40mcp inspect config.prod.json > /tmp/tools.txt
# Review tools.txt for sanity
npm test
# Deploy
```

### Pattern: Vault Initialization

Never commit plaintext secrets. The rule: if it's a secret, it goes in the vault, never in a file.

```bash
# 1. Create vault and seal secrets (one-time)
node scripts/init-vault.js

# 2. Commit .vault.json ONLY (it is encrypted — safe to commit)
git add .vault.json
# NEVER: git add .env  ← This would commit plaintext secrets

# 3. Ensure .env and any plaintext credential files are gitignored
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
git add .gitignore

# 4. Load VAULT_PASSPHRASE at runtime from safe store (never hardcode it)
export VAULT_PASSPHRASE=$(aws secretsmanager get-secret-value \
  --secret-id vault-pass --query SecretString --output text)

# 5. Start bridge — secrets are unsealed JIT, never persisted
npx 40mcp serve config.json
```

**What gets committed vs. what stays secret:**

| File | Commit? | Why |
|------|---------|-----|
| `.vault.json` | Yes | Encrypted ciphertext — no plaintext secrets |
| Config JSON with `seal://` IDs | Yes | IDs are opaque references, not secrets |
| `.env` | **Never** | Contains plaintext credentials |
| `VAULT_PASSPHRASE` | **Never** | The master key — store in secrets manager only |

### Pattern: Policy Gates with Multiple Approval Methods

Fallback from Slack to stdin if webhook unavailable:
```js
const approvalHandler = async (context) => {
  try {
    return await notifySlack(context);
  } catch {
    // Fallback to stdin
    return await stdinApprovalHandler(context);
  }
};

const gated = createPolicyGate({
  dispatch: bridge.dispatch,
  approvalHandler,
  toolPolicies: { 'dangerous_tool': 'require_approval' }
});
```

### Pattern: Webhook Ingestion with Chaining

Webhooks can trigger chains:
```js
const routes = [
  {
    path: '/webhooks/github-push',
    tool: 'full_ci_pipeline',  // A chain that builds, tests, deploys
    secret: { type: 'hmac', envVar: 'GITHUB_SECRET' },
    argMap: {
      repo: '$body.repository.full_name',
      branch: '$body.ref'
    }
  }
];
```

---

## Accidentally Committed a Plaintext Secret

**This is a security incident. Act immediately.**

A secret is compromised the moment it touches git history — even if you delete the file in the next commit, the secret is still readable in the history.

### Step 1: Rotate the key (do this first, before anything else)

```bash
# Revoke and regenerate the key at the provider's dashboard
# GitHub: Settings → Developer Settings → Personal Access Tokens → Revoke
# Stripe: Dashboard → API Keys → Roll
# AWS: IAM → Users → Security credentials → Make inactive → Delete
```

### Step 2: Strip from git history

```bash
# Install BFG Repo Cleaner (faster than git filter-branch)
brew install bfg

# Remove the file that contained the secret
bfg --delete-files secrets.json

# Or replace the literal secret value everywhere in history
echo "<compromised-github-token>" > secrets.txt
bfg --replace-text secrets.txt

# Clean refs and force-push
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push origin --force --all
```

> Note: If this is a shared repository, all collaborators must re-clone after the history rewrite. GitHub also has a "Secret scanning" feature that alerts on known secret patterns — check your repo's Security tab.

### Step 3: Seal the new key in the vault

```bash
# Never put the new key in a file or env var directly
# Seal it immediately
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.set('GITHUB_TOKEN', '<rotated-github-token>')
    .then(id => console.log('New seal ID:', id));
"
# Update your config to reference the new seal:// ID
```

### Step 4: Verify no other plaintext secrets exist

```bash
# Scan for common secret patterns in tracked files
git grep -E "(ghp[_]|sk[_]live[_]|AKIA|Bearer [A-Za-z0-9+/]{20,})" HEAD

# Scan git history for the old pattern
git log --all -p | grep -E "(ghp[_]|sk[_]live[_]|AKIA)" | head -20
```

---

## Key Rotation

When an API key is compromised, expires, or is being cycled as a security practice:

```bash
# Step 1: Seal the new key alongside the old one (zero-downtime rotation)
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.set('GITHUB_TOKEN_V2', '<new-github-token>')
    .then(id => console.log('New seal ID:', id));
"

# Step 2: Update your config to reference the new seal:// ID
# No plaintext ever appears in the config file

# Step 3: Remove the old key from the vault
node -e "
  const { createVault } = require('40mcp');
  const vault = createVault({ path: '.vault.json', passphrase: process.env.VAULT_PASSPHRASE });
  vault.delete('GITHUB_TOKEN').then(() => console.log('Old key deleted'));
"

# Step 4: Revoke the old key at the provider
# The old key no longer appears in the vault, and the new key was never plaintext anywhere
```

**The sealed vault is designed to ensure:** The plaintext value of `GITHUB_TOKEN_V2` exists only in `.vault.json` (encrypted) and in memory during active requests. It never appears in logs, config files, environment variables, or git history.

---

## Getting Help

- **Config validation errors:** Run `npx 40mcp validate config.json --verbose`
- **Unknown error code:** Check `/src/errors.js` in the 40mcp source
- **Community configs:** Check `configs/` directory for working examples (github.json, stripe.json, etc.)
- **API documentation:** Ensure your API docs match your config paths and methods
- **GitHub Issues:** Report bugs at [40verse/40mcp](https://github.com/40verse/40mcp)
