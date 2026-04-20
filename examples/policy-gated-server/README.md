# Example: Policy-Gated Server

Three user management tools with three different policy levels: one that runs automatically, one that pauses for human approval, and one that's blocked entirely.

## What this demonstrates

`bridge.json` configures an MCP server where the same API has tools at three different trust levels:

| Tool | Policy | Behavior |
|------|--------|----------|
| `list_users` | `allow` | Runs immediately, no prompt |
| `update_user` | `require_approval` | Pauses — operator must approve before dispatch |
| `delete_user` | `deny` | Always rejected — never dispatched |

The LLM can call all three; policy enforcement is in the bridge layer, not the model layer.

## Run it

```bash
export API_TOKEN=your_token_here
npx 40mcp serve examples/policy-gated-server/bridge.json
```

When an MCP client calls `update_user`, the terminal will display an approval prompt:

```
[APPROVAL REQUIRED]
Tool:   update_user
Args:   { "user_id": "usr_123", "role": "admin" }

Approve? (y/N):
```

The tool call is held until you type `y` and press Enter. If you decline (or the process has no tty), the call returns a rejection error to the MCP client.

Calling `delete_user` returns an immediate policy rejection:

```json
{ "error": "PolicyDeniedError", "message": "Tool 'delete_user' is denied by policy" }
```

## Policy field syntax

In any tool definition in `bridge.json`:

```json
{ "policy": "allow" }           // default — no gate
{ "policy": "require_approval" } // human-in-the-loop prompt
{ "policy": "deny" }             // hard block
{ "policy": "log_only" }         // dispatch but log every call
```

## Programmatic approval (for CI / audit systems)

The stdin prompt is the default. For automated environments use `createCallbackApprovalHandler`:

```js
import { createPolicyGate, createCallbackApprovalHandler } from '40mcp';

const gate = createPolicyGate({
  dispatch: bridge.dispatch,
  approvalHandler: createCallbackApprovalHandler(async ({ tool, args }) => {
    // log to audit system, check external policy engine, etc.
    return myAuditSystem.approve(tool, args);
  }),
  toolPolicies: { update_user: 'require_approval', delete_user: 'deny' },
});
```

See `src/security/policy.js` and `examples/policy.js` for the full API.
