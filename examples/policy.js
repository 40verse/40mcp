/**
 * Example: Policy Gates (Human-in-the-Loop Approval)
 *
 * Demonstrates how to wrap a bridge with policy gates to require human
 * approval for dangerous actions (delete, reset, etc.).
 *
 * Features:
 * 1. Tool-specific policies (allow, deny, require_approval, log_only)
 * 2. Action-type based policies (dangerous actions always require approval)
 * 3. CLI approval prompts via stdin
 * 4. Callback-based approval (custom handlers, webhooks, Slack)
 * 5. Audit logging with sanitization
 * 6. Approval timeouts and fallback strategies
 *
 * Run (CLI approval):
 *   ADMIN_API_KEY="..." node examples/policy.js
 *
 * Run (custom callback, e.g., Slack):
 *   ADMIN_API_KEY="..." SLACK_WEBHOOK_URL="..." node examples/policy.js --slack
 */

import { createRestBridge, createPolicyGate, createStdinApprovalHandler, createCallbackApprovalHandler as _createCallbackApprovalHandler } from '../src/index.js';
import process from 'node:process';

// ─── Step 1: Create a bridge with dangerous tools ──────────────────────────

async function createAdminBridge() {
  console.log('Creating bridge with admin tools...\n');

  const bridge = await createRestBridge({
    name: 'admin-api-bridge',
    baseUrl: 'https://api.example.com/admin',
    auth: {
      type: 'bearer',
      envVar: 'ADMIN_API_KEY',
    },
    tools: [
      {
        name: 'list_users',
        description: 'List all users (safe, read-only)',
        method: 'GET',
        path: '/users',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'integer', default: 10 },
            offset: { type: 'integer', default: 0 },
          },
          required: [],
        },
      },
      {
        name: 'get_user',
        description: 'Get user details (safe, read-only)',
        method: 'GET',
        path: '/users/{user_id}',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string' },
          },
          required: ['user_id'],
        },
      },
      {
        name: 'create_user',
        description: 'Create a new user (requires approval)',
        method: 'POST',
        path: '/users',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            name: { type: 'string' },
            role: { type: 'string', enum: ['user', 'admin'] },
          },
          required: ['email', 'name'],
        },
      },
      {
        name: 'reset_password',
        description: 'Reset user password (dangerous)',
        method: 'POST',
        path: '/users/{user_id}/reset-password',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string' },
            temporary_password: { type: 'string' },
          },
          required: ['user_id', 'temporary_password'],
        },
      },
      {
        name: 'delete_user',
        description: 'Permanently delete a user (dangerous, blocked)',
        method: 'DELETE',
        path: '/users/{user_id}',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string' },
            reason: { type: 'string' },
          },
          required: ['user_id'],
        },
      },
      {
        name: 'update_permissions',
        description: 'Update user permissions (requires approval)',
        method: 'PATCH',
        path: '/users/{user_id}/permissions',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string' },
            permissions: { type: 'array', items: { type: 'string' } },
          },
          required: ['user_id', 'permissions'],
        },
      },
    ],
  });

  console.log('✓ Bridge created with', bridge.tools.length, 'admin tools');
  return bridge;
}

// ─── Step 2: Create stdin approval handler (CLI) ────────────────────────────

function showStdinApprovalExample() {
  console.log('\n=== Stdin-Based Approval (CLI) ===\n');

  console.log('Usage: createStdinApprovalHandler()');
  console.log('');
  console.log('When require_approval tool is called:');
  console.log('1. Displays action details in a formatted box');
  console.log('2. Reads user input from stdin');
  console.log('3. Returns "approve" or "deny"');
  console.log('');

  console.log('Example output:');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║  🛡️  POLICY GATE — APPROVAL REQUIRED            ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  Tool:  delete_user                              ║');
  console.log('║  Time:  2026-04-06T10:30:45.123Z                 ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  {                                               ║');
  console.log('║    "user_id": "user_123",                        ║');
  console.log('║    "reason": "Inactive account"                  ║');
  console.log('║  }                                               ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  Approve? (y/n):                                 ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
  console.log('Type "y" or "yes" to approve, anything else to deny.');
}

// ─── Step 3: Create callback approval handler (custom logic) ────────────────

async function createCallbackApprovalExample() {
  console.log('\n=== Callback-Based Approval (Custom) ===\n');

  // Example: Slack notification with approval link
  const slackApprovalHandler = async (context) => {
    const { tool, args, timestamp } = context;

    console.log('Would send Slack notification:');
    console.log(`  Channel: #security-approvals`);
    console.log(`  Title: Approval Required`);
    console.log(`  Tool: ${tool}`);
    console.log(`  Time: ${timestamp}`);
    console.log(`  Args: ${JSON.stringify(args, null, 2)}`);
    console.log('');
    console.log('In a real scenario:');
    console.log('  1. Send message to Slack with approve/deny buttons');
    console.log('  2. Store approval request in database');
    console.log('  3. Wait for user interaction');
    console.log('  4. Return "approve" or "deny"');
    console.log('');

    // Simulated response (in real code, would wait for webhook)
    return 'approve';
  };

  return slackApprovalHandler;
}

// ─── Step 4: Create policy gate with rules ──────────────────────────────────

async function createPolicyGateWithRules(bridge, useSlackApproval = false) {
  console.log('\n=== Policy Gate Configuration ===\n');

  // Define per-tool policies
  const toolPolicies = {
    // Read-only tools — always allow
    'list_users': 'allow',
    'get_user': 'allow',

    // Moderate risk — require approval
    'create_user': 'require_approval',
    'update_permissions': 'require_approval',

    // High risk — deny (prevent accidental use)
    'delete_user': 'deny',
  };

  // Use different approval handlers based on mode
  let approvalHandler;
  if (useSlackApproval) {
    const slackHandler = await createCallbackApprovalExample();
    approvalHandler = slackHandler;
  } else {
    // Use CLI stdin approval
    approvalHandler = createStdinApprovalHandler();
  }

  // Create the policy gate
  const gated = createPolicyGate({
    dispatch: bridge.dispatch,
    toolPolicies,
    approvalHandler,
    approvalTimeoutMs: 120_000, // 2 minutes for approval
    defaultPolicy: 'allow', // Default policy for unlisted tools
    dangerousActions: ['delete', 'destroy', 'purge', 'reset'], // Dangerous action types
    logger: (level, message, context) => {
      const prefix = {
        info: 'ℹ️',
        warn: '⚠️',
        deny: '🛑',
      }[level] || '📝';

      console.log(`[POLICY] ${prefix} ${message}`);
      if (context && Object.keys(context).length > 0) {
        console.log('  Context:', JSON.stringify(context, null, 2).split('\n').join('\n  '));
      }
    },
  });

  console.log('✓ Policy gate created with rules:');
  Object.entries(toolPolicies).forEach(([tool, policy]) => {
    const emoji = policy === 'allow' ? '✓' : policy === 'require_approval' ? '⚠️' : '🛑';
    console.log(`  ${emoji} ${tool}: ${policy}`);
  });

  return gated;
}

// ─── Step 5: Demonstrate policy enforcement ────────────────────────────────

async function demonstratePolicies() {
  console.log('\n=== Policy Enforcement Examples ===\n');

  console.log('Scenario 1: ALLOW (read-only)');
  console.log('  Call: list_users()');
  console.log('  Policy: allow');
  console.log('  Result: ✓ Executed immediately\n');

  console.log('Scenario 2: REQUIRE_APPROVAL (moderate risk)');
  console.log('  Call: create_user()');
  console.log('  Policy: require_approval');
  console.log('  Result: ⚠️ Show approval prompt, wait for y/n\n');

  console.log('Scenario 3: DENY (high risk)');
  console.log('  Call: delete_user()');
  console.log('  Policy: deny');
  console.log('  Result: 🛑 Blocked, throws AUTH_MISSING error\n');

  console.log('Scenario 4: DANGEROUS ACTION TYPE');
  console.log('  Call: reset_password() (action: reset)');
  console.log('  Policy: [not explicitly set]');
  console.log('  Result: ⚠️ "reset" is in dangerousActions, requires approval\n');
}

// ─── Step 6: Show audit logging and sanitization ────────────────────────────

function showAuditLogging() {
  console.log('\n=== Audit Logging & Sanitization ===\n');

  console.log('Sensitive fields are redacted in logs:');
  console.log('  - password');
  console.log('  - secret');
  console.log('  - token');
  console.log('  - api_key');
  console.log('  - webhook_secret\n');

  console.log('Example call with sensitive data:');
  console.log(JSON.stringify({
    user_id: 'user_123',
    password: '<your-secret-password>',
    api_key: 'EXAMPLE_API_KEY_PLACEHOLDER',
  }, null, 2));

  console.log('\nLogged as:');
  console.log(JSON.stringify({
    user_id: 'user_123',
    password: '***REDACTED***',
    api_key: '***REDACTED***',
  }, null, 2));

  console.log('\nWhy sanitize logs:');
  console.log('  - Prevent accidental secret exposure');
  console.log('  - Safe to ship logs to audit trail');
  console.log('  - Compliance with security policies');
}

// ─── Step 7: Show approval timeout and fallback ──────────────────────────

function showApprovalTimeoutStrategy() {
  console.log('\n=== Approval Timeout & Fallback ===\n');

  console.log('Default timeout: 60 seconds (configurable)');
  console.log('');

  console.log('Timeline:');
  console.log('  0s    - Tool called, approval prompt shown');
  console.log('  30s   - User thinking...');
  console.log('  60s   - Timeout! No response from user');
  console.log('  Result: Error thrown, tool NOT executed\n');

  console.log('To extend timeout:');
  console.log('');
  console.log('const gated = createPolicyGate({');
  console.log('  ...');
  console.log('  approvalTimeoutMs: 300_000 // 5 minutes');
  console.log('});');
  console.log('');

  console.log('Fallback strategies:');
  console.log('  1. Use stdin approval for CLI use');
  console.log('  2. Use callback approval for web/Slack');
  console.log('  3. Implement retry logic in your app');
}

// ─── Step 8: Best practices ────────────────────────────────────────────────

function showBestPractices() {
  console.log('\n=== Best Practices for Policy Gates ===\n');

  console.log('1. Define clear policies per tool:');
  console.log('   - Read operations: allow');
  console.log('   - Write operations: require_approval');
  console.log('   - Delete operations: deny (or require approval + admins only)');
  console.log('');

  console.log('2. Categorize actions by risk:');
  console.log('   - dangerousActions: delete, destroy, purge, reset, etc.');
  console.log('   - These automatically trigger require_approval');
  console.log('');

  console.log('3. Use appropriate approval handlers:');
  console.log('   - stdin: CLI/REPL use (interactive)');
  console.log('   - callback: Web/Slack/custom integrations');
  console.log('   - webhook: Asynchronous approval flows');
  console.log('');

  console.log('4. Log all decisions for audit trail:');
  console.log('   - Log approved, denied, timed out');
  console.log('   - Include timestamp, user, tool, args (sanitized)');
  console.log('');

  console.log('5. Sanitize sensitive fields:');
  console.log('   - Never log passwords, tokens, API keys');
  console.log('   - Policy gate auto-redacts common fields');
  console.log('');

  console.log('6. Set reasonable timeouts:');
  console.log('   - CLI approval: 2-5 minutes');
  console.log('   - Slack approval: 5-30 minutes');
  console.log('   - Webhook approval: depends on SLA');
  console.log('');

  console.log('7. Implement multi-level approval for critical ops:');
  console.log('   - Tier 1: Tool level approval');
  console.log('   - Tier 2: Secondary verification (e.g., 2FA)');
  console.log('   - Tier 3: Audit logging to centralized system');
  console.log('');

  console.log('8. Test policy enforcement:');
  console.log('   - Verify allow policies execute');
  console.log('   - Verify deny policies block');
  console.log('   - Verify approval prompts appear');
  console.log('   - Verify timeout handling works');
  console.log('');
}

// ─── Step 9: Integration example ────────────────────────────────────────────

async function showIntegrationExample() {
  console.log('\n=== Complete Integration Example ===\n');

  console.log('Code structure:');
  console.log('');
  console.log('// 1. Create bridge with tools');
  console.log('const bridge = await createRestBridge({ ... });');
  console.log('');
  console.log('// 2. Wrap with policy gate');
  console.log('const gated = createPolicyGate({');
  console.log('  dispatch: bridge.dispatch,');
  console.log('  toolPolicies: {');
  console.log('    "list_users": "allow",');
  console.log('    "delete_user": "deny",');
  console.log('    "create_user": "require_approval",');
  console.log('  },');
  console.log('  approvalHandler: createStdinApprovalHandler(),');
  console.log('});');
  console.log('');
  console.log('// 3. Use gated dispatch');
  console.log('await gated("list_users", {}); // ✓ Allowed');
  console.log('await gated("create_user", {email: "..."}); // ⚠️ Approval required');
  console.log('await gated("delete_user", {user_id: "..."}); // 🛑 Blocked');
  console.log('');
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log('40mcp Policy Gates Example\n');
  console.log('Demonstrates human-in-the-loop approval for dangerous actions.\n');

  try {
    // Create the admin bridge
    const bridge = await createAdminBridge();

    // Show approval handlers
    showStdinApprovalExample();
    await createCallbackApprovalExample();

    // Create policy gate
    const useSlack = process.argv.includes('--slack');
    const _gated = await createPolicyGateWithRules(bridge, useSlack);

    // Demonstrate policies
    demonstratePolicies();
    showAuditLogging();
    showApprovalTimeoutStrategy();
    showBestPractices();
    showIntegrationExample();

    console.log('\n✓ Policy gates example initialized!\n');
    console.log('Configuration:');
    console.log('  - Read tools (allow): list_users, get_user');
    console.log('  - Moderate tools (require_approval): create_user, update_permissions');
    console.log('  - Dangerous tools (deny): delete_user');
    console.log('  - Approval timeout: 2 minutes');
    console.log('  - Dangerous actions: delete, destroy, purge, reset\n');

    console.log('To use in your code:');
    console.log('  const result = await gated("tool_name", { arg: value });');
    console.log('');
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    process.exit(1);
  }
}

main();
