/**
 * Example: Webhook listener for GitHub events
 *
 * Creates a bridge that exposes MCP tools, then a webhook listener
 * that accepts GitHub webhooks and dispatches them to tools.
 *
 * Demonstrates:
 * 1. Setting up a REST bridge with tools
 * 2. Creating a webhook listener with multiple routes
 * 3. HMAC-SHA256 signature validation (GitHub style)
 * 4. Event filtering (only process specific actions)
 * 5. Async (fire-and-forget) response mode
 * 6. Argument extraction from webhook payload
 * 7. Both sync and async response patterns
 *
 * Setup:
 *   1. Export a webhook secret and GitHub token:
 *      export GITHUB_WEBHOOK_SECRET="your-webhook-secret"
 *      export GITHUB_TOKEN="<your-github-token>"
 *
 *   2. Start this server:
 *      node examples/webhook.js
 *
 *   3. Configure GitHub webhook:
 *      - Repo Settings → Webhooks → Add webhook
 *      - Payload URL: http://your-server:9090/hooks/github
 *      - Content type: application/json
 *      - Secret: your-webhook-secret
 *      - Events: Pull requests, Issues, Discussions, etc.
 *
 *   4. When you open/close a PR or issue, the webhook will trigger
 *      and call the corresponding MCP tools.
 *
 * Run:
 *   GITHUB_TOKEN="<your-github-token>" GITHUB_WEBHOOK_SECRET="..." node examples/webhook.js
 */

import { createRestBridge, createWebhookListener } from '../src/index.js';
import process from 'node:process';

// ─── Step 1: Create a bridge with event handling tools ─────────────────────

async function createToolBridge() {
  console.log('Creating bridge with GitHub event tools...\n');

  const bridge = await createRestBridge({
    name: 'github-webhook-bridge',
    version: '1.0.0',
    baseUrl: 'https://api.github.com',
    auth: {
      type: 'bearer',
      envVar: 'GITHUB_TOKEN',
    },
    tools: [
      {
        name: 'create_issue_comment',
        description: 'Add a comment to an issue or PR',
        method: 'POST',
        path: '/repos/{owner}/{repo}/issues/{issue_number}/comments',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string', description: 'Repository owner' },
            repo: { type: 'string', description: 'Repository name' },
            issue_number: { type: 'integer', description: 'Issue/PR number' },
            body: { type: 'string', description: 'Comment text' },
          },
          required: ['owner', 'repo', 'issue_number', 'body'],
        },
      },
      {
        name: 'add_issue_label',
        description: 'Add labels to an issue',
        method: 'POST',
        path: '/repos/{owner}/{repo}/issues/{issue_number}/labels',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
            issue_number: { type: 'integer' },
            labels: { type: 'array', items: { type: 'string' } },
          },
          required: ['owner', 'repo', 'issue_number', 'labels'],
        },
      },
      {
        name: 'update_pr_status',
        description: 'Update PR status (approve, request_changes, comment)',
        method: 'POST',
        path: '/repos/{owner}/{repo}/pulls/{pull_number}/reviews',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
            pull_number: { type: 'integer' },
            event: { type: 'string', enum: ['APPROVE', 'REQUEST_CHANGES', 'COMMENT'] },
            body: { type: 'string', description: 'Review comment (optional)' },
          },
          required: ['owner', 'repo', 'pull_number', 'event'],
        },
      },
      {
        name: 'log_webhook_event',
        description: 'Log webhook event (internal tool)',
        method: 'POST',
        path: '/internal/log',
        inputSchema: {
          type: 'object',
          properties: {
            event_type: { type: 'string' },
            action: { type: 'string' },
            payload: { type: 'object' },
          },
          required: ['event_type', 'action'],
        },
      },
    ],
  });

  console.log('✓ Bridge created with', bridge.tools.length, 'tools');
  return bridge;
}

// ─── Step 2: Create webhook listener with routes ────────────────────────────

async function createWebhookServer(bridge) {
  console.log('\n=== Setting up Webhook Listener ===\n');

  // Define routes that map webhooks to tools
  const routes = [
    // GitHub pull request webhook
    {
      path: '/hooks/github/pull-request',
      method: 'POST',
      tool: 'create_issue_comment', // Tool to dispatch
      filter: {
        action: ['opened', 'synchronize'], // Only specific actions
      },
      secret: {
        type: 'hmac',
        envVar: 'GITHUB_WEBHOOK_SECRET',
        header: 'X-Hub-Signature-256', // GitHub's standard header
      },
      // Sync mode: wait for tool result before responding (good for quick ops)
      async: false,
      // Map webhook payload fields to tool arguments
      argMap: {
        owner: '$body.repository.owner.login',
        repo: '$body.repository.name',
        issue_number: '$body.pull_request.number',
        body: 'Webhook from GitHub',
      },
    },

    // GitHub issues webhook
    {
      path: '/hooks/github/issues',
      method: 'POST',
      tool: 'add_issue_label',
      filter: {
        action: ['opened'], // Only when issue is opened
      },
      secret: {
        type: 'hmac',
        envVar: 'GITHUB_WEBHOOK_SECRET',
        header: 'X-Hub-Signature-256',
      },
      // Async mode: respond immediately, execute in background (good for slow ops)
      async: true,
      argMap: {
        owner: '$body.repository.owner.login',
        repo: '$body.repository.name',
        issue_number: '$body.issue.number',
        labels: ['from-webhook'], // Static label
      },
    },

    // Generic GitHub webhook with full payload
    {
      path: '/hooks/github/all',
      method: 'POST',
      tool: 'log_webhook_event',
      secret: {
        type: 'hmac',
        envVar: 'GITHUB_WEBHOOK_SECRET',
        header: 'X-Hub-Signature-256',
      },
      async: true, // Fire and forget
      argMap: {
        event_type: '$header.X-GitHub-Event',
        action: '$body.action',
        payload: '$body', // Pass entire payload
      },
    },

    // Example webhook with different secret type (header-based)
    {
      path: '/hooks/stripe',
      method: 'POST',
      tool: 'log_webhook_event',
      filter: {
        type: ['charge.succeeded', 'charge.failed'],
      },
      secret: {
        type: 'header',
        envVar: 'STRIPE_WEBHOOK_SECRET',
        header: 'Stripe-Signature',
      },
      async: true,
      argMap: {
        event_type: '$body.type',
        action: '$body.data.object.status',
        payload: '$body',
      },
    },
  ];

  // Create the webhook listener
  const listener = await createWebhookListener({
    port: 9090,
    routes,
    dispatch: bridge.dispatch, // Dispatch function from bridge
    logger: (level, message, context) => {
      const emoji = {
        info: 'ℹ️',
        warn: '⚠️',
        error: '❌',
      }[level] || '📝';
      console.log(`[${level.toUpperCase()}] ${emoji} ${message}`);
      if (context && Object.keys(context).length > 0) {
        console.log('  Context:', JSON.stringify(context, null, 2).split('\n').join('\n  '));
      }
    },
  });

  console.log('✓ Webhook listener created on http://localhost:9090');
  console.log(`✓ Routes configured: ${routes.length}`);
  console.log('');
  console.log('Available endpoints:');
  routes.forEach((route) => {
    const asyncMode = route.async ? '(async)' : '(sync)';
    console.log(`  POST ${route.path} ${asyncMode} → ${route.tool}`);
  });

  return listener;
}

// ─── Step 3: Test webhook with simulated GitHub event ──────────────────────

async function testWebhook() {
  console.log('\n=== Testing Webhook Locally ===\n');

  // Note: In production, this would come from GitHub
  const mockGitHubWebhook = {
    action: 'opened',
    pull_request: {
      number: 42,
      title: 'Add webhook example',
    },
    repository: {
      name: '40mcp',
      owner: {
        login: '40verse',
      },
    },
  };

  console.log('Mock GitHub webhook payload:');
  console.log(JSON.stringify(mockGitHubWebhook, null, 2));

  console.log('\nIn a real scenario:');
  console.log('1. GitHub sends POST to http://your-server:9090/hooks/github/pull-request');
  console.log('2. Signature validated with HMAC-SHA256');
  console.log('3. Arguments extracted from payload via argMap');
  console.log('4. Tool called with extracted arguments');
  console.log('5. Response sent back to GitHub (200 OK or async pending)');
}

// ─── Step 4: Show secret validation details ────────────────────────────────

function showSecretValidation() {
  console.log('\n=== Secret Validation Details ===\n');

  console.log('GitHub HMAC validation:');
  console.log('1. GitHub sends: X-Hub-Signature-256: sha256=SIGNATURE');
  console.log('2. Server receives webhook body (raw bytes)');
  console.log('3. Server computes: sha256=HMAC(secret, body)');
  console.log('4. Compare using constant-time comparison');
  console.log('');

  console.log('Signature format:');
  console.log('  sha256=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
  console.log('');

  console.log('Common gotchas:');
  console.log('- Secret must match exactly (case-sensitive)');
  console.log('- Body must be raw bytes, not parsed JSON');
  console.log('- Always use constant-time comparison (prevents timing attacks)');
}

// ─── Step 5: Show argument extraction patterns ────────────────────────────

function showArgMapPatterns() {
  console.log('\n=== Argument Extraction Patterns ===\n');

  console.log('Syntax: argMap maps tool args to webhook sources');
  console.log('');

  console.log('From JSON body (dot notation):');
  console.log('  "$body.pull_request.number"        → get pull_request.number');
  console.log('  "$body.repository.owner.login"     → get repository.owner.login');
  console.log('');

  console.log('From headers:');
  console.log('  "$header.X-GitHub-Event"           → get X-GitHub-Event header');
  console.log('  "$header.X-Hub-Signature-256"      → get X-Hub-Signature-256 header');
  console.log('');

  console.log('From query string:');
  console.log('  "$query.token"                     → get ?token=...');
  console.log('  "$query.repo"                      → get ?repo=...');
  console.log('');

  console.log('Static values:');
  console.log('  "static-label"                     → literal string');
  console.log('  ["tag1", "tag2"]                   → literal array');
  console.log('  { "nested": "object" }             → literal object');
  console.log('');
}

// ─── Step 6: Show filtering patterns ────────────────────────────────────────

function showFilteringPatterns() {
  console.log('\n=== Event Filtering Patterns ===\n');

  console.log('Filters prevent processing unwanted events:');
  console.log('');

  console.log('Filter by action:');
  console.log('  filter: { action: ["opened"] }');
  console.log('  Only processes events where action === "opened"');
  console.log('');

  console.log('Filter by type:');
  console.log('  filter: { type: ["charge.succeeded"] }');
  console.log('  Only processes webhook types matching the list');
  console.log('');

  console.log('Multiple filters (AND):');
  console.log('  filter: { action: ["opened"], state: ["open"] }');
  console.log('  All conditions must match');
  console.log('');

  console.log('Unfiltered (all events):');
  console.log('  filter: undefined or {}');
  console.log('  Processes every webhook received');
}

// ─── Step 7: Best practices ────────────────────────────────────────────────

function showBestPractices() {
  console.log('\n=== Best Practices for Webhooks ===\n');

  console.log('1. Always validate HMAC signature:');
  console.log('   - Prevents processing spoofed webhooks');
  console.log('   - Use constant-time comparison');
  console.log('');

  console.log('2. Use filters to ignore unwanted events:');
  console.log('   - Reduces unnecessary tool calls');
  console.log('   - Saves bandwidth and computation');
  console.log('');

  console.log('3. Use async: true for slow operations:');
  console.log('   - Return 202 Accepted immediately');
  console.log('   - Process webhook in background');
  console.log('   - Prevents provider timeouts');
  console.log('');

  console.log('4. Use async: false for fast operations:');
  console.log('   - Wait for tool result');
  console.log('   - Return 200 OK when done');
  console.log('   - Good for simple queries or status checks');
  console.log('');

  console.log('5. Extract only needed fields with argMap:');
  console.log('   - Avoid passing entire payload');
  console.log('   - Reduces argument size');
  console.log('   - Makes tool calls more predictable');
  console.log('');

  console.log('6. Log all webhook events for debugging:');
  console.log('   - Helps diagnose delivery issues');
  console.log('   - Audit trail for security');
  console.log('');

  console.log('7. Idempotent tool operations:');
  console.log('   - Webhooks may be retried');
  console.log('   - Same tool call should be safe to repeat');
  console.log('');

  console.log('8. Set reasonable port numbers:');
  console.log('   - Use 8080, 3000, 9090, etc. (>1024)');
  console.log('   - Never use root/privileged ports');
  console.log('');
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log('40mcp Webhook Listener Example\n');
  console.log('Demonstrates receiving webhooks and dispatching to MCP tools.\n');

  try {
    // Create the tool bridge
    const bridge = await createToolBridge();

    // Create webhook listener with routes
    const _listener = await createWebhookServer(bridge);

    // Show how it works
    await testWebhook();
    showSecretValidation();
    showArgMapPatterns();
    showFilteringPatterns();
    showBestPractices();

    console.log('\n✓ Webhook listener example initialized!\n');
    console.log('Configuration:');
    console.log('  - Bridge: GitHub API');
    console.log('  - Webhook port: 9090');
    console.log('  - Routes: GitHub PRs, Issues, Generic events, Stripe');
    console.log('  - Secret validation: HMAC-SHA256\n');

    console.log('To test with real GitHub webhooks:');
    console.log('1. Set GITHUB_WEBHOOK_SECRET in your repository');
    console.log('2. Configure webhook in GitHub → Repo Settings → Webhooks');
    console.log('3. Point to: http://your-server:9090/hooks/github/pull-request');
    console.log('4. Open a pull request in the repository');
    console.log('5. Check logs for webhook delivery\n');
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    process.exit(1);
  }
}

main();
