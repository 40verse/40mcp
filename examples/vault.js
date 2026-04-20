/**
 * Example: Sealed Vault Feature
 *
 * Demonstrates how to use 40mcp's sealed vault to securely manage API keys
 * without exposing secrets to process.env or logs.
 *
 * Key concepts:
 * - createVault() initializes a vault with envelope encryption
 * - vault.set() seals a secret and returns a seal:// ID
 * - vault.issueToken() creates short-lived JWTs for credential access
 * - vault.createAuthHook() provides JIT unseal for beforeRequest hooks
 * - vault.unsealConfig() resolves seal:// references in configs
 *
 * Run:
 *   export VAULT_PASSPHRASE="<set-VAULT_PASSPHRASE-in-your-env>"
 *   node examples/vault.js
 */

import { createVault, createRestBridge } from '../src/index.js';
import process from 'node:process';

// ─── Step 1: Initialize the vault ──────────────────────────────────────────

async function initializeVault() {
  // Vault passphrase must come from secure storage, not git.
  // In production, load from AWS Secrets Manager, HashiCorp Vault, etc.
  const passphrase = process.env.VAULT_PASSPHRASE;
  if (!passphrase) {
    console.error('VAULT_PASSPHRASE env var is required. Set a strong passphrase before running this example.');
    process.exit(1);
  }

  // Create or load vault. File path is encrypted at rest.
  const vault = createVault({
    path: '.vault.json',
    passphrase,
    tokenTTL: 300, // 5-minute token lifetime
  });

  return vault;
}

// ─── Step 2: Seal API secrets ──────────────────────────────────────────────

async function sealSecrets(vault) {
  console.log('\n=== Sealing API Secrets ===\n');

  // Seal GitHub API key. vault.set() returns a seal ID (never the plaintext).
  // The seal ID is safe to log, commit to git, or share.
  const gitHubSealId = await vault.set('GITHUB_TOKEN', 'EXAMPLE_GITHUB_TOKEN_VALUE_PLACEHOLDER', {
    service: 'github',
    scopes: 'repo,user',
  });
  console.log('✓ GitHub token sealed:', gitHubSealId);

  // Seal another secret for a different API
  const stripeSealId = await vault.set('STRIPE_API_KEY', 'EXAMPLE_STRIPE_KEY_VALUE_PLACEHOLDER', {
    service: 'stripe',
    livemode: true,
  });
  console.log('✓ Stripe API key sealed:', stripeSealId);

  // You can also list all sealed secrets without revealing values
  const allSecrets = await vault.list();
  console.log('\nSealed secrets in vault:');
  allSecrets.forEach((secret) => {
    console.log(`  - ${secret.name}: ${secret.sealId} (${secret.metadata.service})`);
  });

  return { gitHubSealId, stripeSealId };
}

// ─── Step 3: Issue time-limited credentials ────────────────────────────────

async function issueCredentials(vault) {
  console.log('\n=== Issuing Short-Lived JWT Tokens ===\n');

  // Issue a 5-minute token for GitHub. The token proves authorization but
  // never contains the plaintext secret.
  const { token: gitHubToken, expiresAt: gitHubExpires } = await vault.issueToken('GITHUB_TOKEN', {
    scope: 'repo',
    bot_id: 'my-ci-bot',
  });
  console.log('✓ GitHub token issued');
  console.log('  Expires:', new Date(gitHubExpires).toISOString());

  // Issue a token for Stripe with different claims
  const { token: stripeToken, expiresAt: stripeExpires } = await vault.issueToken('STRIPE_API_KEY', {
    scope: 'charges:read',
    merchant_id: 'acct_123456',
  });
  console.log('✓ Stripe token issued');
  console.log('  Expires:', new Date(stripeExpires).toISOString());

  return { gitHubToken, stripeToken };
}

// ─── Step 4: Verify tokens (JIT unseal) ───────────────────────────────────

async function verifyToken(vault, token, _secretName) {
  // verifyToken() unseals the secret in-memory, then discards it.
  // Never stored in process.env or persisted.
  const { name, value, sealId, claims } = await vault.verifyToken(token);

  console.log(`\nToken verified for: ${name}`);
  console.log(`  Seal ID: ${sealId}`);
  console.log(`  Claims:`, claims);
  console.log(`  Secret (first 20 chars): ${value.substring(0, 20)}...`);

  return { name, value };
}

// ─── Step 5: Create auth hook for bridge ───────────────────────────────────

async function createAuthHookExample(vault) {
  console.log('\n=== Creating Auth Hook for 40mcp Bridge ===\n');

  // createAuthHook() returns a beforeRequest function that unseals secrets JIT.
  // Secrets only exist in-memory during the request, then are discarded.
  const authHook = vault.createAuthHook({
    GITHUB_TOKEN: 'Authorization',    // Secret name → Header name
    STRIPE_API_KEY: 'X-Stripe-Key',
  });

  // Simulate a request (normally handled by bridge internally)
  const mockRequest = {
    method: 'GET',
    url: 'https://api.github.com/user',
    headers: {},
  };

  const result = await authHook(mockRequest);
  console.log('✓ Auth hook executed for request:', mockRequest.url);
  if (result && result.headers) {
    console.log('  Headers will include:');
    Object.keys(result.headers).forEach((key) => {
      console.log(`    - ${key}: ***REDACTED***`);
    });
  }

  return authHook;
}

// ─── Step 6: Use vault with 40mcp bridge ──────────────────────────────────

async function createBridgeWithVault(vault, authHook) {
  console.log('\n=== Creating 40mcp Bridge with Vault ===\n');

  // Config can reference seal:// IDs or use the auth hook
  const config = {
    baseUrl: 'https://api.github.com',
    tools: [
      {
        name: 'get_user',
        description: 'Get current authenticated user',
        method: 'GET',
        path: '/user',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
      {
        name: 'list_repos',
        description: 'List user repositories',
        method: 'GET',
        path: '/user/repos',
        inputSchema: {
          type: 'object',
          properties: {
            per_page: { type: 'integer', description: 'Results per page' },
            sort: { type: 'string', enum: ['created', 'updated', 'pushed', 'full_name'] },
          },
          required: [],
        },
      },
    ],
  };

  // Create bridge with the auth hook (secrets never in process.env)
  const bridge = await createRestBridge({
    ...config,
    hooks: {
      beforeRequest: authHook, // JIT secret unseal
    },
  });

  console.log('✓ Bridge created with vault auth hook');
  console.log('  Tools available:', config.tools.map((t) => t.name).join(', '));

  return bridge;
}

// ─── Step 7: Unseal config (resolve seal:// references) ────────────────────

async function unsealConfigExample(_vault) {
  console.log('\n=== Unsealing Config with seal:// References ===\n');

  // A config might reference secrets by seal:// ID instead of plaintext
  const configWithSeals = {
    baseUrl: 'https://api.stripe.com',
    auth: {
      type: 'bearer',
      // Instead of: value: '<your-stripe-secret-key>' (plaintext, bad!)
      // Use: value: 'seal://stripe-api-key-a1b2c3d4' (safe to commit)
      value: 'seal://stripe-api-key-...',
    },
    tools: [],
  };

  console.log('Config with seal:// references:');
  console.log(JSON.stringify(configWithSeals, null, 2));
  console.log('\nAt runtime, vault.unsealConfig() would decrypt seal:// IDs.');
  console.log('The plaintext secret exists only in-memory, never persisted.');
}

// ─── Step 8: Vault management (list, delete) ───────────────────────────────

async function manageVault(vault) {
  console.log('\n=== Vault Management ===\n');

  // Check if a secret exists
  const hasGithub = await vault.has('GITHUB_TOKEN');
  console.log('✓ GITHUB_TOKEN exists:', hasGithub);

  // Get seal ID (safe to log)
  const sealId = await vault.getSealId('GITHUB_TOKEN');
  console.log('✓ Seal ID:', sealId);

  // Get fingerprint (proof of secret without unsealing)
  const fingerprint = await vault.getFingerprint('GITHUB_TOKEN');
  console.log('✓ Fingerprint:', fingerprint);

  // List all secrets with metadata
  const secrets = await vault.list();
  console.log('✓ All sealed secrets:');
  secrets.forEach((s) => {
    console.log(`  - ${s.name} (created: ${s.created}, sealId: ${s.sealId})`);
  });

  // Delete a secret (if needed)
  // await vault.delete('OLD_TOKEN');
  // console.log('✓ OLD_TOKEN deleted');
}

// ─── Step 9: Best practices pattern ────────────────────────────────────────

function showBestPractices() {
  console.log('\n=== Best Practices for Vault ===\n');

  console.log('1. Load passphrase from secure storage:');
  console.log('   - AWS Secrets Manager');
  console.log('   - HashiCorp Vault');
  console.log('   - Azure Key Vault');
  console.log('   - GCP Secret Manager');
  console.log('');

  console.log('2. Commit .vault.json but NEVER plaintext secrets:');
  console.log('   - .vault.json is encrypted (safe to commit)');
  console.log('   - .env is in .gitignore (never commit secrets)');
  console.log('');

  console.log('3. Use short TTLs for tokens:');
  console.log('   - Default: 5 minutes');
  console.log('   - Reduces impact of token leakage');
  console.log('   - Client re-issues token when expired');
  console.log('');

  console.log('4. Use auth hooks instead of beforeRequest:');
  console.log('   - Auth hook unseals JIT');
  console.log('   - Secret never persisted');
  console.log('   - Works with all auth types (bearer, basic, header)');
  console.log('');

  console.log('5. Separate vaults for environments:');
  console.log('   - .vault-prod.json (production secrets)');
  console.log('   - .vault-staging.json (staging secrets)');
  console.log('   - Different passphrases per environment');
  console.log('');
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log('40mcp Sealed Vault Example\n');
  console.log('This example demonstrates secure credential management.');
  console.log('Secrets are encrypted at rest and unsealed just-in-time (JIT).\n');

  try {
    // Initialize vault
    const vault = await initializeVault();
    console.log('✓ Vault initialized at .vault.json');

    // Seal secrets
    const { gitHubSealId: _gitHubSealId, stripeSealId: _stripeSealId } = await sealSecrets(vault);

    // Issue tokens
    const { gitHubToken, stripeToken: _stripeToken } = await issueCredentials(vault);

    // Verify tokens (unsealing them)
    await verifyToken(vault, gitHubToken, 'GITHUB_TOKEN');

    // Create and use auth hook
    const authHook = await createAuthHookExample(vault);

    // Create bridge with vault
    await createBridgeWithVault(vault, authHook);

    // Unseal config example
    await unsealConfigExample(vault);

    // Manage vault
    await manageVault(vault);

    // Show best practices
    showBestPractices();

    console.log('\n✓ Vault example completed successfully!\n');
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    process.exit(1);
  }
}

main();
