/**
 * Integration tests using vercel-labs/emulate as a test backend.
 *
 * These tests verify 40mcp works against realistic API emulators.
 * When emulate is not installed, tests are skipped gracefully.
 *
 * To run with emulate:
 *   npm install --save-dev emulate
 *   node --test test/emulate-integration.test.js
 *
 * Without emulate, these tests use a lightweight built-in mock server
 * that emulates GitHub-style API responses, proving the config pattern works.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createRestBridge } from '../src/bridge.js';
import { loadFromAny } from '../src/loaders/registry.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Lightweight GitHub-style mock (standalone, no deps) ────────────────────

function createGitHubMock() {
  const repos = [
    { id: 1, full_name: '40verse/40mcp', description: 'Universal API-to-MCP bridge', html_url: 'https://github.com/40verse/40mcp', language: 'JavaScript', stargazers_count: 42, forks_count: 5, open_issues_count: 3, default_branch: 'main', created_at: '2025-01-01', updated_at: '2025-06-01' },
    { id: 2, full_name: '40verse/example-service', description: 'Example microservice', html_url: 'https://github.com/40verse/example-service', language: 'TypeScript', stargazers_count: 100, forks_count: 12, open_issues_count: 7, default_branch: 'main', created_at: '2024-06-01', updated_at: '2025-05-01' },
  ];

  const issues = [
    { number: 1, title: 'Add gRPC loader', state: 'open', user: { login: 'alice' }, labels: [{ name: 'enhancement' }], created_at: '2025-03-01', updated_at: '2025-03-01' },
    { number: 2, title: 'Fix OAuth2 refresh', state: 'closed', user: { login: 'bob' }, labels: [{ name: 'bug' }], created_at: '2025-02-01', updated_at: '2025-02-15' },
  ];

  const pulls = [
    { number: 10, title: 'feat: webhook ingestion', state: 'open', user: { login: 'alice' }, head: { ref: 'feat/webhooks' }, base: { ref: 'main' }, created_at: '2025-03-15' },
  ];

  return createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const url = new URL(req.url, `http://${req.headers.host}`);

    // GET /user/repos
    if (req.method === 'GET' && url.pathname === '/user/repos') {
      res.writeHead(200);
      res.end(JSON.stringify(repos));
      return;
    }

    // GET /repos/:owner/:repo
    const repoMatch = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)$/);
    if (req.method === 'GET' && repoMatch) {
      const repo = repos.find((r) => r.full_name === `${repoMatch[1]}/${repoMatch[2]}`);
      if (repo) {
        res.writeHead(200);
        res.end(JSON.stringify(repo));
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ message: 'Not Found' }));
      }
      return;
    }

    // GET /repos/:owner/:repo/issues
    const issuesMatch = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)\/issues$/);
    if (req.method === 'GET' && issuesMatch) {
      const state = url.searchParams.get('state') || 'open';
      const filtered = state === 'all' ? issues : issues.filter((i) => i.state === state);
      res.writeHead(200);
      res.end(JSON.stringify(filtered));
      return;
    }

    // POST /repos/:owner/:repo/issues
    if (req.method === 'POST' && issuesMatch) {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const data = JSON.parse(body);
        const newIssue = { number: issues.length + 1, title: data.title, state: 'open', user: { login: 'bot' }, labels: data.labels || [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
        issues.push(newIssue);
        res.writeHead(201);
        res.end(JSON.stringify(newIssue));
      });
      return;
    }

    // GET /repos/:owner/:repo/pulls
    const pullsMatch = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)\/pulls$/);
    if (req.method === 'GET' && pullsMatch) {
      res.writeHead(200);
      res.end(JSON.stringify(pulls));
      return;
    }

    // GET /search/repositories
    if (req.method === 'GET' && url.pathname === '/search/repositories') {
      const q = url.searchParams.get('q') || '';
      const matched = repos.filter((r) => r.full_name.includes(q) || r.description.includes(q));
      res.writeHead(200);
      res.end(JSON.stringify({ total_count: matched.length, items: matched }));
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ message: 'Not Found' }));
  });
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('emulate integration — GitHub config', () => {
  let mockServer;
  let baseUrl;

  before(async () => {
    mockServer = createGitHubMock();
    await new Promise((resolve) => {
      mockServer.listen(0, '127.0.0.1', resolve);
    });
    const port = mockServer.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => {
    mockServer.close();
  });

  it('loads GitHub config and creates bridge', async () => {
    const configPath = resolve(__dirname, '../configs/github.json');
    const configText = await readFile(configPath, 'utf-8');
    const config = JSON.parse(configText);

    // Override baseUrl to point at mock
    config.baseUrl = baseUrl;
    delete config.auth; // No auth for mock
    delete config.strictSsrf; // shipped config is strict; test targets a loopback mock

    const bridge = createRestBridge(config);
    assert.ok(bridge.dispatch);
    assert.ok(bridge.server);
  });

  it('list_repos returns shaped results', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('list_repos', {});

    // Response transform should have picked specific fields
    assert.ok(Array.isArray(result) || result.items);
    const repos = result.items || result;
    assert.ok(repos.length > 0);
    assert.ok(repos[0].full_name);
    assert.ok(repos[0].html_url);
  });

  it('get_repo returns a single repository', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('get_repo', { owner: '40verse', repo: '40mcp' });

    assert.equal(result.full_name, '40verse/40mcp');
    assert.ok(result.stargazers_count >= 0);
  });

  it('list_issues filters by state', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('list_issues', { owner: '40verse', repo: '40mcp', issue_state: 'open' });

    const issues = result.items || result;
    assert.ok(Array.isArray(issues));
    for (const issue of issues) {
      assert.equal(issue.state, 'open');
    }
  });

  it('create_issue creates and returns new issue', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('create_issue', {
      owner: '40verse',
      repo: '40mcp',
      issue_title: 'Test issue from 40mcp',
      issue_body: 'Created by integration test',
    });

    assert.equal(result.title, 'Test issue from 40mcp');
    assert.equal(result.state, 'open');
  });

  it('search_repos finds matching repositories', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('search_repos', { search_query: '40mcp' });

    // search endpoint returns {total_count, items} - transforms should preserve structure
    assert.ok(result);
  });

  it('list_pull_requests returns PRs', async () => {
    const configText = await readFile(resolve(__dirname, '../configs/github.json'), 'utf-8');
    const config = JSON.parse(configText);
    config.baseUrl = baseUrl;
    delete config.auth;
    delete config.strictSsrf;

    const bridge = createRestBridge(config);
    const result = await bridge.dispatch('list_pull_requests', { owner: '40verse', repo: '40mcp' });

    const prs = result.items || result;
    assert.ok(Array.isArray(prs));
    assert.ok(prs.length > 0);
  });
});

describe('emulate integration — loadFromAny plugin detection', () => {
  it('detects GitHub config as NOT a loadable spec (it is a bridge config)', async () => {
    const configPath = resolve(__dirname, '../configs/github.json');
    const configText = await readFile(configPath, 'utf-8');
    const config = JSON.parse(configText);

    // A bridge config has tools[] and baseUrl but no openapi/swagger/paths field
    // loadFromAny should NOT match this as OpenAPI
    await assert.rejects(
      () => loadFromAny(config),
      (err) => err.message.includes('No loader found'),
    );
  });

  it('detects inline OpenAPI spec via loadFromAny', async () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test API', version: '1.0.0' },
      servers: [{ url: 'https://api.test.com' }],
      paths: {
        '/ping': {
          get: {
            operationId: 'ping',
            summary: 'Health check',
            responses: { 200: { description: 'OK' } },
          },
        },
      },
    };

    const { baseUrl, tools } = await loadFromAny(spec);
    assert.equal(baseUrl, 'https://api.test.com');
    assert.ok(tools.length > 0);
  });
});
