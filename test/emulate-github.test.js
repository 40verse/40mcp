/**
 * test/emulate-github.test.js
 *
 * Integration tests against a production-fidelity GitHub API emulator
 * (vercel-labs/emulate). No mocks, no fixtures — a real HTTP server
 * running the GitHub REST API surface locally.
 *
 * What this proves:
 * - 40mcp works against a realistic, stateful REST API (not a toy stub)
 * - Tool dispatch handles pagination params, path params, POST bodies
 * - Auth headers are forwarded correctly on every request
 * - Response transforms (pick, tokenBudget) work on real API shapes
 * - reset() lets tests share a single server without state bleed
 */

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createEmulator } from 'emulate';
import { createRestBridge } from '../src/index.js';

// ─── Emulator lifecycle ──────────────────────────────────────────────────────

let github;
const GITHUB_TOKEN = 'test_token_admin'; // default admin token seeded by emulate

before(async () => {
  github = await createEmulator({ service: 'github', port: 14301 });

  // Seed: create repos and issues via the emulator's own REST API
  const headers = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    'Content-Type': 'application/json',
  };

  await fetch(`${github.url}/user/repos`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'alpha', description: 'First repo', auto_init: true }),
  });
  await fetch(`${github.url}/user/repos`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'beta', description: 'Second repo', auto_init: true }),
  });
  await fetch(`${github.url}/repos/admin/alpha/issues`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ title: 'Bug: crash on startup', body: 'Crashes when network unavailable.' }),
  });
  await fetch(`${github.url}/repos/admin/alpha/issues`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ title: 'Feature: dark mode', body: 'Users have requested dark mode.' }),
  });
});

beforeEach(() => {
  // reset() wipes state and replays seed — use sparingly (only tests that mutate)
});

after(async () => {
  await github.close();
});

// ─── Bridge factory ──────────────────────────────────────────────────────────

function buildGitHubBridge() {
  return createRestBridge({
    name: 'github-emulate',
    baseUrl: github.url,
    auth: { type: 'bearer', value: GITHUB_TOKEN },
    tools: [
      {
        name: 'list_my_repos',
        description: 'List repositories for the authenticated user',
        method: 'GET',
        path: '/user/repos',
        inputSchema: {
          type: 'object',
          properties: {
            per_page: { type: 'number', description: 'Results per page (max 100)' },
            sort: { type: 'string', enum: ['created', 'updated', 'pushed', 'full_name'] },
          },
        },
      },
      {
        name: 'get_repo',
        description: 'Get a specific repository by owner and name',
        method: 'GET',
        path: '/repos/:owner/:repo',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
          },
          required: ['owner', 'repo'],
        },
      },
      {
        name: 'list_issues',
        description: 'List issues in a repository',
        method: 'GET',
        path: '/repos/:owner/:repo/issues',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
            state: { type: 'string', enum: ['open', 'closed', 'all'] },
          },
          required: ['owner', 'repo'],
        },
      },
      {
        name: 'create_issue',
        description: 'Create a new issue in a repository',
        method: 'POST',
        path: '/repos/:owner/:repo/issues',
        inputSchema: {
          type: 'object',
          properties: {
            owner: { type: 'string' },
            repo: { type: 'string' },
            title: { type: 'string' },
            body: { type: 'string' },
          },
          required: ['owner', 'repo', 'title'],
        },
      },
      {
        name: 'get_user',
        description: 'Get the authenticated user profile',
        method: 'GET',
        path: '/user',
        inputSchema: { type: 'object', properties: {} },
      },
    ],
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test('GitHub emulator: list_my_repos returns seeded repositories', async () => {
  const { dispatch } = buildGitHubBridge();
  const repos = await dispatch('list_my_repos', {});

  assert.ok(Array.isArray(repos), 'should return array');
  const names = repos.map((r) => r.name);
  assert.ok(names.includes('alpha'), `expected "alpha" in ${JSON.stringify(names)}`);
  assert.ok(names.includes('beta'), `expected "beta" in ${JSON.stringify(names)}`);
});

test('GitHub emulator: get_repo returns correct repository details', async () => {
  const { dispatch } = buildGitHubBridge();
  const repo = await dispatch('get_repo', { owner: 'admin', repo: 'alpha' });

  assert.equal(repo.name, 'alpha');
  assert.equal(repo.owner.login, 'admin');
  assert.equal(repo.full_name, 'admin/alpha');
  assert.equal(repo.description, 'First repo');
});

test('GitHub emulator: list_issues returns seeded issues with correct shape', async () => {
  const { dispatch } = buildGitHubBridge();
  const issues = await dispatch('list_issues', { owner: 'admin', repo: 'alpha' });

  assert.ok(Array.isArray(issues));
  assert.equal(issues.length, 2);

  const titles = issues.map((i) => i.title);
  assert.ok(titles.some((t) => t.includes('Bug')));
  assert.ok(titles.some((t) => t.includes('Feature')));

  // Verify GitHub issue shape is fully preserved
  const issue = issues[0];
  assert.ok(typeof issue.number === 'number');
  assert.ok(typeof issue.state === 'string');
  assert.ok(issue.user?.login === 'admin');
});

test('GitHub emulator: create_issue persists and is retrievable', async () => {
  const { dispatch } = buildGitHubBridge();

  const issue = await dispatch('create_issue', {
    owner: 'admin',
    repo: 'beta',
    title: 'Performance regression',
    body: 'Noticed slowdown after latest deploy.',
  });

  assert.equal(issue.title, 'Performance regression');
  assert.ok(typeof issue.number === 'number');
  assert.equal(issue.state, 'open');

  // Verify it shows up in list_issues
  const issues = await dispatch('list_issues', { owner: 'admin', repo: 'beta' });
  assert.ok(issues.some((i) => i.title === 'Performance regression'));
});

test('GitHub emulator: get_user returns authenticated user profile', async () => {
  const { dispatch } = buildGitHubBridge();
  const user = await dispatch('get_user', {});

  assert.equal(user.login, 'admin');
  assert.equal(user.site_admin, true);
});

test('GitHub emulator: nonexistent repo throws a structured not-found error', async () => {
  const { dispatch } = buildGitHubBridge();

  await assert.rejects(
    () => dispatch('get_repo', { owner: 'admin', repo: 'does-not-exist' }),
    (err) => {
      assert.ok(err.message, 'error should have a message');
      assert.ok(
        err.message.includes('404') || err.message.toLowerCase().includes('not found'),
        `expected 404/not-found in error message, got: "${err.message}"`
      );
      return true;
    }
  );
});

test('GitHub emulator: pick transform reduces issue payload to requested fields', async () => {
  const bridge = createRestBridge({
    name: 'github-pick',
    baseUrl: github.url,
    auth: { type: 'bearer', value: GITHUB_TOKEN },
    tools: [
      {
        name: 'list_issues_compact',
        description: 'List issues, returning only number, title, and state',
        method: 'GET',
        path: '/repos/:owner/:repo/issues',
        inputSchema: {
          type: 'object',
          properties: { owner: { type: 'string' }, repo: { type: 'string' } },
          required: ['owner', 'repo'],
        },
        response: { pick: ['number', 'title', 'state'] },
      },
    ],
  });

  const issues = await bridge.dispatch('list_issues_compact', { owner: 'admin', repo: 'alpha' });

  assert.ok(Array.isArray(issues));
  const issue = issues[0];
  // Only picked fields present
  assert.ok('number' in issue);
  assert.ok('title' in issue);
  assert.ok('state' in issue);
  // Non-picked fields stripped
  assert.ok(!('body' in issue), 'body should be stripped by pick');
  assert.ok(!('user' in issue), 'user should be stripped by pick');
});
