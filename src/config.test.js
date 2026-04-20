import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from './config.js';

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup helper
// ─────────────────────────────────────────────────────────────────────────────

const createdFiles = [];

function createTempFile(suffix, content) {
  const filePath = join(tmpdir(), `test-config-${Date.now()}-${Math.random().toString(36).slice(2)}${suffix}`);
  writeFileSync(filePath, content);
  chmodSync(filePath, 0o600);
  createdFiles.push(filePath);
  return filePath;
}

afterEach(() => {
  for (const filePath of createdFiles) {
    try {
      unlinkSync(filePath);
    } catch {}
  }
  createdFiles.length = 0;
});

// ─────────────────────────────────────────────────────────────────────────────
// loadConfig() tests
// ─────────────────────────────────────────────────────────────────────────────

describe('loadConfig', () => {
  it('loads and parses JSON file', async () => {
    const filePath = createTempFile('.json', JSON.stringify({ api: 'https://api.example.com', port: 3000 }));

    const config = await loadConfig(filePath);

    assert.deepEqual(config, { api: 'https://api.example.com', port: 3000 });
  });

  it('throws for unsupported .txt extension', async () => {
    const filePath = createTempFile('.txt', 'some config');

    await assert.rejects(
      async () => {
        await loadConfig(filePath);
      },
      (err) => {
        return err.message.includes('Unsupported config file type');
      }
    );
  });

  it('throws for unsupported .yaml extension', async () => {
    const filePath = createTempFile('.yaml', 'api: https://api.example.com');

    await assert.rejects(
      async () => {
        await loadConfig(filePath);
      },
      (err) => {
        return err.message.includes('Unsupported config file type');
      }
    );
  });

  it('throws for missing file', async () => {
    const filePath = join(tmpdir(), `nonexistent-${Math.random().toString(36).slice(2)}.json`);

    await assert.rejects(
      async () => {
        await loadConfig(filePath);
      },
      (err) => {
        return err.code === 'ENOENT';
      }
    );
  });

  it('throws for malformed JSON', async () => {
    const filePath = createTempFile('.json', '{ invalid json }');

    await assert.rejects(
      async () => {
        await loadConfig(filePath);
      },
      (err) => {
        return err instanceof SyntaxError;
      }
    );
  });

  describe('JS config imports', () => {
    let originalConfigDirs;

    beforeEach(() => {
      originalConfigDirs = process.env.FOURDMCP_CONFIG_DIRS;
      process.env.FOURDMCP_CONFIG_DIRS = tmpdir();
    });

    afterEach(() => {
      if (originalConfigDirs === undefined) {
        delete process.env.FOURDMCP_CONFIG_DIRS;
      } else {
        process.env.FOURDMCP_CONFIG_DIRS = originalConfigDirs;
      }
    });

    it('loads .js file via dynamic import', async () => {
      const jsContent = `export default { api: 'https://api.example.com', debug: true };`;
      const filePath = createTempFile('.js', jsContent);

      const config = await loadConfig(filePath);

      assert.deepEqual(config, { api: 'https://api.example.com', debug: true });
    });

    it('loads .mjs file via dynamic import', async () => {
      const mjsContent = `export default { format: 'mjs', enabled: true };`;
      const filePath = createTempFile('.mjs', mjsContent);

      const config = await loadConfig(filePath);

      assert.deepEqual(config, { format: 'mjs', enabled: true });
    });

    it('loads .cjs file via dynamic import', async () => {
      const cjsContent = `module.exports = { format: 'cjs', value: 42 };`;
      const filePath = createTempFile('.cjs', cjsContent);

      const config = await loadConfig(filePath);

      assert.deepEqual(config, { format: 'cjs', value: 42 });
    });

    it('returns module.default if available in JS import', async () => {
      const jsContent = `
        const config = { source: 'default' };
        export default config;
      `;
      const filePath = createTempFile('.js', jsContent);

      const config = await loadConfig(filePath);

      assert.deepEqual(config, { source: 'default' });
    });

    it('returns module itself if no default export', async () => {
      const jsContent = `
        export const config = { source: 'named' };
      `;
      const filePath = createTempFile('.js', jsContent);

      const result = await loadConfig(filePath);

      // Module namespace object — verify the named export is accessible
      assert.equal(result.config.source, 'named');
    });
  });

  it('REJECTS .js config outside the allowed directory list (CVE: supply-chain RCE)', async () => {
    const jsContent = `export default { rce: true };`;
    const filePath = createTempFile('.js', jsContent);
    // No temp-dir allowlist — /tmp is not in the default allowlist
    await assert.rejects(
      () => loadConfig(filePath),
      (err) => err.message.includes('outside the allowed directories'),
    );
  });

  it('REJECTS .js config when FOURDMCP_NO_JS_CONFIG=1', async () => {
    const jsContent = `export default { rce: true };`;
    const filePath = createTempFile('.js', jsContent);
    process.env.FOURDMCP_NO_JS_CONFIG = '1';
    try {
      await assert.rejects(
        () => loadConfig(filePath),
        (err) => err.message.includes('JS config loading is disabled'),
      );
    } finally {
      delete process.env.FOURDMCP_NO_JS_CONFIG;
    }
  });

  it('handles JSON with nested objects', async () => {
    const jsonContent = JSON.stringify({
      api: {
        baseUrl: 'https://api.example.com',
        timeout: 30000,
        headers: { 'User-Agent': 'test' },
      },
      auth: {
        type: 'bearer',
        envVar: 'AUTH_TOKEN',
      },
    });
    const filePath = createTempFile('.json', jsonContent);

    const config = await loadConfig(filePath);

    assert.deepEqual(config, {
      api: {
        baseUrl: 'https://api.example.com',
        timeout: 30000,
        headers: { 'User-Agent': 'test' },
      },
      auth: {
        type: 'bearer',
        envVar: 'AUTH_TOKEN',
      },
    });
  });

  it('handles JSON with arrays', async () => {
    const jsonContent = JSON.stringify({
      endpoints: ['https://api1.example.com', 'https://api2.example.com'],
      tags: ['prod', 'critical'],
    });
    const filePath = createTempFile('.json', jsonContent);

    const config = await loadConfig(filePath);

    assert.deepEqual(config, {
      endpoints: ['https://api1.example.com', 'https://api2.example.com'],
      tags: ['prod', 'critical'],
    });
  });

  it('throws for .yml extension (not in allowed list)', async () => {
    const filePath = createTempFile('.yml', 'api: example');

    await assert.rejects(
      async () => {
        await loadConfig(filePath);
      },
      (err) => {
        return err.message.includes('Unsupported config file type');
      }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// World-readable mode warning — fires only when the targeted heuristic
// finds a likely literal credential in the fields 40mcp's own bridge reads
// credentials from. This is a warning-reduction heuristic, not a general
// secret scanner — see `configHasLikelyLiteralSecret` in src/config.js.
// ─────────────────────────────────────────────────────────────────────────────

describe('loadConfig — world-readable mode warning', {
  skip: process.platform === 'win32'
    ? 'POSIX mode bits are not represented on NTFS'
    : false,
}, () => {
  // Capture stderr to assert on the warning string.
  let captured = '';
  const origWrite = process.stderr.write.bind(process.stderr);
  const start = () => {
    captured = '';
    process.stderr.write = (chunk) => {
      captured += typeof chunk === 'string' ? chunk : chunk.toString();
      return true;
    };
  };
  const stop = () => {
    process.stderr.write = origWrite;
  };

  it('does not warn on 0644 config that only uses env-var references', async () => {
    const jsonContent = JSON.stringify({
      name: 'github',
      baseUrl: 'https://api.github.com',
      auth: { type: 'bearer', envVar: 'GITHUB_TOKEN' },
      tools: [{
        name: 'get_repo',
        method: 'GET',
        path: '/repos/:owner/:repo',
        headers: { 'Authorization': 'Bearer ${GITHUB_TOKEN}' },
      }],
    });
    const filePath = createTempFile('.json', jsonContent);
    chmodSync(filePath, 0o644);

    start();
    try {
      await loadConfig(filePath);
    } finally {
      stop();
    }

    assert.equal(
      captured.includes('group- or world-readable'),
      false,
      'should not warn on env-ref-only config',
    );
  });

  it('warns on 0644 config that embeds a literal auth.value', async () => {
    const jsonContent = JSON.stringify({
      name: 'leaky',
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer', value: 'sk_live_abc123deadbeef' },
    });
    const filePath = createTempFile('.json', jsonContent);
    chmodSync(filePath, 0o644);

    start();
    try {
      await loadConfig(filePath);
    } finally {
      stop();
    }

    assert.ok(
      captured.includes('group- or world-readable'),
      'should warn when a literal credential is embedded',
    );
    assert.ok(
      captured.includes('literal credential'),
      'warning should name the literal-credential reason so the operator knows what to redact',
    );
  });

  it('warns on 0644 config with a literal Authorization header on a tool', async () => {
    const jsonContent = JSON.stringify({
      name: 'leaky',
      baseUrl: 'https://api.example.com',
      tools: [{
        name: 'foo',
        method: 'GET',
        path: '/foo',
        headers: { 'Authorization': 'Bearer sk_live_deadbeef' },
      }],
    });
    const filePath = createTempFile('.json', jsonContent);
    chmodSync(filePath, 0o644);

    start();
    try {
      await loadConfig(filePath);
    } finally {
      stop();
    }

    assert.ok(
      captured.includes('group- or world-readable'),
      'should warn on literal header credential',
    );
  });

  it('does not warn on 0600 config regardless of content', async () => {
    const jsonContent = JSON.stringify({
      name: 'locked-down',
      auth: { type: 'bearer', value: 'sk_live_still_secret' },
    });
    const filePath = createTempFile('.json', jsonContent);
    chmodSync(filePath, 0o600);

    start();
    try {
      await loadConfig(filePath);
    } finally {
      stop();
    }

    assert.equal(
      captured.includes('group- or world-readable'),
      false,
      '0600 should never warn',
    );
  });
});
