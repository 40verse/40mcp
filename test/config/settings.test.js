import { describe, it, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadSettings,
  validateSettings,
  parseByteSize,
  pick,
  DEFAULT_SETTINGS,
} from '../../src/config/settings.js';

let workDir;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'settings-test-'));
});

afterEach(() => {
  try { rmSync(workDir, { recursive: true, force: true }); } catch {}
});

function write(file, content) {
  const full = join(workDir, file);
  writeFileSync(full, typeof content === 'string' ? content : JSON.stringify(content));
  return full;
}

describe('parseByteSize', () => {
  it('parses numeric strings as bytes', () => {
    assert.equal(parseByteSize('1024'), 1024);
    assert.equal(parseByteSize('0'), 0);
  });

  it('parses KB / MB / GB / TB suffixes', () => {
    assert.equal(parseByteSize('1KB'), 1024);
    assert.equal(parseByteSize('512KB'), 512 * 1024);
    assert.equal(parseByteSize('1MB'), 1024 * 1024);
    assert.equal(parseByteSize('2GB'), 2 * 1024 * 1024 * 1024);
    assert.equal(parseByteSize('1TB'), 1024 ** 4);
  });

  it('accepts number input', () => {
    assert.equal(parseByteSize(4096), 4096);
    assert.equal(parseByteSize(0), 0);
  });

  it('rejects unknown suffix', () => {
    assert.equal(parseByteSize('1XB'), null);
    assert.equal(parseByteSize('1FooBytes'), null);
  });

  it('rejects negative and malformed input', () => {
    assert.equal(parseByteSize('-1'), null);
    assert.equal(parseByteSize(-1), null);
    assert.equal(parseByteSize('abc'), null);
    assert.equal(parseByteSize(''), null);
    assert.equal(parseByteSize(null), null);
    assert.equal(parseByteSize(undefined), null);
  });
});

describe('pick', () => {
  it('returns first non-null/non-undefined value', () => {
    assert.equal(pick(undefined, null, 'a', 'b'), 'a');
    assert.equal(pick(null, 42), 42);
    assert.equal(pick(undefined, undefined, 'x'), 'x');
  });

  it('treats false, 0, empty string as defined', () => {
    assert.equal(pick(false, 'x'), false);
    assert.equal(pick(0, 1), 0);
    assert.equal(pick('', 'x'), '');
  });

  it('returns undefined when nothing is defined', () => {
    assert.equal(pick(), undefined);
    assert.equal(pick(undefined, null), undefined);
  });
});

describe('validateSettings — structure', () => {
  it('accepts an empty object', () => {
    const r = validateSettings({});
    assert.equal(r.valid, true);
    assert.equal(r.errors.length, 0);
  });

  it('rejects non-object top-level', () => {
    assert.equal(validateSettings(null).valid, false);
    assert.equal(validateSettings([]).valid, false);
    assert.equal(validateSettings('x').valid, false);
  });

  it('rejects unknown top-level keys', () => {
    const r = validateSettings({ foo: 1 });
    assert.equal(r.valid, false);
    assert.match(r.errors[0], /unknown top-level key "foo"/);
  });
});

describe('validateSettings — instance', () => {
  it('accepts simple identifier name', () => {
    const r = validateSettings({ instance: { name: 'prod-east', tags: ['a', 'b'] } });
    assert.equal(r.valid, true);
  });

  it('accepts display-label names with spaces and mixed case', () => {
    for (const name of ['GitHub Production', 'Twitter Frontdoor', 'Source Control Prod']) {
      const r = validateSettings({ instance: { name } });
      assert.equal(r.valid, true, `"${name}" should be a valid display label`);
    }
  });

  it('rejects names with control characters (log-forgery)', () => {
    const r = validateSettings({ instance: { name: 'bad\nname' } });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some((e) => /control characters/.test(e)));
  });

  it('rejects empty name', () => {
    const r = validateSettings({ instance: { name: '' } });
    assert.equal(r.valid, false);
  });

  it('rejects name longer than 100 characters', () => {
    const r = validateSettings({ instance: { name: 'x'.repeat(101) } });
    assert.equal(r.valid, false);
  });

  it('rejects non-string-array tags', () => {
    const r = validateSettings({ instance: { tags: [1, 2] } });
    assert.equal(r.valid, false);
  });

  it('rejects unknown instance keys', () => {
    const r = validateSettings({ instance: { extra: true } });
    assert.equal(r.valid, false);
  });
});

describe('validateSettings — bridge', () => {
  it('rejects invalid transport type', () => {
    const r = validateSettings({ bridge: { transport: { type: 'http' } } });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some((e) => /transport\.type must be one of/.test(e)));
  });

  it('rejects out-of-range port', () => {
    const r = validateSettings({ bridge: { transport: { port: 70000 } } });
    assert.equal(r.valid, false);
  });

  it('accepts byte-size strings for request/response max bytes', () => {
    const r = validateSettings({
      bridge: { limits: { request: { maxBytes: '1MB' }, response: { maxBytes: 2048 } } },
    });
    assert.equal(r.valid, true);
  });

  it('rejects non-integer dispatch.maxConcurrent', () => {
    const r = validateSettings({ bridge: { limits: { dispatch: { maxConcurrent: 1.5 } } } });
    assert.equal(r.valid, false);
  });

  it('rejects maxConcurrent above 10000', () => {
    const r = validateSettings({ bridge: { limits: { dispatch: { maxConcurrent: 20000 } } } });
    assert.equal(r.valid, false);
  });

  it('rejects non-boolean network flags', () => {
    const r = validateSettings({ bridge: { network: { allowPrivate: 'yes' } } });
    assert.equal(r.valid, false);
  });
});

describe('validateSettings — frontdoor', () => {
  it('accepts full valid shape', () => {
    const r = validateSettings({
      frontdoor: {
        transport: { type: 'sse', host: '0.0.0.0', port: 8080 },
        auth: { requireBearerEnv: 'TOK' },
        network: { allowedOrigins: ['https://example.com'] },
        limits: { sse: { maxConnections: 100, idleTimeoutMs: 60000 } },
        surface: { allowTools: ['a.*'], denyTools: ['b.*'], healthDetail: true },
        policy: { path: '/etc/policy.json' },
        telemetry: { audit: false, events: true },
      },
    });
    assert.equal(r.valid, true);
  });

  it('rejects frontdoor.auth.* when transport is stdio', () => {
    const r = validateSettings({
      frontdoor: {
        transport: { type: 'stdio' },
        auth: { requireBearerEnv: 'TOK' },
      },
    });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some((e) => /requires settings.frontdoor.transport.type = "sse"/.test(e)));
  });

  it('warns but does not fail on allowedOrigins under stdio', () => {
    const r = validateSettings({
      frontdoor: {
        transport: { type: 'stdio' },
        network: { allowedOrigins: ['https://x'] },
      },
    });
    assert.equal(r.valid, true);
    assert.ok(r.warnings.some((w) => /allowedOrigins is ignored/.test(w)));
  });

  it('rejects idleTimeoutMs < 1000', () => {
    const r = validateSettings({
      frontdoor: { limits: { sse: { idleTimeoutMs: 500 } } },
    });
    assert.equal(r.valid, false);
  });

  it('rejects non-boolean telemetry flags', () => {
    const r = validateSettings({
      frontdoor: { telemetry: { audit: 'false' } },
    });
    assert.equal(r.valid, false);
  });
});

describe('loadSettings — discovery', () => {
  it('returns defaults when no file present', async () => {
    const r = await loadSettings({ cwd: workDir });
    assert.equal(r.source, null);
    assert.equal(r.settings, DEFAULT_SETTINGS);
    assert.equal(r.warnings.length, 0);
  });

  it('loads CWD settings file when present', async () => {
    write('40mcp.settings.json', { bridge: { transport: { type: 'sse', port: 9999 } } });
    const r = await loadSettings({ cwd: workDir });
    assert.ok(r.source && r.source.endsWith('40mcp.settings.json'));
    assert.equal(r.settings.bridge.transport.type, 'sse');
    assert.equal(r.settings.bridge.transport.port, 9999);
  });

  it('auto-discovers sibling of config file before CWD', async () => {
    // Sibling at workDir/nested/ with its own settings; CWD (workDir) also has one
    const nested = join(workDir, 'nested');
    mkdirSync(nested);
    writeFileSync(join(nested, 'config.json'), '{}');
    writeFileSync(join(nested, '40mcp.settings.json'), JSON.stringify({
      instance: { name: 'sibling' },
    }));
    write('40mcp.settings.json', { instance: { name: 'cwd' } });

    const r = await loadSettings({ cwd: workDir, configPath: 'nested/config.json' });
    assert.equal(r.settings.instance.name, 'sibling');
  });

  it('falls back to CWD when sibling does not exist', async () => {
    const nested = join(workDir, 'nested');
    mkdirSync(nested);
    writeFileSync(join(nested, 'config.json'), '{}');
    write('40mcp.settings.json', { instance: { name: 'cwd' } });

    const r = await loadSettings({ cwd: workDir, configPath: 'nested/config.json' });
    assert.equal(r.settings.instance.name, 'cwd');
  });

  it('honors explicit --settings path', async () => {
    const explicit = write('custom.json', { instance: { name: 'explicit' } });
    write('40mcp.settings.json', { instance: { name: 'cwd' } });
    const r = await loadSettings({ cwd: workDir, explicitPath: explicit });
    assert.equal(r.settings.instance.name, 'explicit');
  });

  it('throws for nonexistent explicit path', async () => {
    await assert.rejects(
      () => loadSettings({ cwd: workDir, explicitPath: join(workDir, 'missing.json') }),
      (err) => /--settings/.test(err.message),
    );
  });

  it('throws with actionable message on invalid JSON', async () => {
    write('40mcp.settings.json', '{ not valid json');
    await assert.rejects(
      () => loadSettings({ cwd: workDir }),
      (err) => /not valid JSON/.test(err.message),
    );
  });

  it('throws when settings fail validation', async () => {
    write('40mcp.settings.json', { bridge: { transport: { port: 999999 } } });
    await assert.rejects(
      () => loadSettings({ cwd: workDir }),
      (err) => /Invalid 40mcp\.settings\.json/.test(err.message),
    );
  });

  it('returned settings object is deeply frozen', async () => {
    write('40mcp.settings.json', { bridge: { transport: { type: 'sse' } } });
    const r = await loadSettings({ cwd: workDir });
    assert.throws(() => { r.settings.bridge.transport.type = 'stdio'; });
    assert.throws(() => { r.settings.frontdoor.telemetry.audit = false; });
  });

  it('merges partial settings with defaults', async () => {
    write('40mcp.settings.json', { bridge: { transport: { type: 'sse', port: 9000 } } });
    const r = await loadSettings({ cwd: workDir });
    // Unspecified keys take defaults.
    assert.equal(r.settings.bridge.limits.dispatch.maxConcurrent, 50);
    assert.equal(r.settings.frontdoor.telemetry.audit, true);
    assert.deepEqual([...r.settings.frontdoor.surface.allowTools], []);
  });
});
