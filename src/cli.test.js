/**
 * Tests for cli.js — currently focused on loadFrontdoorJson file-size cap.
 *
 * loadFrontdoorJson is not exported (cli.js is a runnable script), so
 * coverage is achieved via subprocess: spawn `node src/cli.js serve` with a
 * valid minimal config and a --policy file that is slightly over the 16 MiB
 * limit.  The process must exit 1 and emit the "file too large" diagnostic to
 * stderr.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, 'cli.js');

/** 16 MiB — must match MAX_FRONTDOOR_FILE_BYTES in cli.js. */
const MAX_FRONTDOOR_FILE_BYTES = 16 * 1024 * 1024;

// ─── Temp-file helpers ────────────────────────────────────────────────────────

const createdFiles = [];
const createdDirs = [];

function tmpFile(name, content) {
  const filePath = join(tmpdir(), `cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}-${name}`);
  writeFileSync(filePath, content);
  createdFiles.push(filePath);
  return filePath;
}

after(() => {
  for (const f of createdFiles) {
    try { unlinkSync(f); } catch {}
  }
  for (const d of createdDirs) {
    try { rmdirSync(d); } catch {}
  }
});

// ─── loadFrontdoorJson size-cap ───────────────────────────────────────────────

describe('loadFrontdoorJson — file-size cap', () => {
  it('rejects a --policy file that exceeds the 16 MiB limit', () => {
    // Minimal valid config that loadConfig will accept.
    const configPath = tmpFile('config.json', JSON.stringify({
      tools: [],
      servers: [],
    }));

    // Policy file slightly above the cap: MAX + 1 byte.
    // Fill with spaces so JSON.parse would succeed if the cap weren't present.
    const oversize = MAX_FRONTDOOR_FILE_BYTES + 1;
    // Construct: leading whitespace (ignored by JSON.parse) + valid JSON object.
    // We use a Buffer of spaces followed by "{}" to stay valid JSON while
    // exceeding the size limit.
    const policyBuf = Buffer.alloc(oversize, 0x20); // 0x20 = space
    // Overwrite last two bytes with '{}'
    policyBuf[oversize - 2] = 0x7b; // '{'
    policyBuf[oversize - 1] = 0x7d; // '}'
    const policyPath = tmpFile('policy.json', policyBuf);

    const result = spawnSync(process.execPath, [CLI_PATH, 'serve', configPath, '--policy', policyPath], {
      encoding: 'utf-8',
      timeout: 15_000,
    });

    assert.strictEqual(result.status, 1, `Expected exit code 1, got ${result.status}`);
    assert.ok(
      result.stderr.includes('file too large'),
      `Expected stderr to contain "file too large", got: ${result.stderr}`,
    );
  });

  it('accepts a --policy file at exactly the 16 MiB limit', () => {
    const configPath = tmpFile('config.json', JSON.stringify({
      tools: [],
      servers: [],
    }));

    // File at exactly the cap should not be rejected by the size check.
    // It will be rejected later (not a valid JSON object with meaningful
    // content) — but the process must NOT exit with "file too large".
    const atLimit = MAX_FRONTDOOR_FILE_BYTES;
    const policyBuf = Buffer.alloc(atLimit, 0x20);
    policyBuf[atLimit - 2] = 0x7b; // '{'
    policyBuf[atLimit - 1] = 0x7d; // '}'
    const policyPath = tmpFile('policy-exact.json', policyBuf);

    const result = spawnSync(process.execPath, [CLI_PATH, 'serve', configPath, '--policy', policyPath], {
      encoding: 'utf-8',
      timeout: 15_000,
    });

    assert.ok(
      !result.stderr.includes('file too large'),
      `Unexpected "file too large" for at-limit file. stderr: ${result.stderr}`,
    );
  });
});
