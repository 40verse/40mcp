/**
 * Unit tests for instance-metadata helpers in `src/core/events.js`.
 * `setInstanceMetadata` injects `instance.{name,tags}`
 * into every `[40mcp:event]` and `[40mcp:audit]` entry so the audit trail
 * carries the friendly name and tags alongside canonical identifiers.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  setInstanceMetadata,
  getInstanceMetadata,
  buildInstanceField,
  emitEvent,
  setTelemetryConfig,
} from '../../src/core/events.js';
import { emitAuditLog } from '../../src/bridge.js';

// Capture stderr while `fn` runs; restore after.
async function captureStderr(fn) {
  const lines = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => {
    lines.push(typeof chunk === 'string' ? chunk : chunk.toString());
    return true;
  };
  try { await fn(); } finally { process.stderr.write = original; }
  return lines.join('');
}

beforeEach(() => {
  // Reset module-level state so tests don't bleed.
  setInstanceMetadata({ name: null, tags: [] });
  setTelemetryConfig({ audit: true, events: true });
});

afterEach(() => {
  setInstanceMetadata({ name: null, tags: [] });
  setTelemetryConfig({ audit: true, events: true });
});

describe('setInstanceMetadata / getInstanceMetadata', () => {
  it('defaults to null name and empty tags', () => {
    const m = getInstanceMetadata();
    assert.equal(m.name, null);
    assert.deepEqual(m.tags, []);
  });

  it('stores name and tags', () => {
    setInstanceMetadata({ name: 'GitHub Production', tags: ['prod', 'source-control'] });
    const m = getInstanceMetadata();
    assert.equal(m.name, 'GitHub Production');
    assert.deepEqual(m.tags, ['prod', 'source-control']);
  });

  it('ignores non-object input', () => {
    setInstanceMetadata({ name: 'set' });
    setInstanceMetadata(null);
    setInstanceMetadata('string');
    assert.equal(getInstanceMetadata().name, 'set');
  });

  it('filters non-string tag entries', () => {
    setInstanceMetadata({ tags: ['a', 1, null, 'b'] });
    assert.deepEqual(getInstanceMetadata().tags, ['a', 'b']);
  });

  it('returns a defensive copy (mutation does not bleed)', () => {
    setInstanceMetadata({ name: 'x', tags: ['t1'] });
    const m = getInstanceMetadata();
    m.tags.push('mutated');
    assert.deepEqual(getInstanceMetadata().tags, ['t1']);
  });
});

describe('buildInstanceField', () => {
  it('returns undefined when nothing set', () => {
    assert.equal(buildInstanceField(), undefined);
  });

  it('returns name only when no tags', () => {
    setInstanceMetadata({ name: 'only-name' });
    assert.deepEqual(buildInstanceField(), { name: 'only-name' });
  });

  it('returns tags only when no name', () => {
    setInstanceMetadata({ tags: ['t1', 't2'] });
    assert.deepEqual(buildInstanceField(), { tags: ['t1', 't2'] });
  });

  it('returns both when both set', () => {
    setInstanceMetadata({ name: 'GitHub', tags: ['prod'] });
    assert.deepEqual(buildInstanceField(), { name: 'GitHub', tags: ['prod'] });
  });
});

describe('emitEvent — instance enrichment', () => {
  it('omits instance field when metadata is unset', async () => {
    const out = await captureStderr(() => { emitEvent('test.event', { foo: 1 }); });
    const line = out.trim();
    assert.match(line, /^\[40mcp:event\] /);
    const json = JSON.parse(line.replace('[40mcp:event] ', ''));
    assert.equal(json.instance, undefined);
    assert.equal(json.event, 'test.event');
    assert.equal(json.foo, 1);
  });

  it('injects instance field when metadata is set', async () => {
    setInstanceMetadata({ name: 'GitHub Production', tags: ['prod'] });
    const out = await captureStderr(() => { emitEvent('test.event', { foo: 1 }); });
    const json = JSON.parse(out.trim().replace('[40mcp:event] ', ''));
    assert.deepEqual(json.instance, { name: 'GitHub Production', tags: ['prod'] });
    assert.equal(json.foo, 1);
  });

  it('telemetry off suppresses entirely', async () => {
    setInstanceMetadata({ name: 'x' });
    setTelemetryConfig({ events: false });
    const out = await captureStderr(() => { emitEvent('test.event'); });
    assert.equal(out, '');
  });
});

describe('emitAuditLog — instance enrichment', () => {
  it('omits instance field when metadata is unset', async () => {
    const out = await captureStderr(() => { emitAuditLog({ tool: 't', status: 'success' }); });
    const json = JSON.parse(out.trim().replace('[40mcp:audit] ', ''));
    assert.equal(json.instance, undefined);
    assert.equal(json.tool, 't');
  });

  it('injects instance field when metadata is set', async () => {
    setInstanceMetadata({ name: 'frontdoor-prod', tags: ['prod', 'sse'] });
    const out = await captureStderr(() => { emitAuditLog({ tool: 'github.list', status: 'success', durationMs: 42 }); });
    const json = JSON.parse(out.trim().replace('[40mcp:audit] ', ''));
    assert.deepEqual(json.instance, { name: 'frontdoor-prod', tags: ['prod', 'sse'] });
    assert.equal(json.tool, 'github.list');
    assert.equal(json.durationMs, 42);
  });

  it('caller-supplied instance field wins over injected metadata', async () => {
    setInstanceMetadata({ name: 'global', tags: ['env'] });
    const out = await captureStderr(() => { emitAuditLog({ instance: { name: 'override' }, tool: 't' }); });
    const json = JSON.parse(out.trim().replace('[40mcp:audit] ', ''));
    assert.deepEqual(json.instance, { name: 'override' });
  });

  it('telemetry off suppresses entirely', async () => {
    setInstanceMetadata({ name: 'x' });
    setTelemetryConfig({ audit: false });
    const out = await captureStderr(() => { emitAuditLog({ tool: 't' }); });
    assert.equal(out, '');
  });
});
