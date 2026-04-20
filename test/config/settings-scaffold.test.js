import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildSettingsScaffold } from '../../src/config/settings-scaffold.js';
import { validateSettings } from '../../src/config/settings.js';

describe('buildSettingsScaffold', () => {
  it('returns a JSON-parsable string', () => {
    const out = buildSettingsScaffold();
    assert.doesNotThrow(() => JSON.parse(out));
  });

  it('produces a settings object that passes the validator', () => {
    const obj = JSON.parse(buildSettingsScaffold({ instanceName: 'test-instance' }));
    const res = validateSettings(obj);
    assert.equal(res.valid, true, `validator errors: ${res.errors.join(', ')}`);
  });

  it('uses the given instance name', () => {
    const obj = JSON.parse(buildSettingsScaffold({ instanceName: 'GitHub Production' }));
    assert.equal(obj.instance.name, 'GitHub Production');
  });

  it('defaults instanceName to "my-instance"', () => {
    const obj = JSON.parse(buildSettingsScaffold());
    assert.equal(obj.instance.name, 'my-instance');
  });

  it('populates all three clusters', () => {
    const obj = JSON.parse(buildSettingsScaffold());
    assert.ok(obj.instance);
    assert.ok(obj.bridge);
    assert.ok(obj.frontdoor);
  });

  it('ends with a trailing newline (POSIX-friendly)', () => {
    assert.ok(buildSettingsScaffold().endsWith('\n'));
  });
});
