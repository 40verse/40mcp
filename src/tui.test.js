import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { tui } from './tui.js';

describe('tui — environment detection', () => {
  it('exports isTTY, isNoColor, isMcpStdio booleans', () => {
    assert.equal(typeof tui.isTTY, 'boolean');
    assert.equal(typeof tui.isNoColor, 'boolean');
    assert.equal(typeof tui.isMcpStdio, 'boolean');
  });
});

describe('tui — primitives', () => {
  it('bold wraps string', () => {
    const result = tui.bold('test');
    assert.ok(result.includes('test'));
  });

  it('dim wraps string', () => {
    const result = tui.dim('test');
    assert.ok(result.includes('test'));
  });

  it('color functions return strings containing input', () => {
    assert.ok(tui.red('err').includes('err'));
    assert.ok(tui.green('ok').includes('ok'));
    assert.ok(tui.yellow('warn').includes('warn'));
    assert.ok(tui.blue('info').includes('info'));
    assert.ok(tui.cyan('spin').includes('spin'));
    assert.ok(tui.gray('dim').includes('dim'));
  });
});

describe('tui — table', () => {
  it('renders a table with headers and rows', () => {
    const result = tui.table(
      ['NAME', 'METHOD', 'PATH'],
      [
        ['list_users', 'GET', '/users'],
        ['get_user', 'GET', '/users/:id'],
      ],
    );
    assert.ok(result.includes('NAME'));
    assert.ok(result.includes('list_users'));
    assert.ok(result.includes('/users/:id'));
  });

  it('handles empty rows', () => {
    const result = tui.table(['A', 'B'], []);
    assert.ok(result.includes('A'));
  });
});

describe('tui — box', () => {
  it('renders a box with title and lines', () => {
    const result = tui.box('Title', ['Line 1', 'Line 2']);
    assert.ok(result.includes('Title'));
    assert.ok(result.includes('Line 1'));
    assert.ok(result.includes('┌'));
    assert.ok(result.includes('└'));
  });
});

describe('tui — toolTable', () => {
  it('renders tool list as table', () => {
    const result = tui.toolTable([
      { name: 'list_users', method: 'GET', path: '/users', description: 'List users' },
      { name: 'my_chain', chain: [{ call: 'a', as: 'a' }, { call: 'b', as: 'b' }], description: 'A chain' },
    ]);
    assert.ok(result.includes('list_users'));
    assert.ok(result.includes('CHAIN'));
    assert.ok(result.includes('2 steps'));
  });
});

describe('tui — statusLine', () => {
  it('renders status parts', () => {
    const result = tui.statusLine([
      ['TOOLS', 47],
      ['TRANSPORT', 'stdio'],
    ]);
    assert.ok(result.includes('47'));
    assert.ok(result.includes('stdio'));
  });
});

describe('tui — activityLine', () => {
  it('renders an activity event', () => {
    const result = tui.activityLine({
      tool: 'list_users',
      status: 200,
      latencyMs: 150,
      time: '12:04:31',
    });
    assert.ok(result.includes('list_users'));
    assert.ok(result.includes('200'));
    assert.ok(result.includes('150ms'));
  });
});

describe('tui — banner', () => {
  it('renders a banner', () => {
    const result = tui.banner('my-api', '1.0.0', [['tools', '12']]);
    assert.ok(result.includes('40mcp'));
    assert.ok(result.includes('my-api'));
    assert.ok(result.includes('1.0.0'));
  });
});

describe('tui — spinner', () => {
  it('creates a spinner with stop method', () => {
    const s = tui.spinner('Loading...');
    assert.ok(typeof s.stop === 'function');
    assert.ok(typeof s.update === 'function');
    s.stop('Done');
  });
});

describe('tui — progress', () => {
  it('creates a progress bar', () => {
    const p = tui.progress('Parsing', 10);
    assert.ok(typeof p.tick === 'function');
    assert.ok(typeof p.set === 'function');
    assert.ok(typeof p.done === 'function');
    p.done();
  });
});
