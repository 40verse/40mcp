/**
 * TUI — Terminal UI primitives for 40mcp.
 *
 * Zero dependencies. All output to stderr (stdout is the MCP wire).
 * Respects NO_COLOR and non-TTY environments.
 *
 * @module tui
 */

// ─── Environment detection ──────────────────────────────────────────────────

const isTTY = process.stderr.isTTY === true;
const isNoColor = process.env.NO_COLOR !== undefined || !isTTY;
const isMcpStdio = !process.stdout.isTTY;

const w = (s) => process.stderr.write(s);

// ─── ANSI primitives ────────────────────────────────────────────────────────

function color(code, str) {
  if (isNoColor) return str;
  return `\x1b[${code}m${str}\x1b[0m`;
}

const bold = (s) => color('1', s);
const dim = (s) => color('2', s);
const red = (s) => color('31', s);
const green = (s) => color('32', s);
const yellow = (s) => color('33', s);
const blue = (s) => color('34', s);
const cyan = (s) => color('36', s);
const gray = (s) => color('90', s);

const cursor = {
  hide: () => isTTY && w('\x1b[?25l'),
  show: () => isTTY && w('\x1b[?25h'),
  up: (n = 1) => isTTY && w(`\x1b[${n}A`),
  clearLine: () => isTTY && w('\x1b[2K\r'),
  saveCursor: () => isTTY && w('\x1b[s'),
  restoreCursor: () => isTTY && w('\x1b[u'),
};

// ─── Spinner ────────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

function spinner(label) {
  if (!isTTY) {
    w(`  [ ... ] ${label}\n`);
    return {
      update(newLabel) { w(`  [ ... ] ${newLabel}\n`); },
      stop(finalMsg) { w(`  ${finalMsg}\n`); },
    };
  }

  let frame = 0;
  let currentLabel = label;
  const interval = setInterval(() => {
    cursor.clearLine();
    w(`  ${cyan(SPINNER_FRAMES[frame % SPINNER_FRAMES.length])} ${currentLabel}`);
    frame++;
  }, 80);
  interval.unref();

  return {
    update(newLabel) { currentLabel = newLabel; },
    stop(finalMsg) {
      clearInterval(interval);
      cursor.clearLine();
      w(`  ${finalMsg}\n`);
    },
  };
}

// ─── Progress bar ───────────────────────────────────────────────────────────

function progress(label, total) {
  let current = 0;
  const barWidth = 20;

  function render() {
    const pct = Math.round((current / total) * 100);
    const filled = Math.round((current / total) * barWidth);
    const bar = '█'.repeat(filled) + '░'.repeat(barWidth - filled);

    if (isTTY) {
      cursor.clearLine();
      w(`  ${label}  ${dim('[')}${green(bar)}${dim(']')}  ${pct}%  ${gray(`${current}/${total}`)}`);
    }
  }

  return {
    tick() { current = Math.min(current + 1, total); render(); },
    set(n) { current = Math.min(n, total); render(); },
    done() {
      current = total;
      if (isTTY) {
        cursor.clearLine();
        w(`  ${green('✓')} ${label}  ${dim(`${total} items`)}\n`);
      } else {
        w(`  ${label}  100%  (${total}/${total})\n`);
      }
    },
  };
}

// ─── Table ──────────────────────────────────────────────────────────────────

function table(headers, rows, options = {}) {
  const { indent = '  ' } = options;

  // Calculate column widths
  const colWidths = headers.map((h, i) => {
    const dataMax = rows.reduce((max, row) => Math.max(max, String(row[i] || '').length), 0);
    return Math.max(h.length, dataMax);
  });

  const lines = [];

  // Header
  const headerLine = headers.map((h, i) => bold(h.padEnd(colWidths[i]))).join('  ');
  lines.push(`${indent}${headerLine}`);
  lines.push(`${indent}${dim('─'.repeat(colWidths.reduce((a, b) => a + b + 2, 0)))}`);

  // Rows
  for (const row of rows) {
    const rowLine = row.map((cell, i) => String(cell || '').padEnd(colWidths[i])).join('  ');
    lines.push(`${indent}${rowLine}`);
  }

  return lines.join('\n');
}

// ─── Box ────────────────────────────────────────────────────────────────────

function box(title, lines, options = {}) {
  const { width } = options;
  const maxLineLen = Math.max(title.length, ...lines.map((l) => l.length));
  const boxWidth = width || Math.min(maxLineLen + 4, process.stderr.columns || 60);
  const inner = boxWidth - 4;

  const out = [];
  out.push(dim('┌─') + dim('─'.repeat(inner)) + dim('─┐'));
  out.push(dim('│ ') + bold(title.padEnd(inner)) + dim(' │'));
  out.push(dim('├─') + dim('─'.repeat(inner)) + dim('─┤'));
  for (const line of lines) {
    out.push(dim('│ ') + line.padEnd(inner) + dim(' │'));
  }
  out.push(dim('└─') + dim('─'.repeat(inner)) + dim('─┘'));
  return out.join('\n');
}

// ─── Tool table (formatted for 40mcp) ──────────────────────────────────────

function toolTable(tools) {
  const rows = tools.map((t) => [
    t.name,
    t.method || (t.chain ? 'CHAIN' : '?'),
    t.path || `→ ${(t.chain || []).length} steps`,
    dim(t.description?.slice(0, 40) || ''),
  ]);
  return table(['NAME', 'METHOD', 'PATH', 'DESCRIPTION'], rows);
}

// ─── Status line ────────────────────────────────────────────────────────────

function statusLine(parts) {
  const formatted = parts.map(([label, value, colorFn]) => {
    const fn = colorFn || ((s) => s);
    return `${dim(label)} ${fn(String(value))}`;
  });
  return formatted.join(dim('  ·  '));
}

// ─── Fatal error ────────────────────────────────────────────────────────────

function fatal(msg, code = 1) {
  w(`\n  ${red('✗')} ${bold('Error:')} ${msg}\n\n`);
  process.exit(code);
}

// ─── Success message ────────────────────────────────────────────────────────

function success(msg) {
  w(`  ${green('✓')} ${msg}\n`);
}

// ─── Info message ───────────────────────────────────────────────────────────

function info(msg) {
  w(`  ${blue('ℹ')} ${msg}\n`);
}

// ─── Warning message ────────────────────────────────────────────────────────

function warn(msg) {
  w(`  ${yellow('⚠')} ${msg}\n`);
}

// ─── Banner ─────────────────────────────────────────────────────────────────

function banner(name, version, extras = []) {
  const lines = [];
  lines.push('');
  lines.push(`  ${bold('40mcp')}  ${dim('·')}  ${name}  ${dim(`v${version}`)}`);
  if (extras.length > 0) {
    lines.push(`  ${extras.map(([k, v]) => `${dim(k)} ${v}`).join('  ')}`);
  }
  lines.push('');
  return lines.join('\n');
}

// ─── JSON output (stdout — for machine consumption) ─────────────────────────

function jsonOutput(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

// ─── Activity log line ──────────────────────────────────────────────────────

function activityLine(event) {
  const { tool, status, latencyMs, size, tokensSaved, time } = event;
  const ts = time || new Date().toLocaleTimeString();
  const dot = status >= 200 && status < 300 ? green('●')
    : status >= 400 && status < 500 ? yellow('●')
      : red('●');
  const latencyColor = latencyMs < 200 ? green : latencyMs < 1000 ? yellow : red;
  const parts = [
    gray(ts),
    dot,
    bold(tool.padEnd(25)),
  ];
  if (status) parts.push(`${status}`);
  if (latencyMs) parts.push(latencyColor(`${latencyMs}ms`));
  if (size) parts.push(dim(`${size}`));
  if (tokensSaved) parts.push(dim(`${tokensSaved} tokens saved`));
  return `  ${parts.join('  ')}`;
}

// ─── Export ─────────────────────────────────────────────────────────────────

export const tui = {
  // Environment
  isTTY,
  isNoColor,
  isMcpStdio,

  // Primitives
  color, bold, dim,
  red, green, yellow, blue, cyan, gray,
  cursor,

  // Components
  spinner,
  progress,
  table,
  box,
  toolTable,
  statusLine,
  activityLine,
  banner,

  // Messages
  fatal,
  success,
  info,
  warn,

  // Machine output
  jsonOutput,
};
