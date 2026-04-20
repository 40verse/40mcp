#!/usr/bin/env node
// One-shot audit: every internal markdown link in shipping docs resolves.
// Not wired into CI — a throwaway gate run manually before push.

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';

const rootDocs = [
  'README.md', 'SPEC.md', 'SECURITY.md', 'CHANGELOG.md',
  'AGENTS.md', 'API.md', 'CONCEPT.md', 'CONTRIBUTING.md', 'TROUBLESHOOTING.md',
];
const docsDir = readdirSync('docs', { recursive: true })
  .filter((f) => typeof f === 'string' && f.endsWith('.md'))
  .map((f) => join('docs', f));
const files = [...rootDocs, ...docsDir];

const linkRe = /\]\(([^)]+)\)/g;
const issues = [];

for (const file of files) {
  if (!existsSync(file)) {
    issues.push({ file, link: '(file missing)', kind: 'missing-file' });
    continue;
  }
  const src = readFileSync(file, 'utf-8');
  let m;
  while ((m = linkRe.exec(src))) {
    const raw = m[1].split('#')[0];
    if (!raw || raw.startsWith('http') || raw.startsWith('mailto:')) continue;
    const resolved = resolve(dirname(file), raw);
    if (!existsSync(resolved)) {
      issues.push({
        file,
        link: raw,
        resolved: relative('.', resolved),
        kind: 'broken',
      });
    }
  }
}

if (issues.length === 0) {
  console.log('OK: all internal markdown links resolve');
  process.exit(0);
}
console.log(`BROKEN LINKS: ${issues.length}`);
for (const i of issues) {
  console.log(`  ${i.file} -> ${i.link}  (resolves: ${i.resolved || 'n/a'})`);
}
process.exit(1);
