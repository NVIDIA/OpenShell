#!/usr/bin/env node
// One-shot codemod: convert bare opening ``` fences to ```text so MD040 passes.
// Walks each file, toggles open/close state, and only rewrites the opener.

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, extname } from 'node:path';

const EXCLUDE_DIRS = new Set([
  'node_modules', 'target', '.venv', '.git', '.cache',
  '_build', 'build', 'dist', '.fern-cache', '.agents',
  '.claude', '.opencode', '.github',
]);
const EXTENSIONS = new Set(['.md', '.mdx']);
const BARE_FENCE_RE = /^([ \t]*)```[ \t]*$/;
const FENCE_RE = /^([ \t]*)```/;

async function* walk(root) {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.') continue;
    if (EXCLUDE_DIRS.has(entry.name)) continue;
    const p = join(root, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else if (EXTENSIONS.has(extname(entry.name))) yield p;
  }
}

function transform(text) {
  const lines = text.split('\n');
  let inFence = false;
  let changed = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!FENCE_RE.test(lines[i])) continue;
    if (!inFence) {
      const m = lines[i].match(BARE_FENCE_RE);
      if (m) {
        lines[i] = `${m[1]}\`\`\`text`;
        changed++;
      }
      inFence = true;
    } else {
      inFence = false;
    }
  }
  return { text: lines.join('\n'), changed };
}

const root = process.argv[2] || '.';
let totalFiles = 0, totalChanges = 0;
for await (const f of walk(root)) {
  const orig = await readFile(f, 'utf8');
  const { text, changed } = transform(orig);
  if (changed > 0) {
    await writeFile(f, text);
    console.log(`${f}: ${changed} fence(s)`);
    totalFiles++;
    totalChanges += changed;
  }
}
console.log(`\nRewrote ${totalChanges} fence(s) in ${totalFiles} file(s).`);
