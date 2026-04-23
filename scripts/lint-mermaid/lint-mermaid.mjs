#!/usr/bin/env node
// Validate ```mermaid fenced blocks in Markdown/MDX files using the official
// mermaid parser. Line numbers in error output are offset back to the source
// file so editors can jump to them.

import { readdir, readFile } from 'node:fs/promises';
import { join, relative, resolve, extname } from 'node:path';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;

const { default: mermaid } = await import('mermaid');

const EXCLUDE_DIRS = new Set([
  'node_modules', 'target', '.venv', '.git', '.cache',
  '_build', 'build', 'dist', '.fern-cache', '.agents',
]);
const EXTENSIONS = new Set(['.md', '.mdx']);
const FENCE_RE = /^([ \t]*)```mermaid[ \t]*$/;

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

function extractBlocks(text) {
  const lines = text.split('\n');
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const m = lines[i].match(FENCE_RE);
    if (!m) { i++; continue; }
    const startLine = i + 1;
    const body = [];
    i++;
    while (i < lines.length && !/^[ \t]*```[ \t]*$/.test(lines[i])) {
      body.push(lines[i]);
      i++;
    }
    blocks.push({ startLine, body: body.join('\n') });
    i++;
  }
  return blocks;
}

function formatError(err, file, block) {
  const msg = err?.message || String(err);
  const match = msg.match(/Parse error on line (\d+)/i);
  const relLine = match ? parseInt(match[1], 10) : 1;
  const sourceLine = block.startLine + relLine;
  const head = msg.split('\n').slice(0, 6).join('\n    ');
  return `${file}:${sourceLine}: mermaid parse error\n    ${head}`;
}

async function lintFile(file) {
  const text = await readFile(file, 'utf8');
  const blocks = extractBlocks(text);
  const errors = [];
  for (const block of blocks) {
    try {
      await mermaid.parse(block.body);
    } catch (err) {
      errors.push(formatError(err, file, block));
    }
  }
  return errors;
}

async function main() {
  const args = process.argv.slice(2);
  const roots = args.length ? args : ['.'];
  const files = [];
  for (const root of roots) {
    const abs = resolve(root);
    try {
      const stat = await import('node:fs').then(m => m.promises.stat(abs));
      if (stat.isDirectory()) {
        for await (const f of walk(abs)) files.push(f);
      } else if (EXTENSIONS.has(extname(abs))) {
        files.push(abs);
      }
    } catch (err) {
      console.error(`cannot read ${root}: ${err.message}`);
      process.exitCode = 1;
    }
  }

  const results = await Promise.all(files.map(lintFile));
  const allErrors = results.flat();
  const filesWithBlocks = results.reduce((n, errs, i) => n + (errs.length > 0 ? 1 : 0), 0);

  if (allErrors.length > 0) {
    for (const e of allErrors) console.error(e);
    console.error(`\n${allErrors.length} mermaid error(s) in ${filesWithBlocks} file(s); scanned ${files.length} file(s)`);
    process.exit(1);
  }
  console.log(`mermaid: scanned ${files.length} file(s), all diagrams valid`);
}

main().catch(err => {
  console.error(err);
  process.exit(2);
});
