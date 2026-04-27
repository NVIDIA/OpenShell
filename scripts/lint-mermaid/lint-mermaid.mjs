#!/usr/bin/env node
// Validate ```mermaid fenced blocks in Markdown/MDX files using the official
// mermaid parser. Line numbers in error output are offset back to the source
// file so editors can jump to them.
//
// Why this approach (load the real `mermaid` npm package in Node + jsdom):
//
// - `@mermaid-js/mermaid-cli` (mmdc): uses the official parser/renderer, but
//   pulls Puppeteer + Chromium (~300MB) because it also produces SVGs. Way
//   too heavy for pre-commit; usable only as a CI backstop.
// - `@probelabs/maid`: fast, Chevrotain-based, single small package. In
//   practice it produced false positives AND missed real errors in this
//   repo (notably the `exec()s` sequence-diagram bug in
//   `architecture/sandbox-connect.md`). Dropped for unreliability.
// - `go-mermaid`: pure Go single binary — attractive, but a custom parser
//   that lags the official Mermaid grammar; would drift silently.
// - `@mermaid-js/parser` (Langium, official): library only, and as of
//   writing covers only a subset of diagram types (flowchart, sequence,
//   class, state still partially on the legacy Jison grammar inside the
//   main `mermaid` package). Incomplete for our mix of diagrams.
// - `mermaid.parse()` from the `mermaid` package (this approach): uses the
//   SAME grammar that actually renders on GitHub and in Fern previews, so
//   "passes here" == "renders there". Needs a DOM shim because mermaid
//   loads DOMPurify at import time, hence jsdom. Runs in ~2s across the
//   repo with no browser dependency.

import { readdir, readFile, stat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
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
const OPEN_FENCE_RE = /^[ \t]*(`{3,}|~{3,})(.*)$/;

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

function getGitRoot() {
  const result = spawnSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' });
  if (result.status !== 0) return null;
  return result.stdout.trim();
}

function filterGitIgnored(files) {
  const gitRoot = getGitRoot();
  if (!gitRoot || files.length === 0) return files;

  const pathsByRel = new Map();
  for (const file of files) {
    const rel = relative(gitRoot, file);
    if (rel.startsWith('..') || rel === '' || rel.startsWith('/')) continue;
    pathsByRel.set(rel, file);
  }
  if (pathsByRel.size === 0) return files;

  const result = spawnSync('git', ['check-ignore', '--stdin'], {
    cwd: gitRoot,
    input: `${Array.from(pathsByRel.keys()).join('\n')}\n`,
    encoding: 'utf8',
  });
  if (result.status !== 0 && result.status !== 1) return files;

  const ignored = new Set(result.stdout.split('\n').filter(Boolean));
  return files.filter(file => {
    const rel = relative(gitRoot, file);
    return !ignored.has(rel);
  });
}

function parseFenceOpen(line) {
  const match = line.match(OPEN_FENCE_RE);
  if (!match) return null;

  const marker = match[1][0];
  const length = match[1].length;
  const info = match[2].trim();
  if (marker === '`' && info.includes('`')) return null;

  const language = info.split(/\s+/)[0].toLowerCase();
  return { marker, length, isMermaid: language === 'mermaid' };
}

function isFenceClose(line, fence) {
  const trimmed = line.trim();
  return trimmed.length >= fence.length && [...trimmed].every(ch => ch === fence.marker);
}

function extractBlocks(text) {
  const lines = text.split('\n');
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const fence = parseFenceOpen(lines[i]);
    if (!fence) { i++; continue; }
    const startLine = i + 1;
    const body = [];
    i++;
    while (i < lines.length && !isFenceClose(lines[i], fence)) {
      if (fence.isMermaid) body.push(lines[i]);
      i++;
    }
    if (fence.isMermaid) blocks.push({ startLine, body: body.join('\n') });
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
      const entry = await stat(abs);
      if (entry.isDirectory()) {
        for await (const f of walk(abs)) files.push(f);
      } else if (EXTENSIONS.has(extname(abs))) {
        files.push(abs);
      }
    } catch (err) {
      console.error(`cannot read ${root}: ${err.message}`);
      process.exitCode = 1;
    }
  }

  const filteredFiles = filterGitIgnored(files);
  const results = await Promise.all(filteredFiles.map(lintFile));
  const allErrors = results.flat();
  const filesWithBlocks = results.reduce((n, errs, i) => n + (errs.length > 0 ? 1 : 0), 0);

  if (allErrors.length > 0) {
    for (const e of allErrors) console.error(e);
    console.error(`\n${allErrors.length} mermaid error(s) in ${filesWithBlocks} file(s); scanned ${filteredFiles.length} file(s)`);
    process.exit(1);
  }
  console.log(`mermaid: scanned ${filteredFiles.length} file(s), all diagrams valid`);
}

main().catch(err => {
  console.error(err);
  process.exit(2);
});
