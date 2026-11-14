import { OpenShellClient } from '@nvidia/openshell-sdk';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const state = process.argv[2] ?? join(process.env.LOCALAPPDATA, 'OpenShell', 'Windows-0.1.8');
const settings = JSON.parse(await readFile(join(state, 'settings.json'), 'utf8'));
const workspace = join(state, 'workspace');
await mkdir(workspace, { recursive: true });
const system = process.env.SystemRoot ?? 'C:/Windows';
const id = randomUUID().slice(0, 8);
const resultPath = join(workspace, `result-${id}.txt`);
const command = [join(system, 'System32', 'cmd.exe'), '/d', '/c', `echo OpenShell-Windows-harness-ok>result-${id}.txt`];
const client = await OpenShellClient.connect({ gateway: settings.endpoint });
console.log(await client.health());
let sandbox;
try {
  sandbox = await client.sandbox.create({
    name: `ts-${id}`,
    policy: { version: 1, filesystem: { includeWorkdir: false, readWrite: [workspace] } },
    rawSpec: { template: { driverConfig: { mxc: { command, cwd: workspace } } } },
  });
  await client.sandbox.waitReady(sandbox.name, 60);
  const deadline = Date.now() + 60000;
  let completed;
  while (Date.now() < deadline) {
    completed = await client.sandbox.get(sandbox.name);
    if (['completed', 'error', 'stopped'].includes(completed.phase)) break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  if (completed?.phase !== 'completed' || completed.exitCode !== 0) {
    throw new Error(`Command failed: ${JSON.stringify(completed)}`);
  }
  const output = await readFile(resultPath, 'utf8');
  if (output.trim() !== 'OpenShell-Windows-harness-ok') throw new Error('Unexpected workload result');
  console.log(output.trim());
} catch (error) {
  if (sandbox) console.error(JSON.stringify(await client.sandbox.get(sandbox.name), null, 2));
  throw error;
} finally {
  if (sandbox) {
    const result = await client.sandbox.delete(sandbox.name);
    if (result.outcome === 'accepted') {
      await client.sandbox.waitDeleted(sandbox.name, 60, { expectedSandboxId: result.sandboxId });
    } else if (!['completed', 'already_absent'].includes(result.outcome)) {
      throw new Error(`Cleanup not confirmed: ${result.outcome}`);
    }
  }
  await rm(resultPath, { force: true });
}
