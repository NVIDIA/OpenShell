// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Optional real-browser fixture. CDP uses anonymous pipes, a disposable profile,
// loopback-only hostname resolution, and a disposable test issuer credential.
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const { gateway, application, token } = JSON.parse(input);
  const profile = mkdtempSync(join(tmpdir(), 'openshell-auth-browser-'));
  const chrome = spawn(process.env.OPENSHELL_BROWSER_E2E_CHROME, [
    '--headless=new', '--remote-debugging-pipe', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking',
    '--ignore-certificate-errors', '--no-proxy-server',
    '--host-resolver-rules=MAP gateway.example.test 127.0.0.1, MAP *.services.example.com 127.0.0.1',
    `--user-data-dir=${profile}`,
  ], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  const pending = new Map();
  let next = 0;
  let buffered = '';
  chrome.stdio[4].on('data', chunk => {
    buffered += chunk.toString();
    for (let end; (end = buffered.indexOf('\0')) >= 0;) {
      const message = JSON.parse(buffered.slice(0, end));
      buffered = buffered.slice(end + 1);
      const waiter = pending.get(message.id);
      if (waiter) {
        pending.delete(message.id);
        if (message.error) waiter.reject(new Error(message.error.message));
        else waiter.resolve(message.result);
      }
    }
  });
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++next;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve: result => { clearTimeout(timeout); resolve(result); }, reject: error => { clearTimeout(timeout); reject(error); } });
    chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
  });
  try {
    const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
    await call('Page.enable', {}, sessionId);
    const evaluate = async expression => {
      const result = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
      if (result.exceptionDetails) throw new Error('Browser evaluation failed');
      return result.result.value;
    };
    const waitFor = async expression => {
      const until = Date.now() + 15000;
      while (Date.now() < until) {
        try { if (await evaluate(expression)) return; } catch { /* Navigation can replace the execution context. */ }
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      throw new Error(`Browser flow did not converge: ${await evaluate('location.origin + " " + document.title')}`);
    };
    await call('Page.navigate', { url: `${gateway}/auth/services?service_origin=${encodeURIComponent(application)}` }, sessionId);
    await waitFor(`location.origin === ${JSON.stringify(gateway)} && !!document.getElementById('token')`);
    await evaluate(`document.getElementById('token').value=${JSON.stringify(token)};document.getElementById('login').requestSubmit();true`);
    await waitFor(`location.origin === ${JSON.stringify(application)} && !!document.getElementById('application')`);
    const { cookies } = await call('Network.getCookies', { urls: [application] }, sessionId);
    const session = cookies.find(cookie => cookie.name === '__Host-openshell-service-session');
    if (!session || !session.secure || !session.httpOnly || session.sameSite !== 'Strict') throw new Error('Missing protected session cookie');
    if ((await evaluate('document.cookie')).includes('__Host-openshell-')) throw new Error('Gateway cookie exposed to application JavaScript');
    if (await evaluate(`fetch('/echo',{method:'POST',body:'application request'}).then(r=>r.status)`) !== 200) throw new Error('Authenticated application POST failed');
    if (await evaluate(`fetch('/.openshell/service-auth/session',{method:'DELETE'}).then(r=>r.status)`) !== 204) throw new Error('Logout failed');
    if (await evaluate(`fetch('/').then(r=>r.status)`) !== 401) throw new Error('Logged-out browser retained access');
    process.stdout.write('PASS browser cross-site login, Strict/HttpOnly cookies, authenticated POST, and logout\n');
  } finally {
    if (chrome.exitCode === null && chrome.signalCode === null) {
      chrome.kill('SIGKILL');
      await new Promise(resolve => chrome.once('exit', resolve));
    }
    rmSync(profile, { recursive: true, force: true });
  }
}
main().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
