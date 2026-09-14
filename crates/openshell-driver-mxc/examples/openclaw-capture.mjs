// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// openclaw-capture.mjs - generic launcher/log-capture shim for running an
// arbitrary Node.js entry point as agent_command inside an MXC
// ProcessContainer sandbox.
//
// This is OpenShell's own adapter code, not part of OpenClaw -- it contains
// no OpenClaw-specific logic. It exists because the sandboxed process's own
// stdout/stderr are piped (not inherited) by openshell-supervisor-relay (see
// pc_relay_spawner_path), which forwards them to the gateway log tagged
// "[target stdout]"/"[target stderr]" -- but a durable on-disk log inside
// share_dir is also useful for post-hoc debugging without re-running.
//
// Required env vars (set via agent_env in the gateway TOML):
//   NEMOCLAW_MXC_CAPTURE_ENTRY  absolute path to the real entry .mjs to run
//                               (e.g. <openclaw install>/openclaw.mjs)
//   NEMOCLAW_MXC_CAPTURE_LOG    absolute path to append captured output to
//
// Usage: node openclaw-capture.mjs <args...>
// Equivalent to: node <NEMOCLAW_MXC_CAPTURE_ENTRY> <args...>, except stdout
// and stderr are also appended to NEMOCLAW_MXC_CAPTURE_LOG as they're written.

import fs, { appendFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { createConnection } from "node:net";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

// Node's promises realpath implementation uses a native Windows binding that
// requests privileges unavailable to AppContainer tokens. The callback
// implementation has the same realpath contract without those privileges.
// Patch before importing OpenClaw so node:fs/promises consumers see it too.
if (process.platform === "win32") {
  fs.promises.realpath = promisify(fs.realpath);
  syncBuiltinESMExports();
}

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(name + " is required");
  return value;
};

const entry = required("NEMOCLAW_MXC_CAPTURE_ENTRY");
const logPath = required("NEMOCLAW_MXC_CAPTURE_LOG");
const selfProbePort = process.env.NEMOCLAW_MXC_CAPTURE_SELF_PROBE_PORT;

const append = (label, value) => {
  try {
    appendFileSync(logPath, "[" + label + "] " + String(value), "utf8");
  } catch {
    // best-effort; never let logging failure take down the wrapped process
  }
};

const connectProbe = (host, port, timeoutMs = 5000) =>
  new Promise((resolve) => {
    let settled = false;
    const socket = createConnection({ host, port: Number(port) });
    const finish = (connected, detail) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.destroy();
      resolve({ connected, detail });
    };
    const deadline = setTimeout(() => finish(false, "timeout"), timeoutMs);
    socket.once("connect", () => finish(true, "connected"));
    socket.once("error", (error) =>
      finish(false, String(error?.code || error?.message || error)),
    );
  });

const fetchProbe = async (url, timeoutMs = 15000) => {
  try {
    const response = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    await response.body?.cancel();
    return { connected: true, detail: "status=" + response.status };
  } catch (error) {
    return {
      connected: false,
      detail: String(error?.cause?.code || error?.code || error?.message || error),
    };
  }
};

const runEgressProof = async () => {
  if (process.env.NEMOCLAW_MXC_EGRESS_PROOF !== "1") return;
  const result = {
    proxyConfigured: Boolean(process.env.HTTPS_PROXY || process.env.https_proxy),
    allowedViaProxy: await fetchProbe(required("NEMOCLAW_MXC_EGRESS_ALLOWED_URL")),
    deniedViaProxy: await fetchProbe(required("NEMOCLAW_MXC_EGRESS_DENIED_URL")),
    directInternetBypass: await connectProbe(
      required("NEMOCLAW_MXC_EGRESS_DIRECT_HOST"),
      443,
    ),
    unrelatedHostLoopback: await connectProbe(
      "127.0.0.1",
      required("NEMOCLAW_MXC_EGRESS_LOOPBACK_PORT"),
    ),
  };
  append("egress-proof", JSON.stringify(result) + "\n");
  console.log("[egress-proof] " + JSON.stringify(result));
};

let selfProbeStarted = false;
let readinessWindow = "";

const startSelfProbe = () => {
  if (selfProbeStarted || !selfProbePort) return;
  selfProbeStarted = true;
  append("self-probe-attempt", "started\n");

  const port = Number(selfProbePort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    append("self-probe", "invalid_port\n");
    return;
  }

  const maxAttempts = 6;
  let attempt = 0;
  const probe = () => {
    attempt += 1;
    let responseBytes = 0;
    let settled = false;
    const socket = createConnection({ host: "127.0.0.1", port });
    const finish = (outcome, errorCode = "none") => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.destroy();
      if (responseBytes > 0 || attempt >= maxAttempts) {
        append(
          "self-probe",
          `outcome=${responseBytes > 0 ? "response" : outcome} response_bytes=${responseBytes} attempts=${attempt} error_code=${errorCode}\n`,
        );
      } else {
        setTimeout(probe, 1000);
      }
    };
    const deadline = setTimeout(() => finish("timeout"), 2000);

    socket.once("connect", () => {
      // This is the same protocol boundary exercised by the host-side health
      // client, but it intentionally sends no token or other credential. Any
      // HTTP or WebSocket response proves the target can service a connection
      // from inside the ProcessContainer; payload content is never recorded.
      socket.write(
        `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: b3BlbnNoZWxsLW14YyE=\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
    });
    socket.on("data", (chunk) => {
      responseBytes += chunk.length;
      finish("response");
    });
    socket.once("error", (error) =>
      finish("error", String(error?.code || "unknown").replace(/[^A-Z0-9_-]/gi, "_")),
    );
    socket.once("close", () => {
      if (!settled) finish(responseBytes > 0 ? "response" : "closed");
    });
  };
  probe();
};

const wrap = (stream, label) => {
  const original = stream.write.bind(stream);
  stream.write = (chunk, encoding, callback) => {
    const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    append(label, text);
    // Logging libraries may split one rendered line across multiple writes
    // (and may insert ANSI sequences), so detect readiness across chunk
    // boundaries rather than requiring one exact write call.
    readinessWindow = (readinessWindow + text).slice(-512);
    if (/\[gateway\][\s\S]{0,256}ready/.test(readinessWindow)) startSelfProbe();
    return original(chunk, encoding, callback);
  };
};

wrap(process.stdout, "stdout");
wrap(process.stderr, "stderr");
append("self-probe", selfProbePort ? "configured\n" : "disabled\n");
if (selfProbePort) {
  // Readiness normally triggers the probe immediately. Keep a delayed
  // fallback because some logging stacks bypass or split stdout writes in a
  // way the wrapper cannot observe reliably.
  setTimeout(startSelfProbe, 10000);
}
process.on("uncaughtExceptionMonitor", (error) =>
  append("uncaught", String(error?.stack || error) + "\n"),
);
process.on("unhandledRejection", (error) =>
  append("rejection", String(error?.stack || error) + "\n"),
);

process.argv = [process.execPath, entry, ...process.argv.slice(2)];
await runEgressProof();
await import(pathToFileURL(entry).href);
