#!/usr/bin/env node

// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const required = [
  "CODEX_AUTH_ACCESS_TOKEN",
  "CODEX_AUTH_ACCOUNT_ID",
];
for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`missing required provider credential: ${name}`);
  }
}

const b64u = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const now = Math.floor(Date.now() / 1000);
const idToken = [
  b64u({ alg: "none", typ: "JWT" }),
  b64u({
    iss: "https://auth.openai.com",
    aud: "codex",
    sub: "openshell-app-server",
    email: "app-server@openshell.local",
    iat: now,
    exp: now + 3600,
  }),
  "placeholder",
].join(".");

const codexHome = path.join(process.env.HOME, ".codex");
fs.mkdirSync(codexHome, { recursive: true });
fs.writeFileSync(path.join(codexHome, "auth.json"), JSON.stringify({
  // The gateway owns token refresh; Codex must not attempt to refresh these
  // externally managed tokens itself.
  auth_mode: "chatgptAuthTokens",
  OPENAI_API_KEY: null,
  tokens: {
    // Provider values are opaque stable handles. Codex parses the ID token
    // locally, so use a short-lived, non-secret identity placeholder for it.
    id_token: idToken,
    access_token: process.env.CODEX_AUTH_ACCESS_TOKEN,
    refresh_token: "",
    account_id: process.env.CODEX_AUTH_ACCOUNT_ID,
  },
  last_refresh: new Date().toISOString(),
}, null, 2), { mode: 0o600 });

const port = process.env.CODEX_APP_SERVER_PORT || "4500";
const server = spawn(
  "codex",
  ["app-server", "--listen", `ws://127.0.0.1:${port}`],
  { stdio: "inherit" },
);
server.on("error", (error) => {
  console.error(error);
  process.exit(1);
});
server.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 1);
  }
});
