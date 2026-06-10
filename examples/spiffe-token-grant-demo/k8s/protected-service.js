// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8080);
const SERVICE_NAME = process.env.SERVICE_NAME || "alpha";
const EXPECTED_AUDIENCE = process.env.EXPECTED_AUDIENCE || SERVICE_NAME;
const EXPECTED_SCOPE = process.env.EXPECTED_SCOPE || SERVICE_NAME;
const ACCESS_TOKEN_ISSUER =
  process.env.ACCESS_TOKEN_ISSUER || "http://token-issuer.default.svc.cluster.local";
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

if (!ACCESS_TOKEN_SECRET) {
  throw new Error("ACCESS_TOKEN_SECRET is required");
}

function b64urlDecode(value) {
  const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function b64urlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function parseJwt(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("JWT must contain three segments");
  }
  return {
    payload: JSON.parse(b64urlDecode(parts[1]).toString("utf8")),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: parts[2],
  };
}

function verifyAccessToken(jwt) {
  const parsed = parseJwt(jwt);
  const expected = b64urlEncode(
    crypto.createHmac("sha256", ACCESS_TOKEN_SECRET).update(parsed.signingInput).digest(),
  );
  if (
    parsed.signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(parsed.signature), Buffer.from(expected))
  ) {
    throw new Error("access token signature validation failed");
  }

  const now = Math.floor(Date.now() / 1000);
  if (parsed.payload.exp && parsed.payload.exp <= now) {
    throw new Error("access token expired");
  }
  if (parsed.payload.iss !== ACCESS_TOKEN_ISSUER) {
    throw new Error(`unexpected access token issuer ${parsed.payload.iss}`);
  }
  const aud = Array.isArray(parsed.payload.aud) ? parsed.payload.aud : [parsed.payload.aud];
  if (!aud.includes(EXPECTED_AUDIENCE)) {
    throw new Error(`access token audience did not include ${EXPECTED_AUDIENCE}`);
  }
  const scopes = String(parsed.payload.scope || "").split(/\s+/).filter(Boolean);
  if (!scopes.includes(EXPECTED_SCOPE)) {
    throw new Error(`access token scope did not include ${EXPECTED_SCOPE}`);
  }
  return parsed.payload;
}

function text(res, status, body) {
  res.writeHead(status, { "content-type": "text/plain" });
  res.end(body);
}

http
  .createServer((req, res) => {
    try {
      if (req.url === "/healthz") {
        return text(res, 200, "ok\n");
      }
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
      if (!token) {
        console.warn(`${SERVICE_NAME} rejected request path=${req.url} reason=missing_bearer_token`);
        return text(res, 401, `${SERVICE_NAME} missing bearer token\n`);
      }
      const claims = verifyAccessToken(token);
      const aud = Array.isArray(claims.aud) ? claims.aud.join(", ") : claims.aud;
      console.log(
        `${SERVICE_NAME} accepted request path=${req.url} aud="${aud}" scope="${claims.scope}" client_id=${claims.client_id}`,
      );
      return text(
        res,
        200,
        `${SERVICE_NAME} called with path ${req.url}:\n` +
          `  sub: ${claims.sub}\n` +
          `  aud: ${aud}\n` +
          `  iss: ${claims.iss}\n` +
          `  scope: ${claims.scope}\n` +
          `  azp: ${claims.azp}\n` +
          `  client_id: ${claims.client_id}\n`,
      );
    } catch (error) {
      console.warn(`${SERVICE_NAME} rejected request path=${req.url} reason="${error.message}"`);
      return text(res, 403, `${SERVICE_NAME} rejected token: ${error.message}\n`);
    }
  })
  .listen(PORT, "0.0.0.0", () => {
    console.log(`${SERVICE_NAME} listening on ${PORT}`);
  });
