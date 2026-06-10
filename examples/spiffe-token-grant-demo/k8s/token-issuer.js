// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8080);
const JWKS_URI =
  process.env.SPIRE_JWKS_URI ||
  "https://spire-spiffe-oidc-discovery-provider.spire.svc.cluster.local/keys";
const SPIRE_ISSUER =
  process.env.SPIRE_ISSUER ||
  "https://spire-spiffe-oidc-discovery-provider.spire.svc.cluster.local";
const JWT_SVID_AUDIENCE =
  process.env.JWT_SVID_AUDIENCE || "http://token-issuer.default.svc.cluster.local";
const TRUST_DOMAIN_PREFIX =
  process.env.TRUST_DOMAIN_PREFIX || "spiffe://openshell.local/openshell/sandbox/";
const ACCESS_TOKEN_ISSUER =
  process.env.ACCESS_TOKEN_ISSUER || "http://token-issuer.default.svc.cluster.local";
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

if (!ACCESS_TOKEN_SECRET) {
  throw new Error("ACCESS_TOKEN_SECRET is required");
}

let cachedJwks;
let cachedJwksAt = 0;

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
    header: JSON.parse(b64urlDecode(parts[0]).toString("utf8")),
    payload: JSON.parse(b64urlDecode(parts[1]).toString("utf8")),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: b64urlDecode(parts[2]),
  };
}

async function jwks() {
  const now = Date.now();
  if (cachedJwks && now - cachedJwksAt < 60000) {
    return cachedJwks;
  }
  const response = await fetch(JWKS_URI);
  if (!response.ok) {
    throw new Error(`JWKS fetch failed with HTTP ${response.status}`);
  }
  cachedJwks = await response.json();
  cachedJwksAt = now;
  return cachedJwks;
}

function hasAudience(payload, expected) {
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  return aud.includes(expected);
}

async function verifyJwtSvid(jwt) {
  const parsed = parseJwt(jwt);
  if (parsed.header.alg !== "RS256") {
    throw new Error(`unsupported JWT-SVID alg ${parsed.header.alg}`);
  }

  const keys = await jwks();
  const jwk = keys.keys.find((key) => key.kid === parsed.header.kid);
  if (!jwk) {
    throw new Error(`no JWKS key for kid ${parsed.header.kid}`);
  }

  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(parsed.signingInput);
  verifier.end();
  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (!verifier.verify(publicKey, parsed.signature)) {
    throw new Error("JWT-SVID signature validation failed");
  }

  const now = Math.floor(Date.now() / 1000);
  if (parsed.payload.exp && parsed.payload.exp <= now) {
    throw new Error("JWT-SVID expired");
  }
  if (parsed.payload.nbf && parsed.payload.nbf > now + 30) {
    throw new Error("JWT-SVID not active yet");
  }
  if (parsed.payload.iss !== SPIRE_ISSUER) {
    throw new Error(`unexpected JWT-SVID issuer ${parsed.payload.iss}`);
  }
  if (!hasAudience(parsed.payload, JWT_SVID_AUDIENCE)) {
    throw new Error(`JWT-SVID audience did not include ${JWT_SVID_AUDIENCE}`);
  }
  if (!String(parsed.payload.sub || "").startsWith(TRUST_DOMAIN_PREFIX)) {
    throw new Error("JWT-SVID subject was not an OpenShell sandbox SPIFFE ID");
  }
  return parsed.payload;
}

function signAccessToken(payload) {
  const header = b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlEncode(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signature = crypto
    .createHmac("sha256", ACCESS_TOKEN_SECRET)
    .update(signingInput)
    .digest();
  return `${signingInput}.${b64urlEncode(signature)}`;
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

async function bodyText(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
    if (Buffer.concat(chunks).length > 1024 * 1024) {
      throw new Error("request body too large");
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function handleToken(req, res) {
  const params = new URLSearchParams(await bodyText(req));
  if (params.get("grant_type") !== "client_credentials") {
    return json(res, 400, { error: "unsupported_grant_type" });
  }
  if (
    params.get("client_assertion_type") !==
    "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
  ) {
    return json(res, 400, { error: "unsupported_client_assertion_type" });
  }

  const jwtSvid = params.get("client_assertion");
  if (!jwtSvid) {
    return json(res, 400, { error: "missing_client_assertion" });
  }

  const resourceAudience = params.get("audience") || "";
  const requestedScopes = (params.get("scope") || "").split(/\s+/).filter(Boolean);
  if (!["alpha", "beta"].includes(resourceAudience)) {
    return json(res, 400, { error: "unsupported_audience", audience: resourceAudience });
  }
  if (!requestedScopes.includes(resourceAudience)) {
    return json(res, 403, { error: "missing_matching_scope" });
  }

  const svid = await verifyJwtSvid(jwtSvid);
  const now = Math.floor(Date.now() / 1000);
  const subjectHash = crypto.createHash("sha256").update(svid.sub).digest("hex").slice(0, 32);
  const accessToken = signAccessToken({
    iss: ACCESS_TOKEN_ISSUER,
    sub: subjectHash,
    aud: [resourceAudience, "account"],
    scope: `${requestedScopes.join(" ")} profile email`,
    azp: svid.sub,
    client_id: svid.sub,
    iat: now,
    exp: now + 300,
  });

  return json(res, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 300,
    scope: `${requestedScopes.join(" ")} profile email`,
  });
}

http
  .createServer(async (req, res) => {
    try {
      if (req.url === "/healthz") {
        res.writeHead(200, { "content-type": "text/plain" });
        return res.end("ok\n");
      }
      if (req.method === "POST" && req.url === "/token") {
        return await handleToken(req, res);
      }
      return json(res, 404, { error: "not_found" });
    } catch (error) {
      console.error(error);
      return json(res, 500, { error: "server_error", message: error.message });
    }
  })
  .listen(PORT, "0.0.0.0", () => {
    console.log(`token issuer listening on ${PORT}`);
  });
