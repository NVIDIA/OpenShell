// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const fs = require("fs");

const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_SPIFFE_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";

const PORT = Number(process.env.PORT || 8080);
const JWKS_URI =
  process.env.SPIRE_JWKS_URI ||
  "https://spire-spiffe-oidc-discovery-provider.spire.svc.cluster.local/keys";
const SPIRE_ISSUER =
  process.env.SPIRE_ISSUER ||
  "https://spire-spiffe-oidc-discovery-provider.spire.svc.cluster.local";
const JWT_SVID_AUDIENCE =
  process.env.JWT_SVID_AUDIENCE || "http://token-exchange-issuer.default.svc.cluster.local";
const SUPERVISOR_TRUST_DOMAIN_PREFIX =
  process.env.SUPERVISOR_TRUST_DOMAIN_PREFIX || "spiffe://openshell.local/openshell/sandbox/";
const GATEWAY_TRUST_DOMAIN_PREFIX =
  process.env.GATEWAY_TRUST_DOMAIN_PREFIX || "spiffe://openshell.local/ns/openshell/sa/";
const ACCESS_TOKEN_ISSUER =
  process.env.ACCESS_TOKEN_ISSUER || "http://token-exchange-issuer.default.svc.cluster.local";
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const DEMO_USER_SUBJECT = process.env.DEMO_USER_SUBJECT || "demo-user";
const SPIRE_JWKS_CA_FILE = process.env.SPIRE_JWKS_CA_FILE || "";

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
    signatureB64: parts[2],
  };
}

async function jwks() {
  const now = Date.now();
  if (cachedJwks && now - cachedJwksAt < 60000) {
    return cachedJwks;
  }
  cachedJwks = await fetchJson(JWKS_URI);
  cachedJwksAt = now;
  return cachedJwks;
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === "https:";
    const client = isHttps ? https : http;
    const options = {};
    if (isHttps && SPIRE_JWKS_CA_FILE) {
      options.ca = fs.readFileSync(SPIRE_JWKS_CA_FILE);
    }

    const req = client.get(parsed, options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`JWKS fetch failed with HTTP ${res.statusCode}: ${body}`));
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(10000, () => req.destroy(new Error("JWKS fetch timed out")));
  });
}

function hasAudience(payload, expected) {
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  return aud.includes(expected);
}

async function verifyJwtSvid(jwt, subjectPrefix) {
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
  if (!String(parsed.payload.sub || "").startsWith(subjectPrefix)) {
    throw new Error(`JWT-SVID subject did not start with ${subjectPrefix}`);
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

function verifyAccessToken(jwt, tokenUse) {
  const parsed = parseJwt(jwt);
  const expected = b64urlEncode(
    crypto.createHmac("sha256", ACCESS_TOKEN_SECRET).update(parsed.signingInput).digest(),
  );
  if (
    parsed.signatureB64.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(parsed.signatureB64), Buffer.from(expected))
  ) {
    throw new Error("token signature validation failed");
  }

  const now = Math.floor(Date.now() / 1000);
  if (parsed.payload.exp && parsed.payload.exp <= now) {
    throw new Error("token expired");
  }
  if (parsed.payload.iss !== ACCESS_TOKEN_ISSUER) {
    throw new Error(`unexpected token issuer ${parsed.payload.iss}`);
  }
  if (parsed.payload.demo_token_use !== tokenUse) {
    throw new Error(`expected ${tokenUse} token`);
  }
  return parsed.payload;
}

function issueDemoSubjectToken() {
  const now = Math.floor(Date.now() / 1000);
  return signAccessToken({
    iss: ACCESS_TOKEN_ISSUER,
    sub: DEMO_USER_SUBJECT,
    aud: ["openshell-gateway", "account"],
    scope: "openid profile email",
    demo_token_use: "user_subject",
    iat: now,
    exp: now + 1800,
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
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

async function handleTokenExchange(req, res) {
  const params = new URLSearchParams(await bodyText(req));
  if (params.get("grant_type") !== TOKEN_EXCHANGE_GRANT_TYPE) {
    return json(res, 400, { error: "unsupported_grant_type" });
  }
  if (params.get("client_assertion_type") !== JWT_SPIFFE_ASSERTION_TYPE) {
    return json(res, 400, { error: "unsupported_client_assertion_type" });
  }

  const jwtSvid = params.get("client_assertion");
  if (!jwtSvid) {
    return json(res, 400, { error: "missing_client_assertion" });
  }
  const subjectToken = params.get("subject_token");
  if (!subjectToken) {
    return json(res, 400, { error: "missing_subject_token" });
  }

  const audience = params.get("audience") || "";
  const requestedScopes = (params.get("scope") || "").split(/\s+/).filter(Boolean);
  const now = Math.floor(Date.now() / 1000);

  const userToken = (() => {
    try {
      return verifyAccessToken(subjectToken, "user_subject");
    } catch (_error) {
      return null;
    }
  })();

  if (userToken) {
    const gatewaySvid = await verifyJwtSvid(jwtSvid, GATEWAY_TRUST_DOMAIN_PREFIX);
    if (!audience.startsWith(SUPERVISOR_TRUST_DOMAIN_PREFIX)) {
      return json(res, 400, { error: "unsupported_intermediate_audience", audience });
    }
    const intermediateToken = signAccessToken({
      iss: ACCESS_TOKEN_ISSUER,
      sub: userToken.sub,
      aud: [audience],
      scope: userToken.scope || "openid profile email",
      azp: gatewaySvid.sub,
      client_id: gatewaySvid.sub,
      demo_token_use: "intermediate",
      iat: now,
      exp: now + 300,
    });
    console.log(`issued intermediate token for user=${userToken.sub} audience=${audience}`);
    return json(res, 200, {
      access_token: intermediateToken,
      token_type: "Bearer",
      expires_in: 300,
    });
  }

  const supervisorSvid = await verifyJwtSvid(jwtSvid, SUPERVISOR_TRUST_DOMAIN_PREFIX);
  const intermediateToken = verifyAccessToken(subjectToken, "intermediate");
  if (!hasAudience(intermediateToken, supervisorSvid.sub)) {
    return json(res, 403, { error: "intermediate_token_audience_mismatch" });
  }
  if (!["alpha", "beta"].includes(audience)) {
    return json(res, 400, { error: "unsupported_audience", audience });
  }
  if (!requestedScopes.includes(audience)) {
    return json(res, 403, { error: "missing_matching_scope" });
  }

  const accessToken = signAccessToken({
    iss: ACCESS_TOKEN_ISSUER,
    sub: intermediateToken.sub,
    aud: [audience, "account"],
    scope: `${requestedScopes.join(" ")} profile email`,
    azp: supervisorSvid.sub,
    client_id: supervisorSvid.sub,
    demo_token_use: "final",
    iat: now,
    exp: now + 300,
  });

  console.log(
    `issued final token for user=${intermediateToken.sub} audience=${audience} client=${supervisorSvid.sub}`,
  );
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
      if (req.method === "GET" && req.url === "/demo-subject-token") {
        return json(res, 200, {
          access_token: issueDemoSubjectToken(),
          token_type: "Bearer",
          expires_in: 1800,
        });
      }
      if (req.method === "POST" && req.url === "/token") {
        return await handleTokenExchange(req, res);
      }
      return json(res, 404, { error: "not_found" });
    } catch (error) {
      console.error(error);
      return json(res, 500, { error: "server_error", message: error.message });
    }
  })
  .listen(PORT, "0.0.0.0", () => {
    console.log(`token exchange issuer listening on ${PORT}`);
  });
