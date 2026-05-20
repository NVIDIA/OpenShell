#!/usr/bin/env node

// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";
import { randomUUID } from "node:crypto";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i], process.argv[i + 1]);
}

const role = args.get("--role") ?? "planner";
const host = args.get("--host") ?? "127.0.0.1";
const port = Number(args.get("--port") ?? "8080");

const ROLE_CONFIG = {
  planner: {
    name: "Planning Agent",
    skill: "problem-framing",
    description:
      "Frames the issue, names assumptions, and turns prior critique into the next review plan.",
    tags: ["planning", "triage", "scope"],
  },
  security: {
    name: "Security Agent",
    skill: "security-review",
    description:
      "Reviews credential flow, sandbox policy, prompt injection, and data-exfiltration risks.",
    tags: ["security", "policy", "credentials"],
  },
  implementation: {
    name: "Implementation Agent",
    skill: "implementation-review",
    description:
      "Maps the issue and prior review notes to concrete implementation and testing steps.",
    tags: ["implementation", "testing", "docs"],
  },
  critic: {
    name: "Critic Agent",
    skill: "synthesis-critique",
    description:
      "Challenges weak claims, asks for missing evidence, and synthesizes the strongest next artifact.",
    tags: ["critique", "synthesis", "quality"],
  },
};

const config = ROLE_CONFIG[role] ?? ROLE_CONFIG.planner;

function requestBaseUrl(req) {
  const proto = req.headers["x-forwarded-proto"] ?? "http";
  const hostHeader = req.headers["x-forwarded-host"] ?? req.headers.host;
  return `${proto}://${hostHeader}`;
}

function agentCard(req) {
  const baseUrl = requestBaseUrl(req);
  return {
    name: config.name,
    description: config.description,
    provider: {
      organization: "OpenShell example",
      url: "https://github.com/NVIDIA/OpenShell",
    },
    version: "1.0.0",
    capabilities: {
      streaming: true,
      pushNotifications: false,
    },
    defaultInputModes: ["text/plain", "application/json"],
    defaultOutputModes: ["text/markdown", "application/json"],
    skills: [
      {
        id: config.skill,
        name: config.name,
        description: config.description,
        tags: config.tags,
        examples: [
          "Review this GitHub issue and prior agent notes.",
          "Revise your recommendation based on the latest critique.",
        ],
        inputModes: ["text/plain", "application/json"],
        outputModes: ["text/markdown", "application/json"],
      },
    ],
    supportedInterfaces: [
      {
        protocolBinding: "HTTP+JSON",
        protocolVersion: "1.0",
        url: baseUrl,
      },
    ],
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        req.destroy(new Error("request body too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function parseRequest(body) {
  const parsed = body ? JSON.parse(body) : {};
  const textPart = parsed.message?.parts?.find((part) => typeof part.text === "string");
  const dataPart = parsed.message?.parts?.find((part) => part.data && typeof part.data === "object");
  const data = dataPart?.data ?? {};
  if (textPart && !data.prompt) {
    data.prompt = textPart.text;
  }
  return data;
}

function issueSummary(issue) {
  const labels = Array.isArray(issue.labels) && issue.labels.length > 0 ? issue.labels.join(", ") : "none";
  return `#${issue.number ?? "?"} ${issue.title ?? "Untitled issue"} (${labels})`;
}

function priorByRole(transcript, wantedRole) {
  return transcript
    .filter((entry) => entry.role === wantedRole)
    .slice(-1)
    .map((entry) => entry.artifact)
    .join("\n");
}

function bullets(items) {
  return items.map((item) => `- ${item}`).join("\n");
}

function reviewFor(input) {
  const issue = input.issue ?? {};
  const transcript = Array.isArray(input.transcript) ? input.transcript : [];
  const round = Number(input.round ?? 1);
  const latestPlan = priorByRole(transcript, "planner");
  const latestSecurity = priorByRole(transcript, "security");
  const latestImplementation = priorByRole(transcript, "implementation");
  const latestCritic = priorByRole(transcript, "critic");
  const body = `${issue.title ?? ""}\n${issue.body ?? ""}`.toLowerCase();
  const mentionsPolicy = /policy|credential|token|secret|auth|permission|network|sandbox/.test(body);
  const mentionsDocs = /doc|readme|tutorial|example|guide/.test(body);
  const mentionsTest = /test|ci|e2e|regression|verify|coverage/.test(body);

  if (role === "planner") {
    const focus = [
      "Identify the smallest useful deliverable that would close or de-risk the issue.",
      mentionsPolicy
        ? "Treat policy and credential boundaries as first-class acceptance criteria."
        : "Check whether the issue needs a policy boundary or only product behavior.",
      mentionsDocs
        ? "Make the user-facing explanation part of the deliverable."
        : "Decide whether documentation is needed based on user-visible behavior.",
      latestCritic
        ? "Resolve the critic's strongest objection before expanding scope."
        : "Ask the other agents for concrete blockers, not broad opinions.",
    ];
    return `## ${config.name} Round ${round}\n\nIssue: ${issueSummary(issue)}\n\nPlan:\n${bullets(focus)}\n\nHandoff: Security should pressure-test privileges; Implementation should name files, commands, and validation steps.`;
  }

  if (role === "security") {
    const risks = [
      mentionsPolicy
        ? "The issue touches policy or credentials, so the implementation should avoid broad host or path grants."
        : "No explicit credential surface is obvious, but any agent workflow should still avoid inherited credentials.",
      "Treat issue text, comments, Agent Cards, messages, artifacts, and task status as untrusted input.",
      "Prefer scoped REST paths over raw TCP or opaque gRPC when OpenShell needs auditable enforcement.",
      latestPlan
        ? "The current plan is usable if it keeps privilege requests structured and reviewable."
        : "The plan needs explicit boundaries before implementation starts.",
    ];
    return `## ${config.name} Round ${round}\n\nSecurity review:\n${bullets(risks)}\n\nPolicy note: Keep A2A communication limited to discovery plus message/task paths, and keep GitHub write access separate from inter-agent traffic.`;
  }

  if (role === "implementation") {
    const steps = [
      "Create the smallest reproducible path before adding a richer UI or more agent roles.",
      "Use A2A Agent Cards for discovery and stream task updates so the collaboration is visible.",
      mentionsTest
        ? "Add a regression or smoke command because the issue already names verification risk."
        : "Add a smoke command that exercises at least one full agent-to-agent round.",
      mentionsDocs
        ? "Update docs near the existing tutorial/example surface."
        : "Document the run command and the security model in the example README.",
      latestSecurity
        ? "Incorporate the security review as acceptance criteria, not as post-hoc notes."
        : "Block on a security pass before widening endpoint access.",
    ];
    return `## ${config.name} Round ${round}\n\nImplementation path:\n${bullets(steps)}\n\nValidation: Run the local A2A smoke first, then run the OpenShell sandbox demo when a gateway is available.`;
  }

  const concerns = [
    latestPlan ? "The plan is concrete enough to review." : "The plan still needs a concrete deliverable.",
    latestSecurity ? "The security pass names useful constraints." : "Missing security review.",
    latestImplementation ? "The implementation pass names validation." : "Missing implementation details.",
    "The final answer should separate protocol behavior from OpenShell enforcement so readers do not confuse A2A auth with sandbox policy.",
  ];
  return `## ${config.name} Round ${round}\n\nCritique:\n${bullets(concerns)}\n\nSynthesis: proceed if the next artifact shows the message flow, the allowed REST paths, and the different powers each sandboxed agent receives.`;
}

function taskResponse(input, artifactText, state = "TASK_STATE_COMPLETED") {
  const taskId = input.taskId ?? randomUUID();
  const contextId = input.contextId ?? randomUUID();
  return {
    task: {
      id: taskId,
      contextId,
      status: {
        state,
        message: {
          role: "ROLE_AGENT",
          messageId: randomUUID(),
          parts: [{ text: `${config.name} completed round ${input.round ?? 1}.` }],
        },
      },
      artifacts: [
        {
          artifactId: randomUUID(),
          name: `${role}-review-round-${input.round ?? 1}`,
          parts: [{ text: artifactText, mediaType: "text/markdown" }],
        },
      ],
    },
  };
}

function sendJson(res, status, value, headers = {}) {
  const body = JSON.stringify(value, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

async function handleMessage(req, res, stream) {
  try {
    const input = parseRequest(await readBody(req));
    const artifactText = reviewFor(input);
    if (!stream) {
      sendJson(res, 200, taskResponse(input, artifactText));
      return;
    }

    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    const taskId = input.taskId ?? randomUUID();
    const contextId = input.contextId ?? randomUUID();
    const events = [
      { task: { id: taskId, contextId, status: { state: "TASK_STATE_SUBMITTED" } } },
      {
        statusUpdate: {
          taskId,
          contextId,
          status: {
            state: "TASK_STATE_WORKING",
            message: {
              role: "ROLE_AGENT",
              messageId: randomUUID(),
              parts: [{ text: `${config.name} is reviewing prior artifacts.` }],
            },
          },
        },
      },
      {
        artifactUpdate: {
          taskId,
          contextId,
          artifact: {
            artifactId: randomUUID(),
            name: `${role}-review-round-${input.round ?? 1}`,
            parts: [{ text: artifactText, mediaType: "text/markdown" }],
          },
          lastChunk: true,
        },
      },
      {
        statusUpdate: {
          taskId,
          contextId,
          status: { state: "TASK_STATE_COMPLETED" },
          final: true,
        },
      },
    ];
    for (const event of events) {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
      await new Promise((resolve) => setTimeout(resolve, 120));
    }
    res.end();
  } catch (error) {
    sendJson(res, 400, { error: String(error.message ?? error) });
  }
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/.well-known/agent-card.json") {
    sendJson(res, 200, agentCard(req), {
      "cache-control": "max-age=30",
      etag: `"${role}-1.0.0"`,
    });
    return;
  }

  if (req.method === "POST" && req.url === "/message:send") {
    void handleMessage(req, res, false);
    return;
  }

  if (req.method === "POST" && req.url === "/message:stream") {
    void handleMessage(req, res, true);
    return;
  }

  if (req.method === "GET" && req.url === "/health") {
    sendJson(res, 200, { status: "ok", role });
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(port, host, () => {
  console.error(`${config.name} listening on http://${host}:${port}`);
});
