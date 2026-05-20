#!/usr/bin/env node

// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";

function parseArgs(argv) {
  const out = { agents: [], rounds: 2 };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--agent") out.agents.push(argv[++i]);
    else if (arg === "--issue-url") out.issueUrl = argv[++i];
    else if (arg === "--issue-file") out.issueFile = argv[++i];
    else if (arg === "--rounds") out.rounds = Number(argv[++i]);
    else if (arg === "--output") out.output = argv[++i];
    else if (arg === "--repo") out.repo = argv[++i];
    else throw new Error(`unknown argument: ${arg}`);
  }
  return out;
}

function parseIssueUrl(url) {
  const match = /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/issues\/([0-9]+)(?:[/?#].*)?$/.exec(url);
  if (!match) {
    throw new Error(`issue URL must look like https://github.com/OWNER/REPO/issues/123, got ${url}`);
  }
  return { owner: match[1], repo: match[2], number: match[3] };
}

async function githubJson(url) {
  const headers = {
    accept: "application/vnd.github+json",
    "user-agent": "openshell-a2a-design-review-demo",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  } else if (process.env.GH_TOKEN) {
    headers.authorization = `Bearer ${process.env.GH_TOKEN}`;
  }
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`GitHub request failed ${response.status}: ${await response.text()}`);
  }
  return response.json();
}

async function loadIssue(args) {
  if (args.issueFile) {
    return JSON.parse(await fs.readFile(args.issueFile, "utf8"));
  }

  if (args.issueUrl) {
    const { owner, repo, number } = parseIssueUrl(args.issueUrl);
    const issue = await githubJson(`https://api.github.com/repos/${owner}/${repo}/issues/${number}`);
    return normalizeIssue(issue);
  }

  const repo = args.repo ?? "NVIDIA/OpenShell";
  const issues = await githubJson(`https://api.github.com/repos/${repo}/issues?state=open&per_page=1`);
  const issue = issues.find((item) => !item.pull_request);
  if (!issue) throw new Error(`no open issues found for ${repo}`);
  return normalizeIssue(issue);
}

function normalizeIssue(issue) {
  return {
    number: issue.number,
    title: issue.title,
    body: issue.body ?? "",
    url: issue.html_url ?? issue.url,
    labels: (issue.labels ?? []).map((label) => (typeof label === "string" ? label : label.name)),
  };
}

function parseAgentSpec(spec) {
  const [role, ...rest] = spec.split("=");
  const url = rest.join("=");
  if (!role || !url) throw new Error(`--agent must be role=url, got ${spec}`);
  return { role, url: url.replace(/\/$/, "") };
}

async function discover(agent) {
  const response = await fetch(`${agent.url}/.well-known/agent-card.json`);
  if (!response.ok) {
    throw new Error(`failed to fetch Agent Card for ${agent.role}: ${response.status}`);
  }
  return { ...agent, card: await response.json() };
}

function messagePayload(issue, transcript, role, round) {
  return {
    message: {
      role: "ROLE_USER",
      messageId: randomUUID(),
      parts: [
        {
          data: {
            issue,
            transcript,
            role,
            round,
            prompt: `Round ${round}: review the issue from the ${role} perspective and build on prior artifacts.`,
          },
          mediaType: "application/json",
        },
      ],
    },
  };
}

function artifactTextFromEvent(event) {
  const artifact = event.artifactUpdate?.artifact ?? event.task?.artifacts?.[0];
  const part = artifact?.parts?.find((candidate) => typeof candidate.text === "string");
  return part?.text ?? "";
}

async function callAgent(agent, issue, transcript, round) {
  const response = await fetch(`${agent.url}/message:stream`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "text/event-stream",
      "a2a-version": "1.0",
    },
    body: JSON.stringify(messagePayload(issue, transcript, agent.role, round)),
  });
  if (!response.ok) {
    throw new Error(`${agent.role} returned ${response.status}: ${await response.text()}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let artifact = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      const line = chunk.split("\n").find((candidate) => candidate.startsWith("data: "));
      if (!line) continue;
      const event = JSON.parse(line.slice(6));
      const status = event.statusUpdate?.status?.state ?? event.task?.status?.state;
      if (status) console.log(`  ${agent.role}: ${status}`);
      const text = artifactTextFromEvent(event);
      if (text) artifact = text;
    }
  }
  if (!artifact) {
    throw new Error(`${agent.role} did not return an artifact`);
  }
  return artifact;
}

function finalReport(issue, agents, transcript) {
  const agentRows = agents
    .map((agent) => `- ${agent.role}: ${agent.card.name} (${agent.card.skills?.[0]?.id ?? "unknown skill"})`)
    .join("\n");
  const artifacts = transcript
    .map((entry) => `\n### Round ${entry.round} - ${entry.role}\n\n${entry.artifact}`)
    .join("\n");
  return `# A2A Design Review\n\nIssue: [#${issue.number} ${issue.title}](${issue.url})\n\n## Agents\n\n${agentRows}\n\n## Transcript\n${artifacts}\n`;
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.agents.length === 0) {
    throw new Error("provide at least one --agent role=url");
  }

  const issue = await loadIssue(args);
  const agents = await Promise.all(args.agents.map((spec) => discover(parseAgentSpec(spec))));
  const transcript = [];

  console.log(`A2A design review for #${issue.number}: ${issue.title}`);
  for (const agent of agents) {
    console.log(`  discovered ${agent.role}: ${agent.card.name}`);
  }

  for (let round = 1; round <= args.rounds; round += 1) {
    console.log(`\nRound ${round}`);
    for (const agent of agents) {
      const artifact = await callAgent(agent, issue, transcript, round);
      transcript.push({ round, role: agent.role, artifact });
      console.log(`  ${agent.role}: artifact accepted (${artifact.length} chars)`);
    }
  }

  const report = finalReport(issue, agents, transcript);
  if (args.output) {
    await fs.writeFile(args.output, report);
    console.log(`\nWrote ${args.output}`);
  } else {
    console.log(`\n${report}`);
  }
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
