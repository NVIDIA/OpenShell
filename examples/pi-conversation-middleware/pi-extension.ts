// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const ATTESTATION_HEADER = "x-openshell-agent-attestation";
const HARNESS_VERSION = "prototype-v1";
const REQUEST_TIMEOUT_MS = 5_000;

function bridgeUrl() {
  const value = process.env.OPENSHELL_PI_CONVERSATION_URL;
  if (!value) {
    throw new Error("OPENSHELL_PI_CONVERSATION_URL is not set");
  }
  return value;
}

function modelId(ctx) {
  if (!ctx.model?.id) {
    throw new Error("Pi conversation middleware requires a selected model");
  }
  if (ctx.model.api !== "openai-completions" || ctx.model.reasoning) {
    throw new Error(
      "prototype requires a non-reasoning openai-completions model with a system role",
    );
  }
  return ctx.model.id;
}

function textContent(message) {
  if (typeof message.content === "string") {
    return message.content;
  }
  if (
    Array.isArray(message.content) &&
    message.content.length > 0 &&
    message.content.every((part) => part?.type === "text" && typeof part.text === "string")
  ) {
    return message.content.map((part) => part.text).join("");
  }
  throw new Error(`unsupported ${message.role} message content`);
}

function conversationMessage(message) {
  if (!["system", "developer", "user", "assistant"].includes(message?.role)) {
    throw new Error(`unsupported Pi message role: ${message?.role ?? "missing"}`);
  }
  return { role: message.role, content: textContent(message) };
}

function replacePiMessage(original, replacement) {
  if (original.role !== replacement.role) {
    throw new Error("middleware changed a Pi message role");
  }
  if (original.role === "user" || typeof original.content === "string") {
    return { ...original, content: replacement.content };
  }
  return {
    ...original,
    content: [{ type: "text", text: replacement.content }],
  };
}

function providerMessages(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("unsupported OpenAI Chat Completions payload");
  }
  if (typeof payload.model !== "string" || !Array.isArray(payload.messages)) {
    throw new Error("payload must contain model and messages");
  }
  return payload.messages.map((message) => {
    if (
      !message ||
      typeof message !== "object" ||
      Array.isArray(message) ||
      typeof message.content !== "string" ||
      Object.keys(message).some((key) => key !== "role" && key !== "content")
    ) {
      throw new Error("prototype supports only role/content provider messages");
    }
    return conversationMessage(message);
  });
}

async function inspect(hook, ctx, turnId, model, messages) {
  const response = await fetch(bridgeUrl(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      hook,
      harness_version: HARNESS_VERSION,
      session_id: ctx.sessionManager.getSessionId(),
      turn_id: String(turnId),
      model,
      messages,
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Pi conversation middleware denied ${hook} (${response.status})`);
  }
  const result = await response.json();
  if (
    result?.model !== model ||
    !Array.isArray(result.messages) ||
    result.messages.length !== messages.length ||
    typeof result.attestation !== "string" ||
    result.attestation.length === 0
  ) {
    throw new Error(`invalid Pi conversation middleware response for ${hook}`);
  }
  return result;
}

export default function piConversationMiddleware(pi) {
  let turnId = 0;
  let pendingApproval;

  // This request persists the sanitized user text in Pi's session record.
  pi.on("input", async (event, ctx) => {
    if (event.images?.length) {
      throw new Error("Pi conversation prototype does not support image input");
    }
    const result = await inspect("input", ctx, turnId, modelId(ctx), [
      { role: "user", content: event.text },
    ]);
    return { action: "transform", text: result.messages[0].content };
  });

  // Pi rebuilds the system prompt each turn, so replace that effective prompt
  // before every agent run.
  pi.on("before_agent_start", async (event, ctx) => {
    const result = await inspect("before_agent_start", ctx, turnId, modelId(ctx), [
      { role: "system", content: event.systemPrompt },
    ]);
    return { systemPrompt: result.messages[0].content };
  });

  // Persist finalized plain-text user and assistant messages in their sanitized
  // form. The user pass is idempotent with the earlier input transformation and
  // also covers text introduced by prompt expansion.
  pi.on("message_end", async (event, ctx) => {
    if (event.message.role !== "user" && event.message.role !== "assistant") return;
    const message = conversationMessage(event.message);
    const result = await inspect("message_end", ctx, turnId, modelId(ctx), [message]);
    return { message: replacePiMessage(event.message, result.messages[0]) };
  });

  pi.on("turn_start", (event) => {
    turnId = event.turnIndex;
    pendingApproval = undefined;
  });

  // Inspect and apply the complete semantic conversation Pi will use for this
  // model call. This transformation is intentionally limited to text-only
  // user/assistant messages.
  pi.on("context", async (event, ctx) => {
    pendingApproval = undefined;
    const system = { role: "system", content: ctx.getSystemPrompt() };
    const messages = event.messages.map(conversationMessage);
    const result = await inspect("context", ctx, turnId, modelId(ctx), [system, ...messages]);
    pendingApproval = {
      model: result.model,
      messages: result.messages,
      attestation: result.attestation,
    };
    return {
      messages: event.messages.map((message, index) =>
        replacePiMessage(message, result.messages[index + 1]),
      ),
    };
  });

  // Pi assembles headers before it invokes this payload hook. Confirm that its
  // provider serialization exactly preserves the conversation signed by the
  // preceding context hook; serialization drift fails before dispatch.
  pi.on("before_provider_request", async (event, ctx) => {
    const messages = providerMessages(event.payload);
    if (
      !pendingApproval ||
      event.payload.model !== pendingApproval.model ||
      JSON.stringify(messages) !== JSON.stringify(pendingApproval.messages)
    ) {
      throw new Error("provider message serialization differs from signed Pi context");
    }
  });

  pi.on("before_provider_headers", (event) => {
    if (!pendingApproval?.attestation) {
      throw new Error("missing Pi conversation attestation");
    }
    event.headers[ATTESTATION_HEADER] = pendingApproval.attestation;
  });
}
