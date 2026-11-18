# Agents

Agents live in `.agents/agents/<name>/`. Names are descriptive nouns specifying the job, optionally qualified by adjectives: `labeler`, `reviewer`, or `security-reviewer`.

## Layout

```text
.agents/
|-- skills/
|   `-- agent-behavior -> ../agents/agent-name/skills/agent-behavior
`-- agents/
    |-- README.md
    `-- agent-name/
        |-- README.md
        |-- run.py
        |-- bin/
        |   |-- helper.py
        |   `-- tool.py
        |-- prompts/
        |   `-- task.md
        |-- skills/
        |   `-- agent-behavior/
        |       `-- SKILL.md
        |-- references/
        |   `-- result-contract.md
        |-- tests/
        |   |-- run_test.py
        |   `-- tool_test.py
        |-- deploy/
        |   |-- Dockerfile
        |   `-- policy.yaml
        `-- evals/
            `-- cases.json
```

Only `README.md` and a `run.*` entry point are required. Add other directories when needed; do not create empty scaffolding.

- `run.*` is the agent-root entry point for humans, workflows, and interactive callers. Use the implementation language's extension, such as `run.py` or `run.sh`. It can delegate to a shared launcher.
- `bin/` holds supporting scripts, tools, and implementation modules.
- `prompts/` holds model or harness prompts.
- `skills/` holds canonical agent-owned skills. A symlink in [`.agents/skills/`](../skills) can expose the same skill for discovery. Reference canonical instructions and contracts rather than copying them.
- `references/` holds contracts and supporting guidance.
- `tests/` holds explicitly selected deterministic and integration tests.
- `evals/` holds model-quality cases and scoring code.
- `deploy/` holds execution-specific packaging assets, such as a Dockerfile and sandbox policy. Manifests and dependency files live at the agent root where their tooling expects them. Never commit secrets.
- `README.md` covers setup, invocation, permissions, outputs, and recovery.

## Deterministic orchestration

The `labeler` agent checks authorization, acceptance, lifecycle, and material changes before calling a model-based classifier. The classifier receives prepared evidence and no tools; deterministic code validates and applies the result.

```text
labeler/
|-- README.md
|-- run.py
|-- bin/
|   |-- acceptance.py
|   |-- classifier.py
|   |-- evidence.py
|   `-- policy.py
|-- prompts/
|   `-- classify.md
|-- skills/
|   `-- label-issue/
|       |-- SKILL.md
|       `-- references/
|           `-- result-contract.md
`-- tests/
    |-- run_test.py
    |-- acceptance_test.py
    |-- classifier_test.py
    |-- evidence_test.py
    `-- policy_test.py
```

Execution: `run.py` -> deterministic gates -> prepared evidence -> model-based classifier -> validation and application. Deterministic skips create no model session. Acceptance recognizes established policy and human disposition; the model does not accept work.

## Harness-driven execution

A reviewer launches a model/harness with a prompt and selected tools. Its entry point enforces invocation scope and permissions; sandbox policy, guarded commands, or SDK tool handlers enforce tool access.

```text
reviewer/
|-- README.md
|-- run.sh
|-- agent.yaml
|-- bin/
|   |-- read-item
|   `-- submit-findings
|-- prompts/
|   `-- review.md
|-- skills/
|   `-- review-item/
|       `-- SKILL.md
|-- references/
|   `-- result-contract.md
|-- deploy/
|   |-- Dockerfile
|   `-- policy.yaml
`-- tests/
    |-- run_test.sh
    `-- submit_findings_test.sh
```

Execution: `run.sh` -> scope checks -> harness with prompt and tools -> validated result. Tools can be registered SDK functions or guarded sandbox commands. Supervision and repeated cycles belong outside the model.

These examples illustrate execution styles, not an inventory of agents.
