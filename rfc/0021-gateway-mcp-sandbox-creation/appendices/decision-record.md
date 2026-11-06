# Appendix: Decision Record

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The review of the earlier draft on this pull request and in the design
document led to the following choices. "Proposed by" names where the idea came
from; all were accepted by the author.

| Topic | Decision | Proposed by |
|---|---|---|
| Depth | Only roots create children; one level | drew |
| Sandbox kinds | No agent and tool kinds | review thread |
| Parent link | Read-only `parent` field on the sandbox | drew |
| RPCs | Reuse existing sandbox RPCs; no child-sandbox API | drew, Piotr |
| MCP path | Tools call RPCs through the normal router, so interceptors run | author |
| Callers | Agents in root sandboxes and users on the host (`openshell mcp serve`) | author |
| Enabling | Gateway setting, off by default, also gating `/mcp`; no grants | Piotr |
| Limit | `max_concurrent_children` per parent, default 10; a slot frees when a delete finishes | author, team call |
| Policy | Child uses the parent's policy, copied and kept in sync | author |
| Child policy changes | Refused, including proposals; narrowing planned for v1 | drew (narrowing) |
| Image and resources | Users: all create options, a deliberate departure from drew's "inherited from the parent"; agents: copy the parent or use a template approved for agents | Piotr (copy), author (templates) |
| Providers | Subset of the parent's, for users and agents; removals reach children | author |
| Results | Idle children, `exec`, background jobs and `wait` | Piotr |
| Retries | Over MCP, the same name returns the existing sandbox with `already_existed` | Piotr |
| User check | The root's user must still be a workspace member | Piotr |
| Deleting a parent | Refused while it has children; `--with-children` is future work | author |
| Protocol | 2025 MCP revisions, no sessions, calls under the door's 60 s | Piotr |
| Credential | Existing sandbox session token, attached by the supervisor | Piotr |
| Host access | `openshell mcp serve` bridge using the CLI login; `/mcp` refuses browser requests | author |
