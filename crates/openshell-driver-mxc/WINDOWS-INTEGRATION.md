# Windows integration checkpoint

Reviewed Windows branch through
`d89e4359b810d3d7205bb7d4a706f3c773a59e1f` (PR #4252).
This is a selective port, not a branch merge or a claim of complete demo parity.

- #4252 (`d89e4359b`): MXC 1.0.0 schema, directional networking, and UI contract
  already ported in `ce2ca474a`.
- #4199 (`f6ecca206`): authorize the socket-owning curl executable in the
  inference policy template and real HTTPS test, rather than its cmd launcher.
- #4192 (`ed35eb9f3`): disposable CLI state, cleared inherited gateway
  overrides, exact environment restoration, and strict fresh gateway
  registration in the E2E and OCSF runners.
- Restore the WebSocket and OpenClaw policy fixtures with their original
  grants, updating comments to the host-supervisor/Windows-boundary architecture.

Keep the always-present `openshell-windows-sandbox`, authenticated Sandbox
Protocol, and host isolation-backend supervisor. Do not restore the old relay
executable, driver-owned CONNECT proxy, or legacy demo/task wrappers requiring
them. Provider-backed inference, live WebSocket, OpenClaw, and OCSF demo coverage
are not implied by policy parsing or by the six core E2E scenarios. Network-fence
evidence remains the documented compatibility TODO, not a verified guarantee.
