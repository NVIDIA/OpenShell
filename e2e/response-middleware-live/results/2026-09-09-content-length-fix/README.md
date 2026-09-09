# Content-Length fix validation

The response relay now exposes upstream `Content-Length` in middleware preflight while keeping it immutable. Serialization discards the metadata copy and emits the relay's final framing, preventing duplicate or stale lengths after transformation. Connection-nominated fields remain hidden.

This run used the preserved suite from commit `36402b7766b882e74f2508a357293269f3f6a1db` with the runtime fix in this commit. The rebuilt supervisor image was `sha256:399a14757007a3a3ebc09d7b8310ee019694c84453cba58837b7a45837fe27d6`. The gateway and fixtures ran locally on Linux ARM64, using a real Docker sandbox and four external gRPC middleware services.

- **86/86 live scenarios passed**, including `preflight-content-length-contract`, previously the only failure. Its preflight contains `content-length: 19`; the client receives exactly one `Content-Length: 19` and the unchanged 19-byte body.
- **14/14 chain-event checks passed**, covering stage order, sequence numbers, final body units, and trailers for same-mode and mixed-mode chains.
- **34 response relay tests and 121 middleware tests passed.** New regressions cover metadata visibility, immutable headers, Connection filtering, and framing with preserved lengths, transformed lengths, chunking, and no body.
- The visibility regression failed before the implementation change; see `regression-before.log`.
- `mise run pre-commit` passed.
- `mise run test` was not green: the server suite reported 1,479 passing tests, eight ignored tests, and an OIDC/JWKS assertion failure (`jwk_alg_mismatch_skipped`, Internal versus Unauthenticated). That test passed on an isolated rerun. Seven release-range fixture setup failures caused by the host's Git tag-signing setting passed when rerun with command-scoped `tag.gpgsign=false`. No unrelated code or global Git configuration was changed.

`matrix-results.json.gz` contains all case definitions, checks, client responses, and middleware events, with deterministic gzip compression. `functional-summary.json` contains the derived pass counts and chain checks. The `.log` files preserve the focused test output and matrix progress.

The functional rerun used `MIDDLEWARE_LIVE_OUTPUT=/tmp/pr3074-content-length-fix` with the suite's `services.py`, `start-gateway.sh`, `run.py create`, `run.py matrix`, and `analyze.py` commands. See the suite README for setup. The sandbox and fixture services were stopped after validation.

Performance benchmarks were not rerun for this fix. The original measurements and original 85/86 result remain unchanged in the adjacent `2026-09-09` snapshot.
