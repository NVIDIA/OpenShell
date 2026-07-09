# Brainstorm Overview

Last updated: 2026-07-09

## Sessions

| # | Date | Topic | Status | Spec | Issue |
|---|------|-------|--------|------|-------|
| 01 | 2026-07-09 | warm-pool-feasibility | active | - | - |
| 02 | 2026-07-09 | cluster-setup | active | - | - |
| 03 | 2026-07-09 | warm-pool-measurements | active | - | - |
| 04 | 2026-07-09 | results-and-recommendations | active | - | - |

## Structure

01 is the parent document defining the overall feasibility study. 02-04 are execution phases:

- **02** depends on: nothing (first step)
- **03** depends on: 02 (cluster must be running)
- **04** depends on: 03 (measurements must be complete)

## Open Threads

- Does the Red Hat Agent Sandbox operator tech preview include extension CRDs? (from #01, #02)
- Does env var injection at claim time trigger cold start? (from #01, #03)
- Is KEP-753 (native sidecars) available on the target OpenShift version? (from #01, #02)
- How does pool exhaustion behave (cold fallback vs. Pending)? (from #03)
- Should findings be posted to upstream agent-sandbox repo? (from #04)

## Parked Ideas

None.
