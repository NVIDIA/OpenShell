# Deep Review Findings

**Date:** 2026-07-09
**Branch:** 6111-warm-pool-feasibility
**Rounds:** 2
**Gate Outcome:** PASS
**Invocation:** manual

## Summary

| Severity | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 1 | 1 | 0 |
| Important | 7 | 5 | 2 |
| Minor | 8 | - | 8 |
| Notable | 6 | - | 6 |
| **Total** | **22** | **6** | **16** |

**Agents completed:** 5/5 (+ 0 external tools)
**Agents failed:** CodeRabbit (timed out after 5+ minutes)

## Findings

### FINDING-1
- **Severity:** Critical
- **Confidence:** 95
- **File:** experiments/lib/common.sh:63-91 (defined), experiments/measure-cold-start.sh (not called)
- **Category:** test-quality
- **Source:** test-quality-agent (also reported by: architecture-agent)
- **Round found:** 1
- **Resolution:** fixed (round 1)

**What is wrong:**
`extract_phase_deltas()` was defined in lib/common.sh but never called by any measurement script. The CSV header declares per-phase columns but all scripts passed only 8 positional arguments to `write_csv_row`, leaving phase columns empty. FR-004 requires per-phase timestamps.

**Why this matters:**
The per-phase breakdown is the entire point of User Story 1. Without it, cold-start measurements produce only a single end-to-end delta_ms, making it impossible to identify whether scheduling, image pulling, or supervisor startup is the bottleneck.

**How it was resolved:**
Added calls to `extract_phase_deltas()` in measure-cold-start.sh for both prepulled/noprepull and vanilla config paths. Results are split via `IFS=',' read` and passed as positional arguments 9-13 to write_csv_row.

### FINDING-2
- **Severity:** Important
- **Confidence:** 95
- **File:** experiments/lib/common.sh:63-91
- **Category:** correctness
- **Source:** correctness-agent (also reported by: architecture-agent)
- **Round found:** 1
- **Resolution:** fixed (round 1)

**What is wrong:**
`extract_phase_deltas()` jq timestamp conversion used incompatible reference frames. The `ts_to_epoch` function produced an approximate day-count value (`year*365*86400 + month*30*86400`), while `$cs` was a real Unix epoch. The subtraction produced nonsensical values (off by ~62 billion seconds for 2026 dates). It also ignored the time-of-day component entirely.

**Why this matters:**
After FINDING-1 was fixed (wiring up the function), this would have written garbage values into the per-phase CSV columns, corrupting the feasibility study data.

**How it was resolved:**
Rewrote `extract_phase_deltas()` to use shell-based ISO-to-epoch conversion via `gdate -d` (macOS) or `date -d` (Linux), producing correct epoch seconds for proper delta computation.

### FINDING-3
- **Severity:** Important
- **Confidence:** 95
- **File:** experiments/lib/common.sh:141-143
- **Category:** correctness
- **Source:** correctness-agent
- **Round found:** 1
- **Resolution:** fixed (round 1)

**What is wrong:**
`compute_stats` awk uses `vals[NR-1]` for array indexing, but `NR-1` creates non-contiguous indices when rows are skipped (non-ok status or empty delta). The insertion sort iterates `1..n` contiguously, reading uninitialized slots (treated as 0 by awk) while actual values at higher indices are orphaned. This corrupts p50/p90 percentile values.

**Why this matters:**
When any measurement run produces a timeout or failed row, the percentile statistics in the summary output are wrong. Unset array slots read as 0, pulling percentiles down.

**How it was resolved:**
Changed `vals[NR-1] = v; n++` to `n++; vals[n] = v` so the array is contiguously indexed by the sample counter, not the line number.

### FINDING-4
- **Severity:** Important
- **Confidence:** 92
- **File:** experiments/measure-warm-pool.sh:374-384
- **Category:** production-readiness
- **Source:** production-agent (also reported by: correctness-agent, architecture-agent)
- **Round found:** 1
- **Resolution:** fixed (round 1)

**What is wrong:**
The aggressive config's trap on line 374 replaced the common.sh `_cleanup_on_exit` EXIT trap. Line 384 (`trap - EXIT INT TERM`) permanently cleared ALL traps. When running `--config all`, the burst config ran with zero cleanup traps, meaning Kubernetes resources leaked on interrupt.

**Why this matters:**
Resources registered via `register_cleanup` would not be cleaned up if the script crashed or was interrupted after the aggressive config completed.

**How it was resolved:**
Changed the trap to chain both handlers: `trap 'patch_readiness_probe $period; _cleanup_on_exit' EXIT`. After aggressive run, restore only the original common.sh trap instead of clearing all traps.

### FINDING-5
- **Severity:** Important
- **Confidence:** 90
- **File:** experiments/measure-combined.sh:165-184, experiments/measure-env-injection.sh:102-125
- **Category:** architecture
- **Source:** architecture-agent (also reported by: test-quality-agent)
- **Round found:** 1
- **Resolution:** fixed (round 1)

**What is wrong:**
Two inconsistent `detect_adoption()` implementations: combined.sh checked only Scheduled events, env-injection.sh checked Scheduled AND Pulled/Pulling events. The combined.sh version would misclassify cold-fallback pods as "warm-adopted" when images were cached.

**Why this matters:**
The combined experiment is designed to produce the "best case" measurement. Incorrect adoption detection means the RFC results could contain falsely inflated warm pool performance data.

**How it was resolved:**
Extracted the more thorough version (checking Scheduled + Pulled/Pulling) to lib/common.sh as a shared function. Removed both local implementations. Updated all call sites to pass namespace.

### FINDING-6
- **Severity:** Important
- **Confidence:** 90
- **File:** experiments/measure-env-injection.sh, experiments/measure-combined.sh
- **Category:** production-readiness
- **Source:** production-agent
- **Round found:** 1
- **Resolution:** remaining (low risk)

**What is wrong:**
Both scripts patch SandboxTemplate envVarsInjectionPolicy and readiness probes but never restore original values on interrupt. If interrupted mid-run, the template remains modified.

### FINDING-7
- **Severity:** Important
- **Confidence:** 85
- **File:** experiments/measure-warm-pool.sh:302-339
- **Category:** test-quality
- **Source:** test-quality-agent
- **Round found:** 1
- **Resolution:** remaining (measurement artifact, documented)

**What is wrong:**
Burst claim latencies are measured sequentially despite being submitted in parallel. All 5 burst claims share a single `create_ts`, but readiness checks run sequentially. Claim j's `ready_ts` is captured only after claims 1 through j-1 have been waited on, inflating later claims' measured latency.

## Minor Findings

### FINDING-8 (Minor, correctness)
- **File:** experiments/lib/common.sh:12
- **Source:** correctness-agent (also: architecture-agent)
- **Description:** `deregister_cleanup()` uses bash pattern substitution `${array[@]/$1}` which does substring matching, not exact match. Currently unused by any script.

### FINDING-9 (Minor, architecture)
- **File:** experiments/lib/wait-ready.sh:7-10
- **Source:** architecture-agent
- **Description:** `wait_for_ready()` is defined but never called. Dead code.

### FINDING-10 (Minor, architecture)
- **File:** experiments/measure-combined.sh, experiments/measure-env-injection.sh
- **Source:** architecture-agent
- **Description:** `wait_claim_ready()`, `cleanup_claim()`, `get_claim_pod()` remain duplicated across two scripts. Should be extracted to lib/.

### FINDING-11 (Minor, architecture)
- **File:** experiments/measure-combined.sh, experiments/measure-env-injection.sh
- **Source:** architecture-agent
- **Description:** Both scripts bypass `write_csv_header()`/`write_csv_row()`, writing CSV rows directly with `echo` and custom headers (adding adoption/behavior columns).

### FINDING-12 (Minor, security)
- **File:** experiments/lib/common.sh:17
- **Source:** security-agent
- **Description:** `kubectl delete $res` in cleanup handler uses unquoted variable expansion. Low risk since resource names are controlled.

### FINDING-13 (Minor, security)
- **File:** experiments/manifests/sandbox-claim.yaml:14-15
- **Source:** security-agent
- **Description:** Commented-out example includes predictable synthetic token `tok-xxx`. Clearly test data, no real risk.

### FINDING-14 (Minor, production-readiness)
- **File:** experiments/manifests/sidecar-readiness.yaml:6-19
- **Source:** production-agent
- **Description:** Readiness sidecar init container has no resource requests or limits.

### FINDING-15 (Minor, test-quality)
- **File:** experiments/measure-warm-pool.sh:370-378
- **Source:** test-quality-agent
- **Description:** Aggressive probe config does not verify that warm pool pods actually have updated probe configuration before measuring. If the pool controller doesn't recycle pods on template changes, measurements may use old probes.

## Notable Observations

### NOTABLE-1
- **File:** experiments/sidecar/main.go:35-46
- **Category:** architecture
- **Source:** architecture-agent
- **Description:** Sidecar readiness binary exits polling loop after signal file detection, stays "ready" permanently even if file is deleted
- **Rationale:** Adequate for the experiment but worth noting if pattern is promoted to production

### NOTABLE-2
- **File:** experiments/measure-warm-pool.sh:303-305
- **Category:** correctness
- **Source:** correctness-agent
- **Description:** Background `kubectl apply` failures in burst mode are silently swallowed by `wait` with no operands
- **Rationale:** Transient API server errors during burst would be misdiagnosed as bind timeouts

### NOTABLE-3
- **File:** experiments/measure-combined.sh:199-296
- **Category:** test-quality
- **Source:** test-quality-agent
- **Description:** Combined script does not wait for pool replenishment between runs, unlike measure-warm-pool.sh
- **Rationale:** Later runs may measure cold-start fallback latency instead of warm pool claims

### NOTABLE-4
- **File:** rfc/NNNN-warm-pool-feasibility/README.md
- **Category:** architecture
- **Source:** architecture-agent
- **Description:** RFC document has TBD placeholders throughout all results and recommendation sections
- **Rationale:** Expected at this stage (pre-experiment), document structure is complete and ready to receive data

### NOTABLE-5
- **File:** experiments/manifests/sidecar-readiness.yaml, readiness-gate-pod.yaml
- **Category:** security
- **Source:** security-agent
- **Description:** Pod manifests lack securityContext (no runAsNonRoot, no dropped capabilities)
- **Rationale:** Acceptable for ephemeral experiment pods

### NOTABLE-6
- **File:** experiments/measure-cold-start.sh:85-138
- **Category:** test-quality
- **Source:** test-quality-agent
- **Description:** The `noprepull` config uses the same code path as `prepulled` with no validation that images are actually uncached. If the prepull DaemonSet is still running, results will be indistinguishable.
- **Rationale:** Worth adding a pre-flight warning but not blocking

## Test Suite Results

No test command detected; post-fix test step was skipped.
