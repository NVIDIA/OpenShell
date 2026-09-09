# PR #3074 results from 2026-09-09

These are the unchanged final observations from the live run on commit `555ff32896a225020b670902a601707624bbadc5`. See [report.md](report.md) for the findings and timing tables. Download [report.html](report.html) to use its expandable case traces and filters offline.

- `matrix-results.json.gz`: all 86 final case definitions, assertions, observed responses, and gRPC middleware events, including the single Content-Length failure.
- `benchmark-raw.json.gz` and `tunnel-raw.json.gz`: lossless curl observations, including warm-ups and connection counts.
- `streaming-latency.json.gz`: delayed-upstream measurements.
- `functional-summary.json`, `benchmark-summary.json`, and `tunnel-summary.json`: derived checks and statistics.
- `runtime-tests.log` and `relay-tests.log`: the 65 passing selected regression tests.

The raw JSON files use deterministic gzip compression. To reconstruct the inputs for `analyze.py`, decompress them into the suite's ignored `output/` directory:

```shell
mkdir -p e2e/response-middleware-live/output
gzip -dc e2e/response-middleware-live/results/2026-09-09/matrix-results.json.gz > e2e/response-middleware-live/output/matrix-results.json
gzip -dc e2e/response-middleware-live/results/2026-09-09/benchmark-raw.json.gz > e2e/response-middleware-live/output/benchmark-raw.json
gzip -dc e2e/response-middleware-live/results/2026-09-09/tunnel-raw.json.gz > e2e/response-middleware-live/output/tunnel-raw.json
gzip -dc e2e/response-middleware-live/results/2026-09-09/streaming-latency.json.gz > e2e/response-middleware-live/output/streaming-latency.json
```

The historical report mentions the original ignored working directory and setup/debug logs. Those transient logs and credentials are not part of this snapshot. The tracked scripts now live two directories below the repository root and write new results separately, so rerunning them cannot overwrite this snapshot.
