# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build portable evidence reports and exportable charts from recorded results."""

import base64
import html
import json
import statistics

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from run import OUT

SHA = "555ff32896a225020b670902a601707624bbadc5"
REPO = "https://github.com/NVIDIA/OpenShell"
LABELS = {
    "baseline": "No middleware",
    "headers-1": "1 header-only",
    "whole-1": "1 whole-body",
    "stream-1": "1 streaming",
    "headers-2": "2 header-only",
    "whole-2": "2 whole-body",
    "stream-2": "2 streaming",
    "stream-whole": "Streaming → whole-body",
    "headers-whole-stream": "Header-only → whole-body → streaming",
}
ORDER = list(LABELS)
forward = [
    r
    for r in json.loads((OUT / "benchmark-summary.json").read_text())
    if not r["fresh"]
]
tunnel = json.loads((OUT / "tunnel-summary.json").read_text())
results = json.loads((OUT / "matrix-results.json").read_text())
functional = json.loads((OUT / "functional-summary.json").read_text())
slow = json.loads((OUT / "streaming-latency.json").read_text())
lookup = {
    (path, r["name"], r["size"]): r
    for path, rows in [("HTTP proxy", forward), ("CONNECT reuse", tunnel)]
    for r in rows
}

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.spines.left": False,
        "axes.edgecolor": "#dddddd",
    }
)
fig, axes = plt.subplots(1, 2, figsize=(14, 6.8), sharey=True)
names = ORDER[1:]
y = np.arange(len(names))
for ax, size, title in zip(
    axes, [19, 262144], ["19-byte response", "256 KiB response"], strict=False
):
    for offset, path, color in [
        (-0.18, "HTTP proxy", "#76b900"),
        (0.18, "CONNECT reuse", "#004b31"),
    ]:
        values = [lookup[(path, n, size)]["overhead_ms"] for n in names]
        bars = ax.barh(y + offset, values, height=0.32, color=color, label=path)
        ax.bar_label(bars, fmt="%.2f", padding=4, fontsize=8)
    ax.set_title(title, loc="left", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Added median latency vs no middleware, ms")
    ax.set_xlim(0, 10.2)
    ax.set_axisbelow(True)
    ax.grid(axis="x", color="#eeeeee")
axes[0].set_yticks(y, [LABELS[n].replace(" → ", " / ") for n in names])
axes[0].invert_yaxis()
axes[0].legend(loc="lower right", frameon=False)
fig.suptitle(
    "OpenShell PR #3074: external response middleware overhead",
    x=0.02,
    ha="left",
    fontsize=17,
    fontweight="bold",
)
fig.text(
    0.02,
    0.025,
    "105 measured requests per bar · 3 randomized rounds · local Python gRPC services · optimized ARM64 supervisor\nMedians describe this fixture and machine. They include gRPC and service work; they are not production latency bounds.",
    fontsize=9,
    color="#555555",
)
fig.tight_layout(rect=[0, 0.095, 1, 0.93])
fig.savefig(OUT / "latency.png", dpi=160, bbox_inches="tight")
fig.savefig(OUT / "latency.svg", bbox_inches="tight")
plt.close(fig)


def md_table(path):
    lines = [
        "| Middleware chain | 19 B median / p95 | Added | 64 KiB median / p95 | Added | 256 KiB median / p95 | Added |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ORDER:
        cells = [LABELS[name]]
        for size in [19, 65536, 262144]:
            r = lookup[(path, name, size)]
            cells += [
                f"{r['median_ms']:.2f} / {r['p95_ms']:.2f}",
                f"+{r['overhead_ms']:.2f}",
            ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


method = """Tested commit `555ff32896a225020b670902a601707624bbadc5` on 2026-09-09. Built a dedicated gateway and CLI from the PR, and built the sandbox supervisor with the repository's Docker task in the optimized release profile. No tracked source files changed.

The test ran on Linux 6.17, ARM64, 20 logical CPUs with Cortex-X925/Cortex-A725 cores. A dedicated Docker sandbox sent requests through the actual OpenShell policy and response relay. The local upstream used HTTP/1.1 and TCP_NODELAY. Four Python gRPC servers ran in one fixture process on separate ports, three with 256 KiB caps and one with a 32-byte cap. Policies selected independent modes and actions per stage. gRPC used plaintext local transport and a 150 ms RPC timeout. The fixture base image set the existing policy polling interval to one second; each policy update waited for the sandbox's loaded acknowledgement.

For each of nine middleware configurations and three payload sizes, each transport path ran three rounds in a reproducible randomized order. Each batch sent 40 sequential curl requests from a single process inside the sandbox; the first five were discarded. Each reported cell therefore contains 105 observations. Time is curl `time_total`, which excludes CLI launch, SSH setup, policy updates, and the Python wrapper. It includes response writes to the same sandbox temporary file and external gRPC/service processing. Fixture event logging was disabled during timing. Every measured response was checked for HTTP 200 and the expected byte count.

The ordinary HTTP forward-proxy path closes each connection. The measured samples recorded 105 new connections per cell. CONNECT tunnels reused the existing connection, recording zero new connections after warm-up. Neither series uses TLS. The machine was shared and CPU frequency/load was not controlled. These are serial latency measurements, not a concurrency, CPU, memory, production-network, or saturation-throughput benchmark. Sub-millisecond differences, especially on the ordinary HTTP path, are sensitive to background noise. Median and nearest-rank p95 are reported; p95 is an observation, not a guarantee."""

finding = f"""One protocol mismatch reproduced. The upstream sends `Content-Length: 19`, and the sandbox receives it, but the external middleware preflight omits it. The [protocol contract]({REPO}/blob/{SHA}/proto/supervisor_middleware.proto#L167-L170) says `Content-Length`, `Content-Encoding`, and `Content-Range` retain their read-only upstream values. The [relay filters protected fields]({REPO}/blob/{SHA}/crates/openshell-supervisor-network/src/l7/rest.rs#L4178-L4181), and [that filter includes content-length]({REPO}/blob/{SHA}/crates/openshell-supervisor-network/src/l7/rest.rs#L4234-L4238).

This prevents middleware from inspecting the advertised response size through its promised header metadata. Internal length-based mode eligibility still worked, including the 32-byte-cap checks. Suggested fix: distinguish fields hidden from middleware from fields visible but immutable, retain Content-Length for preflight, and keep writes/removals forbidden. Evidence: `responses/preflight-content-length-contract.json`. No fix was applied in this testing task."""

behavior = """- Single stages: header-only, whole-body, and streaming pass-through; preflight skip/block; header writes; whole/stream redaction, replacement with empty bytes, body block, and skip_remaining.
- Failures: bad sequence numbers, explicit gRPC failure, 350 ms fixture sleeps exceeding the 150 ms RPC timeout, invalid mode selection, and attempts to mutate protected headers. Both fail-open and fail-closed were exercised.
- Chains: all nine ordered pairs of body modes; five three-stage combinations; later stages after skip_remaining and fail-open; transformed data and headers reaching subsequent stages; block despite fail-open. Event checks verified policy order, contiguous per-stage body sequences, one final unit, and trailer events for all 14 pair/triple cases.
- Delivery boundaries: preflight/whole-body blocks returned canonical 403; fail-closed before commitment returned canonical 502. Stream-only blocks/failures after commitment retained status 200 and ended with curl error 18, without injected error bytes. A delayed second-unit block delivered only `alpha ` before truncation. Both stream→whole and whole→stream blocking produced 403 because the whole-body stage delayed commitment.
- Response shapes: HEAD, 204, partial responses, gzip, no-transform, empty bodies, chunked responses, and trailer mutation. Ineligible whole-body requests followed the selected failure policy. The header-only shape tests verified permitted modes; they did not exhaustively assert every byte of compressed/partial responses.
- Limits: known and unknown lengths exceeding 32 bytes; fail-open overflow followed by another stage; growth beyond a later stage's limit; one and two streaming stages delivering 1 MiB despite a 256 KiB per-stage payload cap.
- Unit boundaries: with the literal `secret` split into `sec` and `ret` by a delayed upstream, the stateless streaming redactor delivered `secret`; whole-body redaction returned `[REDACTED]`. This matches the documented V1 limitation: stream units have no application meaning and this fixture does not retain cross-unit matching state."""

slow_lines = [
    "| Chain | Median first byte, ms | Median complete response, ms |",
    "|---|---:|---:|",
]
for r in slow:
    slow_lines.append(
        f"| {LABELS[r['name']]} | {statistics.median(x['time_starttransfer'] for x in r['samples']) * 1000:.2f} | {statistics.median(x['time_total'] for x in r['samples']) * 1000:.2f} |"
    )
slow_table = "\n".join(slow_lines)
summary = "85 of 86 live scenarios passed. The remaining check exposed missing Content-Length metadata in preflight. All 14 multi-stage event-order checks passed, as did 33 selected response-runtime and 32 response-relay regression tests."

md = f"""# PR #3074 live middleware test report

{summary}

## Protocol mismatch

{finding}

## Live coverage and observed behavior

{behavior}

## Latency with CONNECT connection reuse

All numbers below are milliseconds. Added latency is the difference between the configuration's pooled median and the no-middleware pooled median at the same payload size.

{md_table("CONNECT reuse")}

## Latency through the ordinary HTTP proxy

{md_table("HTTP proxy")}

## Delayed response and buffering

The upstream emitted three chunks with two 60 ms gaps. These are ordinary HTTP-proxy measurements, 12 retained observations per configuration. First byte refers to receipt of the response head, not the first body byte.

{slow_table}

Whole-body inspection withholds the head and body until accumulation finishes. Adding a whole-body stage to a streaming chain also removes early delivery. Streaming needs a round trip for each normalized body unit, which explains why its overhead grows with larger responses and additional stages. The 1 MiB trace shows 64 KiB units going through both services in order, plus final/trailer handling.

## Method and limits

{method}

## Evidence and reproduction

- `services.py`: configurable gRPC middleware and HTTP upstream.
- `run.py`, `policies/`, `responses/`, `matrix-results.json`: all 86 case definitions, loaded policies, wire results, and middleware events.
- `functional-summary.json`: case totals and extra chain event checks.
- `bench.py`, `tunnel-bench.py`, `extras-bench.py`: timing drivers.
- `benchmark-raw.json`, `tunnel-raw.json`, `streaming-latency.json`: unaggregated curl samples, including warm-ups and connection counts.
- `benchmark-summary.json`, `tunnel-summary.json`: derived medians, p95, and deltas.
- `runtime-tests.log`, `relay-tests.log`: selected repository regression results.
- `build.log`, `supervisor-docker-build.log`, `sandbox.log`: build and live runtime evidence.

The initial matrix had fixture-only false failures: the 502 checker expected the wrong error identifier, and curl could leave an earlier output file intact when no body arrived. Both were corrected, and the entire matrix was rerun. The initial benchmark attempted `/dev/null`, which was not writable under the fixture policy; successful runs use a temporary file. An unsupported curl fresh-connection option failed after the main timing rounds; the separate explicit-Connection-close controls were rerun with a valid header. Those controls are retained but excluded from the primary tables. Initial logs are retained for audit.

To rerun, build the gateway/CLI and supervisor at the recorded commit, create a Python environment with grpcio-tools, PyYAML, and matplotlib using uv, and regenerate the bindings from `proto/supervisor_middleware.proto`. Start `services.py`, then `start-gateway.sh`, run `run.py create`, `run.py matrix`, `bench.py`, and `tunnel-bench.py`. Run the two benchmark drivers sequentially because they update the same sandbox policy. Run `analyze.py` and `report.py` after results are complete. `start-gateway.sh` contains this host's reachable address and port choices; adapt them for another host. Keep temporary JWT private keys outside the report directory.

The disposable sandbox and fixture services were stopped after measurements. Test scripts and reports remain under the ignored `architecture/plans/pr-3074-live-tests` directory. The HTML report follows the OpenShell docs' NVIDIA green, white, gray, and dark-green palette from `fern/main.css` and `fern/docs.yml`.
"""
(OUT / "report.md").write_text(md)


def table(path):
    rows = []
    for name in ORDER:
        cells = [f"<th scope='row'>{html.escape(LABELS[name])}</th>"]
        for size in [19, 65536, 262144]:
            r = lookup[(path, name, size)]
            cells.append(
                f"<td><strong>{r['median_ms']:.2f}</strong><small>p95 {r['p95_ms']:.2f} · +{r['overhead_ms']:.2f}</small></td>"
            )
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return (
        "<div class='scroll'><table><thead><tr><th>Chain</th><th>19 bytes</th><th>64 KiB</th><th>256 KiB</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


case_rows = []
for r in results:
    c = r["case"]
    detail = {
        "path": c["path"],
        "stages": c["stages"],
        "checks": r["checks"],
        "response": {
            "status": r["result"]["metrics"]["http_code"],
            "curl_code": r["result"]["curl_code"],
            "headers": r["result"]["headers"],
            "bytes": r["result"]["metrics"]["size_download"],
            "sample": base64.b64decode(r["result"]["body_b64"])[:150].decode(
                errors="replace"
            ),
        },
        "middleware_events": r["events"],
    }
    modes = (
        " → ".join(
            {1: "Headers", 2: "Whole", 3: "Stream"}.get(s.get("mode", 1), "Invalid")
            for s in c["stages"]
        )
        or "Baseline"
    )
    case_rows.append(
        f"<tr data-status='{'pass' if r['passed'] else 'fail'}'><td><span class='{'pass' if r['passed'] else 'fail'}'>{'PASS' if r['passed'] else 'FAIL'}</span></td><th scope='row'><details><summary>{html.escape(c['name'])}</summary><pre>{html.escape(json.dumps(detail, indent=2))}</pre></details></th><td>{html.escape(modes)}</td><td>{r['result']['metrics']['http_code']}<small>curl {r['result']['curl_code']}</small></td></tr>"
    )

picture = base64.b64encode((OUT / "latency.png").read_bytes()).decode()
slow_rows = "".join(
    f"<tr><th>{html.escape(LABELS[r['name']])}</th><td>{statistics.median(x['time_starttransfer'] for x in r['samples']) * 1000:.2f}</td><td>{statistics.median(x['time_total'] for x in r['samples']) * 1000:.2f}</td></tr>"
    for r in slow
)
page = """<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>OpenShell PR 3074 live tests</title>
<style>
:root{--green:#76b900;--ink:#111;--deep:#004b31;--muted:#616161;--line:#ddd}*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}header{background:#111;color:#fff;border-top:6px solid var(--green);padding:40px max(24px,calc((100vw - 1180px)/2))}header a{color:#acd96a}h1{font-size:clamp(28px,4vw,42px);line-height:1.2;margin:12px 0}h2{font-size:27px;line-height:1.3;margin-top:0}h3{font-size:20px}p{max-width:100ch}main{max-width:1228px;margin:auto;padding:32px 24px 70px}section{margin-bottom:46px}.eyebrow{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#acd96a}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-bottom:32px}.stat{border:1px solid var(--line);padding:20px}.stat strong{display:block;font-size:35px;line-height:1.2}.stat span,small{color:var(--muted)}.finding{border-left:5px solid #b76b00;background:#fff8ec;padding:25px;margin-bottom:36px}.pass{color:var(--deep);font-weight:700}.fail{color:#a44300;font-weight:700}a{color:var(--deep)}code,pre{font:13px/1.5 ui-monospace,monospace}code{background:#eee;padding:2px 5px}pre{background:#f7f7f7;padding:16px;max-height:500px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-weight:400}.scroll{overflow:auto;max-width:100%}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:13px 14px;border-bottom:1px solid var(--line);vertical-align:top}thead th{background:#f2f2f2}tbody th{font-weight:500}td strong{font-variant-numeric:tabular-nums;font-size:17px}small{display:block;font-size:12px}summary{cursor:pointer}img{width:100%;height:auto}.controls{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:15px}input,select{font:inherit;padding:9px 12px;border:1px solid #999;background:#fff;max-width:100%}.note{color:#555;font-size:14px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}.grid>*{min-width:0}p,th,td{overflow-wrap:anywhere}footer{border-top:1px solid #ddd;padding-top:20px;color:#666;font-size:13px}@media(max-width:700px){.stats,.grid{grid-template-columns:1fr}header{padding:28px 24px}th,td{padding:9px 7px}}
</style>
<header><div class='eyebrow'>NVIDIA OpenShell · live validation · 9 September 2026</div><h1>Response middleware under test</h1><p>PR <a href='https://github.com/NVIDIA/OpenShell/pull/3074'>#3074</a> · commit 555ff3289 · real Docker sandbox, external gRPC services, measured HTTP responses</p></header><main>
"""
page += "<div class='stats'><div class='stat'><strong>85 / 86</strong><span>live scenarios passed</span></div><div class='stat'><strong>65 / 65</strong><span>selected runtime and relay regressions passed</span></div><div class='stat'><strong>5,670</strong><span>retained primary latency observations</span></div></div>"
page += f"<section class='finding'><h2>One protocol mismatch needs a fix</h2><p>The upstream sends <code>Content-Length: 19</code>, but external middleware preflight omits it. The <a href='{REPO}/blob/{SHA}/proto/supervisor_middleware.proto#L167-L170'>protocol promises read-only visibility</a>. The <a href='{REPO}/blob/{SHA}/crates/openshell-supervisor-network/src/l7/rest.rs#L4178-L4181'>relay's visibility filter</a> drops it because it shares the protected-field list.</p><p>Delivery and internal size-limit enforcement passed. Middleware cannot use the advertised size from its promised metadata. Keep this header visible while continuing to forbid mutations. No source fix was applied.</p></section>"
page += "<section><h2>What worked, and what to account for</h2><div class='grid'><div><h3>Single and chained stages</h3><p>All nine ordered mode pairs and five three-stage chains passed. Redaction, deletion, header and trailer changes, skips, blocks, RPC timeouts, invalid replies, and fail-open/fail-closed behaved as expected. Later stages still ran after skip_remaining or fail-open. All 14 extra event-order and final-unit checks passed.</p></div><div><h3>Delivery and body boundaries</h3><p>Whole-body blocks returned 403. Streaming blocks after commitment left an incomplete 200 response and curl error 18. A whole-body stage anywhere in a mixed chain delayed delivery. A literal split across two units evaded the stateless streaming redactor; whole-body inspection caught it.</p></div></div><p class='note'>Also exercised bodyless, encoded, partial, no-transform, empty, chunked, and trailer-bearing responses; 32-byte per-stage limits; growth across stages; and 1 MiB streaming through one and two stages.</p></section>"
page += f"<section><h2>Measured overhead</h2><p>One lightweight external service added about <strong>0.74 ms header-only</strong>, <strong>1.59 ms whole-body</strong>, or <strong>1.81 ms streaming</strong> on the 19-byte CONNECT path. Two streaming stages added <strong>4.38 ms</strong> for 19 bytes and <strong>8.89 ms</strong> for 256 KiB.</p><img alt='Added median latency by middleware configuration, payload size, and proxy path' src='data:image/png;base64,{picture}'><p class='note'>Local ARM64 host, optimized supervisor, Python gRPC fixtures, plaintext transport. This includes service and transport work. It does not isolate the Rust runtime alone or predict production network latency.</p></section>"
page += (
    "<section><h2>CONNECT tunnels with connection reuse</h2><p>Milliseconds. Bold numbers are medians; p95 and added median latency appear below each. Each cell has 105 observations. All retained transfers reused the existing connection.</p>"
    + table("CONNECT reuse")
    + "</section>"
)
page += (
    "<section><h2>Ordinary HTTP forward proxy</h2><p>The proxy closed each connection. All retained transfers opened a new connection. CLI/SSH startup is excluded from both paths.</p>"
    + table("HTTP proxy")
    + "</section>"
)
page += (
    "<section><h2>Whole-body inspection postpones the first byte</h2><p>The upstream sent three chunks separated by two 60 ms gaps. A whole-body stage withheld the response head until collection completed, even when a streaming stage preceded it.</p><div class='scroll'><table><thead><tr><th>Chain</th><th>Median first byte, ms</th><th>Median completion, ms</th></tr></thead><tbody>"
    + slow_rows
    + "</tbody></table></div><p class='note'>12 observations per row. Curl first byte measures response-head arrival, not the first body byte.</p></section>"
)
page += (
    "<section><h2>All 86 live scenarios</h2><p>Expand a case for the observed response, assertions, and middleware event trace.</p><div class='controls'><input id='search' type='search' aria-label='Filter cases' placeholder='Filter cases or body modes'><select id='status' aria-label='Filter result'><option value='all'>All results</option><option value='fail'>Failures only</option><option value='pass'>Passes only</option></select></div><div class='scroll'><table id='cases'><thead><tr><th>Result</th><th>Case and evidence</th><th>Stage modes</th><th>HTTP / curl</th></tr></thead><tbody>"
    + "".join(case_rows)
    + "</tbody></table></div></section>"
)
page += (
    "<section><h2>Method and practical limits</h2>"
    + "".join(
        "<p>" + html.escape(p).replace("`", "") + "</p>" for p in method.split("\n\n")
    )
    + "<p>The initial fixture issues and corrections are recorded in the companion Markdown report. The full matrix was rerun after corrections. Raw data, including warm-ups, and executable fixtures remain beside this report. No full workspace CI, concurrent-load, CPU, RSS, or TLS/authentication benchmark was run.</p></section>"
)
page += "<footer>Generated from saved observations, not predicted timings. The disposable sandbox and fixture services were stopped after testing. Design follows the OpenShell docs palette from fern/main.css and fern/docs.yml. Portable report: no remote scripts, fonts, or image dependencies.</footer></main><script>function filter(){const q=document.querySelector('#search').value.toLowerCase(),s=document.querySelector('#status').value;document.querySelectorAll('#cases tbody tr').forEach(r=>r.hidden=!(r.textContent.toLowerCase().includes(q)&&(s==='all'||s===r.dataset.status)))}document.querySelector('#search').addEventListener('input',filter);document.querySelector('#status').addEventListener('change',filter);</script></html>"
(OUT / ".lavish").mkdir(exist_ok=True)
(OUT / ".lavish/report.html").write_text(page)
print(
    f"Wrote report.md, .lavish/report.html, latency.png, latency.svg ({len(results)} cases)"
)
