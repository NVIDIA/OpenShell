# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import security_dispositions as sd

SCRIPT = Path(__file__).resolve().parent / "security_dispositions.py"
REPO_DISPOSITIONS = Path(__file__).resolve().parents[2] / "security-dispositions.toml"
TODAY = dt.date(2026, 9, 24)


def deferral(**overrides: object) -> dict[str, object]:
    """A valid Zizmor deferral; pass a field as None to drop it."""
    entry: dict[str, object] = {
        "id": "zizmor/unpinned-images/4",
        "scanner": "zizmor",
        "rule": "zizmor/unpinned-images",
        "disposition": "deferred",
        "scanner_severity": "high",
        "assessed_severity": "high",
        "reason": "CI jobs use a floating image tag.",
        "approver": "purp",
        "first_seen": dt.date(2026, 9, 20),
        "first_seen_at": "https://github.com/NVIDIA/OpenShell/actions/runs/1",
        "expires": dt.date(2026, 10, 4),
        "alerts": {
            "4": ".github/workflows/a.yml",
            "5": ".github/workflows/a.yml",
            "12": ".github/workflows/b.yml",
        },
    }
    entry.update(overrides)
    return {key: value for key, value in entry.items() if value is not None}


def rejection(**overrides: object) -> dict[str, object]:
    return deferral(
        **{
            "id": "codeql/rust/cleartext-logging/166",
            "scanner": "codeql",
            "rule": "rust/cleartext-logging",
            "disposition": "rejected",
            "assessed_severity": "none",
            "expires": None,
            "alerts": {"166": "crates/openshell-cli/src/commands/gateway.rs"},
            **overrides,
        }
    )


def _toml_value(value: object) -> str:
    if isinstance(value, str):
        # A JSON string is a valid TOML basic string.
        return json.dumps(value)
    if isinstance(value, dt.date):
        return value.isoformat()
    raise TypeError(value)


def write_dispositions(path: Path, *entries: dict[str, object]) -> Path:
    lines: list[str] = []
    for entry in entries:
        lines.append("[[disposition]]")
        for key, value in entry.items():
            if key != "alerts":
                lines.append(f"{key} = {_toml_value(value)}")
        if "alerts" in entry:
            lines.append("[disposition.alerts]")
            for number, alert_path in entry["alerts"].items():  # type: ignore[union-attr]
                lines.append(f"{number} = {json.dumps(alert_path)}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def load(tmp_path: Path, *entries: dict[str, object]) -> list[sd.Entry]:
    return sd.load_dispositions(write_dispositions(tmp_path / "d.toml", *entries))


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(path))
    return path


# Loading and validation


def test_missing_file_means_no_entries(tmp_path: Path) -> None:
    assert sd.load_dispositions(tmp_path / "absent.toml") == []


def test_loads_valid_entries(tmp_path: Path) -> None:
    deferred, rejected = load(tmp_path, deferral(), rejection())
    assert deferred.alerts == {
        4: ".github/workflows/a.yml",
        5: ".github/workflows/a.yml",
        12: ".github/workflows/b.yml",
    }
    assert deferred.cap(".github/workflows/a.yml") == 2
    assert deferred.cap(".github/workflows/c.yml") == 0
    assert deferred.expired(dt.date(2026, 10, 4)) is False
    assert deferred.expired(dt.date(2026, 10, 5)) is True
    assert rejected.expires is None
    assert rejected.expired(dt.date(2099, 1, 1)) is False


def test_derived_ids() -> None:
    assert (
        sd.derived_id("zizmor", "zizmor/github-env", {180: "x", 125: "y"})
        == "zizmor/github-env/125"
    )
    assert (
        sd.derived_id("codeql", "rust/cleartext-logging", {163: "x"})
        == "codeql/rust/cleartext-logging/163"
    )
    assert sd.derived_id("trivy", "KSV-0014", {210: "x"}) == "trivy/KSV-0014/210"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (deferral(owner="purp"), "unknown field"),
        (deferral(reason=None), "missing field"),
        (deferral(reason=""), "reason must be a non-empty string"),
        (deferral(first_seen="2026-09-20"), "first_seen must be a TOML date"),
        (deferral(scanner="semgrep"), "scanner must be one of"),
        (deferral(disposition="accepted"), "disposition must be one of"),
        (deferral(scanner_severity="medium"), "scanner_severity must be one of"),
        (
            deferral(assessed_severity="none"),
            "assessed_severity none requires disposition rejected",
        ),
        (deferral(id="V5"), "id must be 'zizmor/unpinned-images/4'"),
        (
            deferral(rule="unpinned-images", id="unpinned-images/4"),
            "zizmor rules start with 'zizmor/'",
        ),
        (deferral(expires=None), "deferred entries need expires"),
        (rejection(expires=dt.date(2026, 10, 1)), "rejected entries do not expire"),
        (
            rejection(sla_exception="x"),
            "sla_exception applies only to deferred entries",
        ),
        (deferral(alerts={}), "alerts must be a non-empty table"),
        (deferral(expires=dt.date(2026, 10, 5)), "past the high SLA (2026-10-04)"),
    ],
)
def test_rejects_invalid_entries(
    tmp_path: Path, entry: dict[str, object], message: str
) -> None:
    with pytest.raises(sd.DispositionError, match=re.escape(message)):
        load(tmp_path, entry)


def test_sla_exception_allows_longer_expiry(tmp_path: Path) -> None:
    (entry,) = load(
        tmp_path,
        deferral(expires=dt.date(2026, 11, 17), sla_exception="Pre-GA backlog."),
    )
    assert entry.sla_exception == "Pre-GA backlog."


def test_expiry_on_sla_deadline_is_allowed(tmp_path: Path) -> None:
    (entry,) = load(
        tmp_path,
        deferral(expires=dt.date(2026, 9, 20) + dt.timedelta(days=sd.SLA_DAYS["high"])),
    )
    assert entry.expires == dt.date(2026, 10, 4)


@pytest.mark.parametrize("key", ["04", "0", "x", "-3"])
def test_rejects_bad_alert_keys(tmp_path: Path, key: str) -> None:
    path = write_dispositions(tmp_path / "d.toml", deferral(alerts={"4": "a.yml"}))
    path.write_text(path.read_text().replace('4 = "a.yml"', f'"{key}" = "a.yml"'))
    with pytest.raises(sd.DispositionError, match="is not an alert number"):
        sd.load_dispositions(path)


def test_rejects_datetime_for_date_fields(tmp_path: Path) -> None:
    path = write_dispositions(tmp_path / "d.toml", deferral())
    path.write_text(
        path.read_text().replace(
            "first_seen = 2026-09-20", "first_seen = 2026-09-20T12:46:43Z"
        )
    )
    with pytest.raises(sd.DispositionError, match="first_seen must be a TOML date"):
        sd.load_dispositions(path)


def test_rejects_alert_listed_twice(tmp_path: Path) -> None:
    other = deferral(
        id="zizmor/github-env/4",
        rule="zizmor/github-env",
        alerts={"4": ".github/actions/x/action.yml"},
    )
    with pytest.raises(sd.DispositionError, match="alert 4 is listed by both"):
        load(tmp_path, deferral(), other)


def test_rejects_two_entries_for_one_rule_and_path(tmp_path: Path) -> None:
    other = deferral(
        id="zizmor/unpinned-images/40", alerts={"40": ".github/workflows/a.yml"}
    )
    with pytest.raises(
        sd.DispositionError,
        match=re.escape("both cover zizmor/unpinned-images at .github/workflows/a.yml"),
    ):
        load(tmp_path, deferral(), other)


def test_rejects_toml_syntax_errors(tmp_path: Path) -> None:
    path = tmp_path / "d.toml"
    path.write_text("[[disposition]\n")
    with pytest.raises(sd.DispositionError, match=re.escape("d.toml")):
        sd.load_dispositions(path)


def test_rejects_unknown_top_level_keys(tmp_path: Path) -> None:
    path = tmp_path / "d.toml"
    path.write_text('version = "1"\n')
    with pytest.raises(sd.DispositionError, match="unknown top-level key"):
        sd.load_dispositions(path)


def test_repository_dispositions_file_is_valid() -> None:
    entries = sd.load_dispositions(REPO_DISPOSITIONS)
    assert entries, "security-dispositions.toml should exist and list entries"


# Finding extraction

HIGH_RULES = [
    {"id": "rust/cleartext-logging", "properties": {"security-severity": "7.5"}},
    {
        "id": "rust/disabled-certificate-check",
        "properties": {"security-severity": "7.5"},
    },
    {"id": "rust/low-severity", "properties": {"security-severity": "5.0"}},
]


def codeql_result(
    rule: str, path: str, line: int, *, accepted: bool = False
) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": rule,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if accepted:
        result["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
    return result


def codeql_sarif(*results: dict[str, object]) -> dict[str, object]:
    # CodeQL puts query rules in tool.extensions, not tool.driver.
    return {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL", "rules": []},
                    "extensions": [
                        {"name": "codeql/rust-queries", "rules": HIGH_RULES}
                    ],
                },
                "results": list(results),
            }
        ]
    }


def zizmor_item(
    ident: str, path: str, row: int, *, severity: str = "High", ignored: bool = False
) -> dict[str, object]:
    return {
        "ident": ident,
        "ignored": ignored,
        "determinations": {
            "confidence": "Low",
            "severity": severity,
            "persona": "Regular",
        },
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": f"./{path}"}},
                    "annotation": "finding",
                    "kind": "Primary",
                },
                "concrete": {"location": {"start_point": {"row": row, "column": 6}}},
            }
        ],
    }


def trivy_report(
    target: str = "deploy/docker/Dockerfile.supervisor",
    *,
    misconfigurations: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
    vulnerabilities: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
) -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "deploy",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": target,
                "Misconfigurations": list(misconfigurations),
                "Vulnerabilities": list(vulnerabilities),
            }
        ],
    }


def test_codeql_findings_apply_threshold_and_suppressions() -> None:
    report = codeql_sarif(
        codeql_result("rust/cleartext-logging", "crates/a.rs", 10),
        codeql_result("rust/low-severity", "crates/a.rs", 11),
        codeql_result("rust/cleartext-logging", "crates/a.rs", 12, accepted=True),
    )
    assert sd.codeql_findings(report) == [
        sd.Finding("rust/cleartext-logging", "crates/a.rs", 10)
    ]


def test_zizmor_findings_keep_high_unignored() -> None:
    report = [
        zizmor_item("github-env", ".github/actions/setup-e2e-cli/action.yml", 20),
        zizmor_item("github-env", ".github/actions/x/action.yml", 1, ignored=True),
        zizmor_item(
            "template-injection", ".github/workflows/a.yml", 5, severity="Medium"
        ),
    ]
    assert sd.zizmor_findings(report) == [
        sd.Finding("zizmor/github-env", ".github/actions/setup-e2e-cli/action.yml", 21)
    ]


def test_trivy_findings_use_target_for_config_and_package_for_images() -> None:
    config = trivy_report(
        misconfigurations=[
            {
                "ID": "DS-0002",
                "Status": "FAIL",
                "Severity": "HIGH",
                "CauseMetadata": {},
            },
            {"ID": "DS-0026", "Status": "FAIL", "Severity": "LOW", "CauseMetadata": {}},
            {
                "ID": "DS-0001",
                "Status": "PASS",
                "Severity": "HIGH",
                "CauseMetadata": {},
            },
        ]
    )
    image = trivy_report(
        "ghcr.io/nvidia/openshell/gateway (debian 12)",
        vulnerabilities=[
            {
                "VulnerabilityID": "CVE-2026-1",
                "PkgName": "openssl",
                "Severity": "CRITICAL",
            }
        ],
    )
    severities = frozenset({"HIGH", "CRITICAL"})
    assert sd.trivy_findings(config, severities) == [
        sd.Finding("DS-0002", "deploy/docker/Dockerfile.supervisor", 0)
    ]
    assert sd.trivy_findings(image, severities) == [
        sd.Finding("CVE-2026-1", "openssl", 0)
    ]


def test_trivy_rejects_non_trivy_json() -> None:
    with pytest.raises(sd.DispositionError, match="SchemaVersion"):
        sd.trivy_findings({}, frozenset({"HIGH"}))


def test_load_findings_dedupes_across_reports(tmp_path: Path) -> None:
    vulnerability = {
        "VulnerabilityID": "CVE-2026-1",
        "PkgName": "openssl",
        "Severity": "HIGH",
    }
    amd64 = write_json(
        tmp_path / "image-amd64.json",
        trivy_report("gateway", vulnerabilities=[vulnerability]),
    )
    arm64 = write_json(
        tmp_path / "image-arm64.json",
        trivy_report("gateway", vulnerabilities=[vulnerability]),
    )
    findings = sd.load_findings(
        "trivy", [amd64, arm64], frozenset({"HIGH", "CRITICAL"})
    )
    assert findings == [sd.Finding("CVE-2026-1", "openssl", 0)]


def test_zizmor_same_line_findings_count_once(tmp_path: Path) -> None:
    # Two expressions in one run: block are two Zizmor findings but one code-scanning alert.
    report = write_json(
        tmp_path / "zizmor.json",
        [zizmor_item("template-injection", ".github/workflows/a.yml", 5)] * 2,
    )
    assert len(sd.load_findings("zizmor", [report], frozenset())) == 1


def test_load_findings_rejects_malformed_reports(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{")
    with pytest.raises(sd.DispositionError, match=re.escape("bad.json")):
        sd.load_findings("zizmor", [bad_json], frozenset())
    wrong_shape = write_json(
        tmp_path / "shape.json", {"runs": [{"results": [{"ruleId": 3}]}], "tool": 1}
    )
    with pytest.raises(sd.DispositionError, match=re.escape("shape.json")):
        sd.load_findings("zizmor", [wrong_shape], frozenset())


# Evaluation and CLI

COVERED_ITEMS = [
    zizmor_item("unpinned-images", ".github/workflows/a.yml", 10),
    zizmor_item("unpinned-images", ".github/workflows/a.yml", 20),
    zizmor_item("unpinned-images", ".github/workflows/b.yml", 30),
]


def zizmor_gate(
    tmp_path: Path,
    items: list[dict[str, object]],
    *entries: dict[str, object],
    extra: tuple[str, ...] = (),
) -> int:
    dispositions = write_dispositions(tmp_path / "d.toml", *entries)
    report = write_json(tmp_path / "zizmor.json", items)
    return sd.main(
        [
            "gate",
            "--scanner",
            "zizmor",
            "--dispositions",
            str(dispositions),
            "--today",
            TODAY.isoformat(),
            *extra,
            str(report),
        ]
    )


def test_all_covered_passes(
    tmp_path: Path, step_summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert zizmor_gate(tmp_path, COVERED_ITEMS, deferral()) == 0
    summary = step_summary.read_text()
    assert (
        "| `zizmor/unpinned-images/4` | deferred (high) | @purp | 2026-10-04 | 3 / 3 |"
        in summary
    )
    assert "::error::" not in capsys.readouterr().out


def test_uncovered_finding_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    items = [
        *COVERED_ITEMS,
        zizmor_item("template-injection", ".github/workflows/release-canary.yml", 404),
    ]
    assert zizmor_gate(tmp_path, items, deferral()) == sd.EXIT_FINDINGS
    assert (
        "::error::no disposition: zizmor/template-injection at .github/workflows/release-canary.yml:405"
        in capsys.readouterr().out
    )


def test_expired_deferral_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    entry = deferral(first_seen=dt.date(2026, 9, 1), expires=dt.date(2026, 9, 15))
    assert zizmor_gate(tmp_path, COVERED_ITEMS, entry) == sd.EXIT_FINDINGS
    assert (
        "::error::deferral zizmor/unpinned-images/4 expired 2026-09-15"
        in capsys.readouterr().out
    )


def test_over_cap_at_one_path_fails_even_when_another_path_is_under(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # a.yml lists two alerts and has three findings; b.yml lists one and has none.
    items = [
        *COVERED_ITEMS[:2],
        zizmor_item("unpinned-images", ".github/workflows/a.yml", 99),
    ]
    assert zizmor_gate(tmp_path, items, deferral()) == sd.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert out.count("::error::") == 1
    assert "more findings than listed alerts" in out


def test_rejection_never_expires(tmp_path: Path) -> None:
    entry = rejection(
        id="zizmor/unpinned-images/4",
        scanner="zizmor",
        rule="zizmor/unpinned-images",
        alerts=deferral()["alerts"],
    )
    dispositions = write_dispositions(tmp_path / "d.toml", entry)
    report = write_json(tmp_path / "z.json", COVERED_ITEMS)
    args = [
        "gate",
        "--scanner",
        "zizmor",
        "--dispositions",
        str(dispositions),
        "--today",
        "2099-01-01",
        str(report),
    ]
    assert sd.main(args) == 0


def test_stale_and_expiring_entries_warn(
    tmp_path: Path, step_summary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = deferral(
        id="zizmor/github-env/125",
        rule="zizmor/github-env",
        alerts={"125": ".github/actions/setup-e2e-gateway/action.yml"},
    )
    soon = deferral(expires=dt.date(2026, 9, 30))
    assert zizmor_gate(tmp_path, COVERED_ITEMS, soon, stale) == 0
    out = capsys.readouterr().out
    assert "::warning::zizmor/github-env/125 matched no findings" in out
    assert "::warning::zizmor/unpinned-images/4 expires 2026-09-30" in out
    assert "#### Warnings" in step_summary.read_text()


def test_missing_dispositions_file_fails_on_findings(tmp_path: Path) -> None:
    report = write_json(tmp_path / "z.json", COVERED_ITEMS)
    args = [
        "gate",
        "--scanner",
        "zizmor",
        "--dispositions",
        str(tmp_path / "absent.toml"),
        str(report),
    ]
    assert sd.main(args) == sd.EXIT_FINDINGS


def test_no_findings_and_no_file_passes(tmp_path: Path) -> None:
    report = write_json(tmp_path / "z.json", [])
    args = [
        "gate",
        "--scanner",
        "zizmor",
        "--dispositions",
        str(tmp_path / "absent.toml"),
        str(report),
    ]
    assert sd.main(args) == 0


def test_enforcement_off_warns_instead(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        zizmor_gate(tmp_path, COVERED_ITEMS, extra=("--fail-on-findings", "false")) == 0
    )
    out = capsys.readouterr().out
    assert "::error::" not in out
    assert "::warning::no disposition: zizmor/unpinned-images" in out


def test_invalid_dispositions_always_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        zizmor_gate(
            tmp_path, [], deferral(id="V5"), extra=("--fail-on-findings", "false")
        )
        == sd.EXIT_ERROR
    )
    assert "::error::" in capsys.readouterr().out


def test_language_scopes_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    entries = write_dispositions(
        tmp_path / "d.toml",
        rejection(),
        rejection(
            id="codeql/py/unsafe/7", rule="py/unsafe", alerts={"7": "python/x.py"}
        ),
    )
    sarif = write_json(
        tmp_path / "rust.sarif",
        codeql_sarif(
            codeql_result(
                "rust/cleartext-logging",
                "crates/openshell-cli/src/commands/gateway.rs",
                1256,
            )
        ),
    )
    args = [
        "gate",
        "--scanner",
        "codeql",
        "--language",
        "rust",
        "--dispositions",
        str(entries),
        str(sarif),
    ]
    assert sd.main(args) == 0
    assert "py/unsafe" not in capsys.readouterr().out


def test_script_entrypoint(tmp_path: Path) -> None:
    report = write_json(tmp_path / "z.json", [])
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "gate",
            "--scanner",
            "zizmor",
            "--dispositions",
            str(tmp_path / "none.toml"),
            str(report),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"]},
    )
    assert completed.returncode == 0, completed.stderr
    assert "### Security dispositions: zizmor" in completed.stdout
