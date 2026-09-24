#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Apply reviewed security finding dispositions to a scanner's release gate.

Each scanner's enforce step passes its native reports here. A HIGH/CRITICAL
finding passes only when a current entry in security-dispositions.toml covers
its rule and path, and that entry lists at least as many alerts at the path as
there are findings. Everything else fails the gate as before.

Exit status: 0 when every finding is covered (or enforcement is off), 10 when a
finding is uncovered, expired, or over its entry's cap, and 2 when the
dispositions file or a report cannot be evaluated.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

EXIT_FINDINGS = 10
EXIT_ERROR = 2

SCANNERS = ("codeql", "trivy", "zizmor")
DISPOSITIONS = ("deferred", "rejected")
SCANNER_SEVERITIES = ("critical", "high")
ASSESSED_SEVERITIES = ("critical", "high", "medium", "low", "none")
SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}
CODEQL_THRESHOLD = 7.0
# CodeQL rule IDs use short prefixes for some matrix languages.
CODEQL_RULE_PREFIXES = {"javascript-typescript": "js", "python": "py"}
EXPIRY_WARNING_DAYS = 7

STRING_FIELDS = (
    "id",
    "scanner",
    "rule",
    "disposition",
    "scanner_severity",
    "assessed_severity",
    "reason",
    "approver",
    "first_seen_at",
)
REQUIRED_FIELDS = (*STRING_FIELDS, "first_seen", "alerts")
OPTIONAL_FIELDS = ("expires", "sla_exception")


class DispositionError(Exception):
    """The dispositions file or a scanner report cannot be evaluated."""


@dataclass(frozen=True)
class Entry:
    id: str
    scanner: str
    rule: str
    disposition: str
    scanner_severity: str
    assessed_severity: str
    reason: str
    approver: str
    first_seen: dt.date
    first_seen_at: str
    expires: dt.date | None
    sla_exception: str | None
    alerts: dict[int, str]

    def cap(self, path: str) -> int:
        """How many findings this entry may cover at one path."""
        return sum(1 for alert_path in self.alerts.values() if alert_path == path)

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today


def derived_id(scanner: str, rule: str, alerts: dict[int, str]) -> str:
    # Zizmor's code-scanning rule IDs already carry the scanner name.
    prefix = "" if scanner == "zizmor" else f"{scanner}/"
    return f"{prefix}{rule}/{min(alerts)}"


def _choice(where: str, name: str, value: str, allowed: tuple[str, ...]) -> None:
    if value not in allowed:
        raise DispositionError(f"{where}: {name} must be one of {', '.join(allowed)}")


def _parse_alerts(where: str, raw: object) -> dict[int, str]:
    if not isinstance(raw, dict) or not raw:
        raise DispositionError(
            f"{where}: alerts must be a non-empty table of alert number = path"
        )
    alerts: dict[int, str] = {}
    for key, path in raw.items():
        # Only canonical numbers: "04" would silently alias alert 4.
        if not key.isdecimal() or str(int(key)) != key or int(key) < 1:
            raise DispositionError(
                f"{where}: alerts key {key!r} is not an alert number"
            )
        if not isinstance(path, str) or not path.strip():
            raise DispositionError(f"{where}: alert {key} needs a non-empty path")
        alerts[int(key)] = path
    return alerts


def _parse_entry(raw: object, index: int) -> Entry:
    where = f"disposition[{index}]"
    if not isinstance(raw, dict):
        raise DispositionError(f"{where}: expected a table")
    if isinstance(raw.get("id"), str):
        where = f"{where} ({raw['id']})"

    unknown = sorted(set(raw) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if unknown:
        raise DispositionError(f"{where}: unknown field(s): {', '.join(unknown)}")
    missing = [name for name in REQUIRED_FIELDS if name not in raw]
    if missing:
        raise DispositionError(f"{where}: missing field(s): {', '.join(missing)}")
    for name in (*STRING_FIELDS, "sla_exception"):
        if name in raw and (not isinstance(raw[name], str) or not raw[name].strip()):
            raise DispositionError(f"{where}: {name} must be a non-empty string")
    for name in ("first_seen", "expires"):
        # tomllib returns datetime (a date subclass) for date-times; require a plain date.
        if name in raw and type(raw[name]) is not dt.date:
            raise DispositionError(f"{where}: {name} must be a TOML date (YYYY-MM-DD)")

    scanner, rule, disposition = raw["scanner"], raw["rule"], raw["disposition"]
    assessed = raw["assessed_severity"]
    _choice(where, "scanner", scanner, SCANNERS)
    _choice(where, "disposition", disposition, DISPOSITIONS)
    _choice(where, "scanner_severity", raw["scanner_severity"], SCANNER_SEVERITIES)
    _choice(where, "assessed_severity", assessed, ASSESSED_SEVERITIES)
    if scanner == "zizmor" and not rule.startswith("zizmor/"):
        raise DispositionError(f"{where}: zizmor rules start with 'zizmor/'")
    if assessed == "none" and disposition != "rejected":
        raise DispositionError(
            f"{where}: assessed_severity none requires disposition rejected"
        )

    alerts = _parse_alerts(where, raw["alerts"])
    expected = derived_id(scanner, rule, alerts)
    if raw["id"] != expected:
        raise DispositionError(f"{where}: id must be {expected!r}")

    expires = raw.get("expires")
    sla_exception = raw.get("sla_exception")
    if disposition == "rejected":
        if expires is not None:
            raise DispositionError(
                f"{where}: rejected entries do not expire; remove expires"
            )
        if sla_exception is not None:
            raise DispositionError(
                f"{where}: sla_exception applies only to deferred entries"
            )
    else:
        if expires is None:
            raise DispositionError(f"{where}: deferred entries need expires")
        deadline = raw["first_seen"] + dt.timedelta(days=SLA_DAYS[assessed])
        if expires > deadline and sla_exception is None:
            raise DispositionError(
                f"{where}: expires {expires} is past the {assessed} SLA ({deadline}); "
                "fix sooner or add sla_exception"
            )

    return Entry(
        id=raw["id"],
        scanner=scanner,
        rule=rule,
        disposition=disposition,
        scanner_severity=raw["scanner_severity"],
        assessed_severity=assessed,
        reason=raw["reason"],
        approver=raw["approver"],
        first_seen=raw["first_seen"],
        first_seen_at=raw["first_seen_at"],
        expires=expires,
        sla_exception=sla_exception,
        alerts=alerts,
    )


def load_dispositions(path: Path) -> list[Entry]:
    """Load and validate the dispositions file. A missing file has no entries."""
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise DispositionError(f"{path}: {error}") from error

    unknown = sorted(set(data) - {"disposition"})
    if unknown:
        raise DispositionError(
            f"{path}: unknown top-level key(s): {', '.join(unknown)}"
        )
    raw_entries = data.get("disposition", [])
    if not isinstance(raw_entries, list):
        raise DispositionError(f"{path}: disposition must be an array of tables")
    entries = [_parse_entry(raw, index) for index, raw in enumerate(raw_entries)]

    alert_owner: dict[int, str] = {}
    coverage: dict[tuple[str, str, str], str] = {}
    for entry in entries:
        for number, alert_path in entry.alerts.items():
            if number in alert_owner:
                raise DispositionError(
                    f"alert {number} is listed by both {alert_owner[number]} and {entry.id}"
                )
            alert_owner[number] = entry.id
            owner = coverage.setdefault(
                (entry.scanner, entry.rule, alert_path), entry.id
            )
            if owner != entry.id:
                raise DispositionError(
                    f"{owner} and {entry.id} both cover {entry.rule} at {alert_path}"
                )
    return entries


@dataclass(frozen=True, order=True)
class Finding:
    rule: str
    path: str
    line: int  # 0 when the scanner reports none, as for image vulnerabilities

    def describe(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{self.rule} at {where}"


def codeql_findings(report: dict) -> list[Finding]:
    """Results scored at least 7.0 that are not suppressed as accepted."""
    findings = []
    for run in report.get("runs", []):
        tool = run.get("tool", {})
        scores: dict[str, float] = {}
        for component in (tool.get("driver", {}), *tool.get("extensions", [])):
            for rule in component.get("rules", []):
                score = float(rule.get("properties", {}).get("security-severity", "0"))
                scores[rule["id"]] = max(score, scores.get(rule["id"], 0.0))
        for result in run.get("results", []):
            if any(
                suppression.get("status") == "accepted"
                for suppression in result.get("suppressions", [])
            ):
                continue
            if scores.get(result.get("ruleId"), 0.0) < CODEQL_THRESHOLD:
                continue
            physical = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append(
                Finding(
                    rule=result["ruleId"],
                    path=physical.get("artifactLocation", {}).get("uri", ""),
                    line=physical.get("region", {}).get("startLine", 0),
                )
            )
    return findings


def zizmor_findings(report: list) -> list[Finding]:
    """High findings that are not ignored inline. Zizmor has no critical level."""
    findings = []
    for item in report:
        if (
            item.get("ignored")
            or item.get("determinations", {}).get("severity") != "High"
        ):
            continue
        locations = item.get("locations", [])
        primary = next(
            (
                location
                for location in locations
                if location.get("symbolic", {}).get("kind") == "Primary"
            ),
            locations[0] if locations else {},
        )
        local = primary.get("symbolic", {}).get("key", {}).get("Local", {})
        row = (
            primary.get("concrete", {})
            .get("location", {})
            .get("start_point", {})
            .get("row")
        )
        findings.append(
            Finding(
                rule=f"zizmor/{item['ident']}",
                path=local.get("verbatim_path", "").removeprefix("./"),
                line=row + 1 if row is not None else 0,
            )
        )
    return findings


def trivy_findings(report: dict, severities: frozenset[str]) -> list[Finding]:
    """Failed misconfigurations by target, and vulnerabilities by package.

    Image targets change with every digest, so vulnerabilities key on the
    package name instead.
    """
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise DispositionError("not a Trivy JSON report (SchemaVersion 2)")
    findings = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for misconfiguration in result.get("Misconfigurations") or []:
            if (
                misconfiguration.get("Status", "FAIL") == "FAIL"
                and misconfiguration.get("Severity") in severities
            ):
                line = (misconfiguration.get("CauseMetadata") or {}).get(
                    "StartLine"
                ) or 0
                findings.append(Finding(misconfiguration["ID"], target, line))
        for vulnerability in result.get("Vulnerabilities") or []:
            if vulnerability.get("Severity") in severities:
                findings.append(
                    Finding(
                        vulnerability["VulnerabilityID"], vulnerability["PkgName"], 0
                    )
                )
    return findings


def load_findings(
    scanner: str, reports: list[Path], severities: frozenset[str]
) -> list[Finding]:
    """All gating findings across reports, one per rule, path, and line.

    Code scanning keeps one alert per rule and line, and Trivy repeats findings
    across platform images and Helm profiles.
    """
    findings: set[Finding] = set()
    for path in reports:
        try:
            with path.open(encoding="utf-8") as handle:
                report = json.load(handle)
            if scanner == "codeql":
                findings.update(codeql_findings(report))
            elif scanner == "zizmor":
                findings.update(zizmor_findings(report))
            else:
                findings.update(trivy_findings(report, severities))
        except DispositionError as error:
            raise DispositionError(f"{path}: {error}") from error
        except (
            OSError,
            ValueError,
            AttributeError,
            KeyError,
            TypeError,
            IndexError,
        ) as error:
            raise DispositionError(
                f"{path}: malformed {scanner} report ({error!r})"
            ) from error
    return sorted(findings)


STATUS_TEXT = {
    "expired": "deferral expired",
    "over-cap": "more findings than listed alerts",
    "uncovered": "no disposition",
}


@dataclass(frozen=True)
class Outcome:
    finding: Finding
    entry: Entry | None
    status: str  # covered, expired, over-cap, or uncovered

    def describe(self) -> str:
        if self.status == "expired" and self.entry is not None:
            return f"deferral {self.entry.id} expired {self.entry.expires}: {self.finding.describe()}"
        return f"{STATUS_TEXT[self.status]}: {self.finding.describe()}"


@dataclass
class Evaluation:
    outcomes: list[Outcome]
    entries: list[Entry]  # entries in scope for this scanner and language
    today: dt.date
    failures: list[Outcome] = field(init=False)

    def __post_init__(self) -> None:
        self.failures = [
            outcome for outcome in self.outcomes if outcome.status != "covered"
        ]

    def matched(self, entry: Entry) -> int:
        return sum(
            1
            for outcome in self.outcomes
            if outcome.entry is not None and outcome.entry.id == entry.id
        )

    @property
    def stale(self) -> list[Entry]:
        return [entry for entry in self.entries if not self.matched(entry)]

    @property
    def expiring(self) -> list[Entry]:
        horizon = self.today + dt.timedelta(days=EXPIRY_WARNING_DAYS)
        return [
            entry
            for entry in self.entries
            if entry.expires is not None and self.today <= entry.expires <= horizon
        ]

    def warnings(self) -> list[str]:
        return [
            *(
                f"{entry.id} matched no findings; remove it if its alerts are fixed."
                for entry in self.stale
            ),
            *(f"{entry.id} expires {entry.expires}." for entry in self.expiring),
        ]


def evaluate(
    findings: list[Finding],
    entries: list[Entry],
    *,
    scanner: str,
    today: dt.date,
    language: str | None = None,
) -> Evaluation:
    prefix = f"{CODEQL_RULE_PREFIXES.get(language, language)}/" if language else ""
    scoped = [
        entry
        for entry in entries
        if entry.scanner == scanner and entry.rule.startswith(prefix)
    ]
    by_rule_path = {
        (entry.rule, path): entry for entry in scoped for path in entry.alerts.values()
    }
    used: Counter[tuple[str, str]] = Counter()
    outcomes = []
    for finding in findings:
        entry = by_rule_path.get((finding.rule, finding.path))
        if entry is None:
            status = "uncovered"
        elif entry.expired(today):
            status = "expired"
        else:
            used[(entry.id, finding.path)] += 1
            status = (
                "covered"
                if used[(entry.id, finding.path)] <= entry.cap(finding.path)
                else "over-cap"
            )
        outcomes.append(Outcome(finding, entry, status))
    return Evaluation(outcomes, scoped, today)


def _cell(text: str | None) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


def render_summary(evaluation: Evaluation, title: str) -> str:
    total = len(evaluation.outcomes)
    failing = len(evaluation.failures)
    lines = [
        f"### Security dispositions: {title}",
        "",
        f"HIGH/CRITICAL findings: {total}. Covered by a disposition: {total - failing}. Failing: {failing}.",
    ]
    matched = [entry for entry in evaluation.entries if evaluation.matched(entry)]
    if matched:
        lines += [
            "",
            "| Entry | Disposition | Approver | Expires | Findings / alerts | SLA exception |",
            "|---|---|---|---|---|---|",
        ]
        for entry in matched:
            lines.append(
                f"| `{entry.id}` | {entry.disposition} ({entry.assessed_severity}) | @{entry.approver} "
                f"| {entry.expires or 'never'} | {evaluation.matched(entry)} / {len(entry.alerts)} "
                f"| {_cell(entry.sla_exception)} |"
            )
    if evaluation.failures:
        lines += ["", "#### Failing findings", ""]
        lines += [f"- {outcome.describe()}" for outcome in evaluation.failures]
    warnings = evaluation.warnings()
    if warnings:
        lines += ["", "#### Warnings", ""]
        lines += [f"- {warning}" for warning in warnings]
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    gate = commands.add_parser(
        "gate", help="Evaluate one scanner's reports against the dispositions file"
    )
    gate.add_argument("--scanner", choices=SCANNERS, required=True)
    gate.add_argument("--dispositions", type=Path, required=True)
    gate.add_argument(
        "--language",
        help="CodeQL language; only entries for <language>/ rules are in scope",
    )
    gate.add_argument(
        "--severity", default="HIGH,CRITICAL", help="Trivy severities that gate"
    )
    gate.add_argument("--fail-on-findings", choices=("true", "false"), default="true")
    gate.add_argument(
        "--today", type=dt.date.fromisoformat, default=dt.datetime.now(dt.UTC).date()
    )
    gate.add_argument("reports", nargs="+", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    severities = frozenset(
        part.strip().upper() for part in args.severity.split(",") if part.strip()
    )
    try:
        entries = load_dispositions(args.dispositions)
        findings = load_findings(args.scanner, args.reports, severities)
    except DispositionError as error:
        print(f"::error::{error}")
        return EXIT_ERROR

    evaluation = evaluate(
        findings,
        entries,
        scanner=args.scanner,
        today=args.today,
        language=args.language,
    )
    title = f"{args.scanner} ({args.language})" if args.language else args.scanner
    summary = render_summary(evaluation, title)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as handle:
            handle.write(summary)
    else:
        print(summary)

    enforce = args.fail_on_findings == "true"
    level = "error" if enforce else "warning"
    for outcome in evaluation.failures:
        print(f"::{level}::{outcome.describe()}")
    for warning in evaluation.warnings():
        print(f"::warning::{warning}")
    if evaluation.failures and not enforce:
        print(
            f"::warning::{len(evaluation.failures)} finding(s) fail the disposition gate; enforcement is disabled."
        )
    return EXIT_FINDINGS if evaluation.failures and enforce else 0


if __name__ == "__main__":
    sys.exit(main())
