# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the compatibility reviewer without inference or release publication."""

import json
import subprocess
import sys

import pytest
from codex_compatibility import resolve_candidate, run_review
from codex_compatibility_report import SURFACES, validate_review


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


@pytest.fixture(autouse=True)
def repository(tmp_path, monkeypatch):
    repo = tmp_path / "source"
    repo.mkdir()
    monkeypatch.chdir(repo)
    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.com")
    git("-c", "commit.gpgsign=false", "commit", "-qm", "stable", "--allow-empty")
    git("tag", "v0.1.2")
    git("-c", "commit.gpgsign=false", "commit", "-qm", "first change", "--allow-empty")
    git("tag", "v0.1.3-pre.1")
    git("-c", "commit.gpgsign=false", "commit", "-qm", "second change", "--allow-empty")
    git("tag", "v0.1.3-pre.2")
    return repo


def review():
    return {
        "verdict": "no_unaddressed_breaks",
        "summary": "No incompatible changes found in the reviewed surfaces.",
        "reviewed_surfaces": list(SURFACES),
        "unreviewed_surfaces": [],
        "findings": [],
    }


@pytest.fixture
def fake_codex(tmp_path, monkeypatch):
    executable = tmp_path / "codex"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, subprocess, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('codex-cli test'); sys.exit(0)\n"
        "assert '--sandbox' in sys.argv and 'read-only' in sys.argv\n"
        "assert '--ignore-user-config' in sys.argv and '--ignore-rules' in sys.argv\n"
        "assert 'shell_environment_policy.inherit=\"none\"' in sys.argv\n"
        "assert not pathlib.Path('.codex').exists()\n"
        "assert pathlib.Path('source.git/objects').is_dir()\n"
        "context = json.loads(sys.stdin.read().split('Review context:\\n')[1])\n"
        "assert context['baseline_tag'] == 'v0.1.2'\n"
        "assert subprocess.check_output(['git', '--git-dir=source.git', 'rev-list',\n"
        "    '--count', context['baseline_sha'] + '..' + context['candidate_sha']],\n"
        "    text=True).strip() == '2'\n"
        "mode = os.environ.get('FAKE_CODEX_MODE', 'ok')\n"
        "if mode == 'error': sys.exit(7)\n"
        "if mode == 'missing': sys.exit(0)\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        "output.write_text('invalid' if mode == 'malformed' else os.environ['FAKE_REVIEW'])\n"
    )
    executable.chmod(0o755)
    monkeypatch.setenv("NVIDIA_INFERENCE_API_KEY", "fake-key-for-test")
    monkeypatch.setenv("FAKE_REVIEW", json.dumps(review()))
    return str(executable)


def test_cumulative_range_and_stable_retag():
    candidate = resolve_candidate("v0.1.3-pre.2", git("rev-parse", "HEAD"))
    assert candidate["baseline_tag"] == "v0.1.2"
    assert candidate["allows_breaks"] is False
    git("tag", "v0.1.3")
    assert resolve_candidate("v0.1.3", "")["baseline_tag"] == "v0.1.2"


def test_minor_train_and_wrong_source():
    git("tag", "v0.2.0-pre.1")
    assert resolve_candidate("v0.2.0-pre.1", "")["allows_breaks"] is True
    with pytest.raises(ValueError, match="source SHA"):
        resolve_candidate("v0.1.3-pre.2", git("rev-parse", "v0.1.2"))


@pytest.mark.parametrize("tag", ["HEAD", "v0.1.2", "v1.0.0-pre.1"])
def test_missing_baseline_or_unsupported_tag(tag):
    if tag.startswith("v1"):
        git("tag", tag)
    with pytest.raises(ValueError):
        resolve_candidate(tag, "")


def test_runner_retains_report_with_trusted_context(fake_codex, tmp_path):
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", fake_codex)
    assert result["status"] == "complete"
    assert result["context"]["baseline_sha"] == git("rev-parse", "v0.1.2")
    assert result["review"] == review()
    assert (tmp_path / "report" / "report.md").is_file()
    assert json.loads((tmp_path / "report" / "report.json").read_text()) == result


@pytest.mark.parametrize("mode", ["error", "missing", "malformed"])
def test_failed_execution_is_not_a_clean_report(
    fake_codex, tmp_path, monkeypatch, mode
):
    monkeypatch.setenv("FAKE_CODEX_MODE", mode)
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", fake_codex)
    assert result["status"] == "error"
    assert result["review"] is None


def test_incomplete_coverage_is_explicit(fake_codex, tmp_path, monkeypatch):
    partial = review()
    partial["verdict"] = "needs_review"
    partial["unreviewed_surfaces"] = [partial["reviewed_surfaces"].pop()]
    monkeypatch.setenv("FAKE_REVIEW", json.dumps(partial))
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", fake_codex)
    assert result["status"] == "incomplete"
    assert result["review"]["unreviewed_surfaces"]


@pytest.mark.parametrize(
    "change",
    [
        {"reviewed_surfaces": []},
        {"verdict": "pass"},
        {"findings": ["unsupported finding"]},
        {"summary": 42},
    ],
)
def test_rejects_malformed_agent_output(change):
    with pytest.raises(ValueError):
        validate_review(review() | change)


def test_missing_credentials_retains_error_report(tmp_path, monkeypatch):
    monkeypatch.delenv("NVIDIA_INFERENCE_API_KEY", raising=False)
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", "unused-codex")
    assert result["status"] == "error"
    assert "credential" in result["error"]


def test_timeout_retains_error_report(fake_codex, tmp_path, monkeypatch):
    real_run = subprocess.run

    def timeout_review(command, **kwargs):
        if command[:2] == [fake_codex, "exec"]:
            raise subprocess.TimeoutExpired(command, 1800)
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", timeout_review)
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", fake_codex)
    assert result["status"] == "error"
    assert "time limit" in result["error"]


def test_breaking_finding_is_retained(fake_codex, tmp_path, monkeypatch):
    breaking = review()
    breaking["verdict"] = "unaddressed_breaks"
    breaking["findings"] = [
        {
            "surface": "cli",
            "change": "Removed --policy without an alias.",
            "impact": "Existing scripts fail argument parsing.",
            "evidence": "baseline:cli.rs:12; candidate:cli.rs:14",
            "recommendation": "Keep the alias for this patch train.",
        }
    ]
    monkeypatch.setenv("FAKE_REVIEW", json.dumps(breaking))
    result = run_review("v0.1.3-pre.2", "", tmp_path / "report", fake_codex)
    assert result["status"] == "complete"
    assert result["advisory"] is True
    assert result["review"] == breaking
    assert "Existing scripts" in (tmp_path / "report" / "report.md").read_text()
