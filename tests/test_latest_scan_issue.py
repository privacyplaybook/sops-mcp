"""lib/latest_scan_issue.py: the scheduled re-scan's single tracking issue."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "latest_scan_issue", ROOT / "lib" / "latest_scan_issue.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lsi = _load()

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
REV = "b6618d96ec3a9e7b2d4009edcd28235e41479e90"
IMAGE = "ghcr.io/privacyplaybook/sops-mcp"
RUN = "https://github.com/privacyplaybook/sops-mcp/actions/runs/1"


def _match(vid, severity, name="zlib", version="1.3", fixed=("1.3.1",)):
    return {
        "vulnerability": {
            "id": vid,
            "severity": severity,
            "fix": {"versions": list(fixed), "state": "fixed"},
        },
        "artifact": {"name": name, "version": version, "type": "apk"},
    }


REPORT = {
    "matches": [
        _match("CVE-2026-0002", "High"),
        _match("CVE-2026-0001", "Critical", name="glibc"),
        _match("CVE-2026-0003", "Medium"),
        _match("CVE-2026-0004", "Unknown"),
        _match("CVE-2026-0002", "High"),  # Grype's duplicate (CPE + apk)
    ]
}


class FakeGitHub:
    """Answers the `gh api` calls the script makes, and records them."""

    def __init__(self, issues=None, label_exists=True):
        self.issues = issues or []
        self.label_exists = label_exists
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        path = next(a for a in args if a.startswith("repos/"))
        fields = {}
        for i, a in enumerate(args):
            if a == "-f":
                key, _, value = args[i + 1].partition("=")
                fields[key] = value
        if path.endswith("/issues") and method == "GET":
            assert fields["labels"] == lsi.LABEL
            assert fields["state"] == "open"
            return self.issues
        if "/labels/" in path:
            if not self.label_exists:
                raise subprocess.CalledProcessError(1, "gh")
            return {"name": lsi.LABEL}
        if path.endswith("/labels"):
            self.label_exists = True
            return {"name": fields["name"]}
        if path.endswith("/issues") and method == "POST":
            return {"number": 99}
        return {}

    def writes(self):
        return [
            (c[c.index("--method") + 1], next(a for a in c if a.startswith("repos/")))
            for c in self.calls
            if "--method" in c and c[c.index("--method") + 1] != "GET"
        ]

    def field(self, method, suffix, key):
        for c in self.calls:
            if "--method" in c and c[c.index("--method") + 1] == method:
                path = next(a for a in c if a.startswith("repos/"))
                if path.endswith(suffix):
                    for i, a in enumerate(c):
                        if a == "-f" and c[i + 1].startswith(key + "="):
                            return c[i + 1].partition("=")[2]
        raise AssertionError(f"no {method} {suffix} {key}")


def _issue(number=7, body="", title=None, pr=False):
    issue = {"number": number, "title": title or lsi.TITLE, "body": body}
    if pr:
        issue["pull_request"] = {}
    return issue


def _rows():
    return lsi.findings_from_report(REPORT, "high")


# --- findings_from_report ----------------------------------------------------


def test_threshold_keeps_high_and_above_sorted_and_deduped():
    rows = _rows()
    assert [(r["id"], r["severity"]) for r in rows] == [
        ("CVE-2026-0001", "Critical"),
        ("CVE-2026-0002", "High"),
    ]
    assert rows[0]["package"] == "glibc"
    assert rows[1]["fixed_in"] == "1.3.1"


def test_threshold_is_case_insensitive_and_inclusive():
    rows = lsi.findings_from_report(REPORT, "MEDIUM")
    assert {r["id"] for r in rows} == {
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    }


def test_unknown_threshold_is_refused():
    with pytest.raises(ValueError, match="unknown severity"):
        lsi.findings_from_report(REPORT, "severe")


def test_empty_report_has_no_rows():
    assert lsi.findings_from_report({"matches": []}, "high") == []
    assert lsi.findings_from_report({}, "high") == []


# --- render_body -------------------------------------------------------------


def test_body_names_the_image_and_carries_the_fingerprint():
    body = lsi.render_body(
        rows=_rows(),
        image=IMAGE,
        digest=DIGEST,
        revision=REV,
        fail_on="high",
        run_url=RUN,
    )
    assert f"{IMAGE}@{DIGEST}" in body
    assert REV in body
    assert RUN in body
    assert "| CVE-2026-0001 | Critical | glibc |" in body
    found = lsi.FINGERPRINT_RE.search(body)
    assert found
    assert found.group(1) == lsi.fingerprint(DIGEST, _rows())


def test_body_cells_cannot_break_the_table_or_mention():
    rows = [
        {
            "id": "CVE|x",
            "severity": "High",
            "package": "@team/pkg`x`",
            "version": "1\n2",
            "type": "npm",
            "fixed_in": "2",
        }
    ]
    body = lsi.render_body(
        rows=rows,
        image=IMAGE,
        digest=DIGEST,
        revision="",
        fail_on="high",
        run_url=RUN,
    )
    line = next(ln for ln in body.splitlines() if ln.startswith("| CVE"))
    assert line.count("|") == 7
    assert "`" not in line
    assert "@team" not in line
    assert "unknown (no revision label)" in body


def test_body_is_capped():
    rows = [
        {
            "id": f"CVE-2026-{i:05d}",
            "severity": "High",
            "package": "p",
            "version": "1",
            "type": "apk",
            "fixed_in": "2",
        }
        for i in range(lsi.MAX_ROWS + 5)
    ]
    body = lsi.render_body(
        rows=rows,
        image=IMAGE,
        digest=DIGEST,
        revision=REV,
        fail_on="high",
        run_url=RUN,
    )
    assert "and 5 more" in body
    assert len(body) < 65536


def test_fingerprint_tracks_digest_and_findings():
    rows = _rows()
    assert lsi.fingerprint(DIGEST, rows) == lsi.fingerprint(DIGEST, list(rows))
    assert lsi.fingerprint(DIGEST, rows) != lsi.fingerprint(OTHER_DIGEST, rows)
    assert lsi.fingerprint(DIGEST, rows) != lsi.fingerprint(DIGEST, rows[:1])


# --- find_open_issue ---------------------------------------------------------


def test_find_skips_prs_and_other_titles():
    gh = FakeGitHub(
        [_issue(1, pr=True), _issue(2, title="Something else"), _issue(3), _issue(4)]
    )
    assert lsi.find_open_issue(gh)["number"] == 3


def test_find_none():
    assert lsi.find_open_issue(FakeGitHub([_issue(2, title="x")])) is None


# --- report_findings ---------------------------------------------------------


def _report(gh, digest=DIGEST):
    return lsi.report_findings(
        gh,
        rows=_rows(),
        image=IMAGE,
        digest=digest,
        revision=REV,
        fail_on="high",
        run_url=RUN,
    )


def test_first_finding_opens_one_labelled_issue():
    gh = FakeGitHub([], label_exists=False)
    assert _report(gh) == "opened #99"
    assert gh.writes() == [
        ("POST", "repos/{owner}/{repo}/labels"),
        ("POST", "repos/{owner}/{repo}/issues"),
    ]
    assert gh.field("POST", "/issues", "title") == lsi.TITLE
    assert gh.field("POST", "/issues", "labels[]") == lsi.LABEL


def test_existing_label_is_not_recreated():
    gh = FakeGitHub([], label_exists=True)
    _report(gh)
    assert ("POST", "repos/{owner}/{repo}/labels") not in gh.writes()


def test_unchanged_findings_update_the_body_without_a_comment():
    body = lsi.render_body(
        rows=_rows(),
        image=IMAGE,
        digest=DIGEST,
        revision=REV,
        fail_on="high",
        run_url="older run",
    )
    gh = FakeGitHub([_issue(7, body=body)])
    assert _report(gh) == "updated #7 (findings unchanged)"
    assert gh.writes() == [("PATCH", "repos/{owner}/{repo}/issues/7")]
    assert RUN in gh.field("PATCH", "/issues/7", "body")


def test_changed_findings_update_and_comment():
    body = lsi.render_body(
        rows=_rows()[:1],
        image=IMAGE,
        digest=DIGEST,
        revision=REV,
        fail_on="high",
        run_url=RUN,
    )
    gh = FakeGitHub([_issue(7, body=body)])
    assert _report(gh) == "updated #7 (findings changed, commented)"
    assert gh.writes() == [
        ("PATCH", "repos/{owner}/{repo}/issues/7"),
        ("POST", "repos/{owner}/{repo}/issues/7/comments"),
    ]


def test_new_digest_comments_even_with_same_findings():
    body = lsi.render_body(
        rows=_rows(),
        image=IMAGE,
        digest=DIGEST,
        revision=REV,
        fail_on="high",
        run_url=RUN,
    )
    gh = FakeGitHub([_issue(7, body=body)])
    assert _report(gh, digest=OTHER_DIGEST).endswith("commented)")


def test_issue_without_fingerprint_gets_a_comment():
    gh = FakeGitHub([_issue(7, body="hand-edited")])
    assert _report(gh).endswith("commented)")


# --- report_clean ------------------------------------------------------------


def test_clean_with_no_issue_writes_nothing():
    gh = FakeGitHub([])
    out = lsi.report_clean(gh, image=IMAGE, digest=DIGEST, revision=REV, run_url=RUN)
    assert out == "clean; no open issue"
    assert gh.writes() == []


def test_clean_closes_the_open_issue_with_a_comment():
    gh = FakeGitHub([_issue(7)])
    out = lsi.report_clean(gh, image=IMAGE, digest=DIGEST, revision=REV, run_url=RUN)
    assert out == "clean; closed #7"
    assert gh.writes() == [
        ("POST", "repos/{owner}/{repo}/issues/7/comments"),
        ("PATCH", "repos/{owner}/{repo}/issues/7"),
    ]
    assert gh.field("PATCH", "/issues/7", "state") == "closed"


# --- main --------------------------------------------------------------------


def _main(tmp_path, *args, report=REPORT, gh=None):
    path = tmp_path / "grype.json"
    path.write_text(json.dumps(report))
    gh = gh if gh is not None else FakeGitHub([])
    argv = ["latest_scan_issue.py", *[str(path) if a == "REPORT" else a for a in args]]
    return lsi.main(argv, api=gh), gh


COMMON = ["--image", IMAGE, "--digest", DIGEST, "--revision", REV, "--run-url", RUN]


def test_main_findings_opens_issue(tmp_path):
    rc, gh = _main(tmp_path, "findings", "REPORT", "--fail-on", "high", *COMMON)
    assert rc == 0
    assert ("POST", "repos/{owner}/{repo}/issues") in gh.writes()


def test_main_findings_with_nothing_at_threshold_fails(tmp_path, capsys):
    report = {"matches": [_match("CVE-2026-0003", "Medium")]}
    rc, gh = _main(
        tmp_path, "findings", "REPORT", "--fail-on", "high", *COMMON, report=report
    )
    assert rc == 1
    assert gh.writes() == []
    assert "no match at or above high" in capsys.readouterr().out


def test_main_findings_without_report_fails(tmp_path):
    rc, gh = _main(tmp_path, "findings", *COMMON)
    assert rc == 1
    assert gh.calls == []


def test_main_refuses_a_non_digest(tmp_path):
    args = ["clean", "--image", IMAGE, "--digest", "latest", "--run-url", RUN]
    rc, gh = _main(tmp_path, *args)
    assert rc == 1
    assert gh.calls == []


def test_main_clean(tmp_path):
    rc, gh = _main(tmp_path, "clean", *COMMON, gh=FakeGitHub([_issue(7)]))
    assert rc == 0
    assert ("PATCH", "repos/{owner}/{repo}/issues/7") in gh.writes()
