#!/usr/bin/env python3
"""Open, update or close the issue for the scheduled re-scan of `:latest`.

Run by .github/workflows/rescan-latest.yml, in a job that holds
`issues: write` and nothing else, after the scan job (which holds no write
token) has scanned the published image with .github/actions/image-scan.

One issue, never one per run: it is the oldest open issue carrying LABEL
that the script wrote (TITLE, or its fingerprint marker in the body, so a
retitle doesn't lose it and an issue someone else labelled is never touched). On
findings it is created, or its body is replaced with the
current findings; a comment is added only when the findings or the image
digest changed since the body was last written (a hidden fingerprint in the
body says what it held), so a daily run doesn't add a daily comment. On a
clean scan an open issue is closed with a comment naming the clean image.

    latest_scan_issue.py findings <grype.json> --image REF --digest D \\
        --revision SHA --fail-on high --run-url URL
    latest_scan_issue.py clean --image REF --digest D --revision SHA \\
        --run-url URL

GitHub is reached through `gh api` (GH_TOKEN and GH_REPO from the
environment). Standard library only: the runner's system Python runs it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

TITLE = "Published :latest image has fixable vulnerabilities"
LABEL = "scheduled-image-scan"
LABEL_COLOR = "b60205"
LABEL_DESCRIPTION = "Opened and closed by the scheduled re-scan of :latest"

SEVERITIES = ["negligible", "low", "medium", "high", "critical"]

# Issue bodies are capped at 65536 characters; stay well under it, by rows,
# by cell and by total length.
MAX_ROWS = 200
MAX_CELL = 120
MAX_BODY = 60000

FINGERPRINT_RE = re.compile(r"<!-- rescan-latest:fingerprint ([0-9a-f]{64}) -->")

# gh api <args...> -> parsed JSON (None for an empty response).
Api = Callable[..., Any]


def severity_rank(severity: str) -> int:
    """Rank of a Grype severity; -1 for Unknown or anything unexpected."""
    try:
        return SEVERITIES.index(severity.strip().lower())
    except ValueError:
        return -1


def findings_from_report(report: dict[str, Any], fail_on: str) -> list[dict[str, str]]:
    """The report's matches at or above `fail_on`, one row each, sorted.

    The report is Grype's JSON after --only-fixed and the .grype.yaml
    allowlist, so `matches` already excludes what those drop; this keeps
    only the severities that fail the scan.
    """
    threshold = severity_rank(fail_on)
    if threshold < 0:
        raise ValueError(f"unknown severity threshold: {fail_on!r}")
    rows = []
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        severity = str(vuln.get("severity") or "Unknown")
        if severity_rank(severity) < threshold:
            continue
        fixed = (vuln.get("fix") or {}).get("versions") or []
        rows.append(
            {
                "id": str(vuln.get("id") or "?"),
                "severity": severity,
                "package": str(artifact.get("name") or "?"),
                "version": str(artifact.get("version") or "?"),
                "type": str(artifact.get("type") or "?"),
                "fixed_in": ", ".join(str(v) for v in fixed) or "?",
            }
        )
    # Highest severity first, then by id and package, so the body (and its
    # fingerprint) doesn't depend on Grype's ordering.
    rows.sort(key=lambda r: (-severity_rank(r["severity"]), r["id"], r["package"]))
    # Dedupe: Grype can match one vulnerability to one package twice (by
    # CPE and by package-manager data).
    unique: list[dict[str, str]] = []
    for row in rows:
        if row not in unique:
            unique.append(row)
    return unique


def fingerprint(digest: str, rows: list[dict[str, str]]) -> str:
    """What the issue's comments track: the image and its findings."""
    data = json.dumps({"digest": digest, "rows": rows}, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


# Never cut: the vulnerability and the version that fixes it are what the
# reader acts on. MAX_BODY still bounds the total.
UNCAPPED = ("id", "fixed_in")


def _cell(text: str, cap: bool = True) -> str:
    """A Markdown table cell: no pipes, no newlines, no backticks, no
    mentions (Grype's data comes from the image and its DB)."""
    text = text.replace("|", "/").replace("`", "'").replace("@", "@\u200b")
    text = " ".join(text.split())
    if not cap or len(text) <= MAX_CELL:
        return text
    return text[: MAX_CELL - 1] + "…"


def render_body(
    *,
    rows: list[dict[str, str]],
    image: str,
    digest: str,
    revision: str,
    fail_on: str,
    run_url: str,
) -> str:
    lines = [
        f"<!-- rescan-latest:fingerprint {fingerprint(digest, rows)} -->",
        (
            "The scheduled re-scan (`.github/workflows/rescan-latest.yml`) found "
            f"fixable vulnerabilities of severity **{_cell(fail_on)}** or above in "
            "the published image. The same threshold and allowlist (`.grype.yaml`) "
            "as the `image-scan` gate apply, so the next publish would fail too."
        ),
        "",
        f"- Image: `{_cell(image)}@{_cell(digest)}`",
        f"- Built from: {_cell(revision) or 'unknown (no revision label)'}",
        f"- Latest run: {run_url}",
        "",
        "| Vulnerability | Severity | Package | Installed | Fixed in | Type |",
        "|---|---|---|---|---|---|",
    ]
    shown = 0
    length = sum(len(line) + 1 for line in lines)
    for row in rows[:MAX_ROWS]:
        line = (
            "| "
            + " | ".join(
                _cell(row[k], cap=k not in UNCAPPED)
                for k in ("id", "severity", "package", "version", "fixed_in", "type")
            )
            + " |"
        )
        if length + len(line) + 1 > MAX_BODY:
            break
        lines.append(line)
        length += len(line) + 1
        shown += 1
    if len(rows) > shown:
        lines += ["", f"…and {len(rows) - shown} more: see the run's summary."]
    lines += [
        "",
        (
            "Fix by rebuilding on a patched base or lock (Dependabot's base-digest "
            "and lockfile bumps, or `lib/pin_base_images.py`), or, if a finding is "
            "genuinely not exploitable here, an `ignore:` rule with a reason in "
            "`.grype.yaml`. This issue is updated by each scheduled run and closed "
            "by the first clean one. Closing it by hand doesn't stick: while the "
            "finding stands, the next run opens a new one, so accept a finding "
            "with an `ignore:` rule instead."
        ),
    ]
    return "\n".join(lines) + "\n"


def is_ours(issue: dict[str, Any]) -> bool:
    """An issue this script wrote: its fingerprint marker in the body, or
    its title. A retitled issue keeps the marker; an issue someone else
    labelled has neither, and is never overwritten or closed."""
    return issue.get("title") == TITLE or bool(
        FINGERPRINT_RE.search(issue.get("body") or "")
    )


def open_issues(api: Api) -> list[dict[str, Any]]:
    """Every open issue (not PR) carrying LABEL that this script wrote,
    oldest first."""
    issues = api(
        "--method",
        "GET",
        "repos/{owner}/{repo}/issues",
        "-f",
        f"labels={LABEL}",
        "-f",
        "state=open",
        "-f",
        "per_page=100",
        "-f",
        "sort=created",
        "-f",
        "direction=asc",
    )
    return [i for i in issues or [] if "pull_request" not in i and is_ours(i)]


def find_open_issue(api: Api) -> dict[str, Any] | None:
    """The tracking issue: the oldest open one of ours carrying LABEL."""
    issues = open_issues(api)
    return issues[0] if issues else None


def ensure_label(api: Api) -> None:
    try:
        api("repos/{owner}/{repo}/labels/" + LABEL)
    except subprocess.CalledProcessError as err:
        # Only a 404 means missing; anything else (5xx, rate limit) is raised
        # as itself, not as a misleading 422 from creating a label that exists.
        if "HTTP 404" not in (err.stderr or ""):
            raise
        api(
            "--method",
            "POST",
            "repos/{owner}/{repo}/labels",
            "-f",
            f"name={LABEL}",
            "-f",
            f"color={LABEL_COLOR}",
            "-f",
            f"description={LABEL_DESCRIPTION}",
        )


def report_findings(
    api: Api,
    *,
    rows: list[dict[str, str]],
    image: str,
    digest: str,
    revision: str,
    fail_on: str,
    run_url: str,
) -> str:
    """Create or update the issue. Returns what it did, for the log."""
    body = render_body(
        rows=rows,
        image=image,
        digest=digest,
        revision=revision,
        fail_on=fail_on,
        run_url=run_url,
    )
    issue = find_open_issue(api)
    if issue is None:
        ensure_label(api)
        created = api(
            "--method",
            "POST",
            "repos/{owner}/{repo}/issues",
            "-f",
            f"title={TITLE}",
            "-f",
            f"body={body}",
            "-f",
            f"labels[]={LABEL}",
        )
        return f"opened #{created['number']}"
    number = issue["number"]
    old = FINGERPRINT_RE.search(issue.get("body") or "")
    new = fingerprint(digest, rows)
    api(
        "--method",
        "PATCH",
        f"repos/{{owner}}/{{repo}}/issues/{number}",
        "-f",
        f"body={body}",
    )
    if old and old.group(1) == new:
        return f"updated #{number} (findings unchanged)"
    api(
        "--method",
        "POST",
        f"repos/{{owner}}/{{repo}}/issues/{number}/comments",
        "-f",
        f"body=The findings changed: {len(rows)} at or above {fail_on} in "
        f"`{_cell(image)}@{_cell(digest)}` ({run_url}). The issue body is current.",
    )
    return f"updated #{number} (findings changed, commented)"


def report_clean(
    api: Api, *, image: str, digest: str, revision: str, run_url: str
) -> str:
    issues = open_issues(api)
    if not issues:
        return "clean; no open issue"
    for issue in issues:
        _close(
            api,
            issue["number"],
            image=image,
            digest=digest,
            revision=revision,
            run_url=run_url,
        )
    return "clean; closed " + ", ".join(f"#{i['number']}" for i in issues)


def _close(
    api: Api, number: int, *, image: str, digest: str, revision: str, run_url: str
) -> None:
    # Close first: a failed close leaves no "Closing." comment behind to be
    # repeated by every later clean run.
    api(
        "--method",
        "PATCH",
        f"repos/{{owner}}/{{repo}}/issues/{number}",
        "-f",
        "state=closed",
        "-f",
        "state_reason=completed",
    )
    api(
        "--method",
        "POST",
        f"repos/{{owner}}/{{repo}}/issues/{number}/comments",
        "-f",
        f"body=The scheduled re-scan of `{_cell(image)}@{_cell(digest)}` "
        f"(built from {_cell(revision) or 'unknown'}) is clean: {run_url}. "
        "Closed.",
    )


def gh_api(*args: str) -> Any:
    # Fixed argv (no shell), gh from the runner's PATH.
    cmd = ["gh", "api", *args]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def main(argv: list[str], api: Api = gh_api) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("result", choices=["findings", "clean"])
    parser.add_argument("report", nargs="?", type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--revision", default="")
    parser.add_argument("--fail-on", default="high")
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args(argv[1:])
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest):
        print(f"::error::not an image digest: {args.digest!r}")
        return 1
    if args.result == "clean":
        print(
            report_clean(
                api,
                image=args.image,
                digest=args.digest,
                revision=args.revision,
                run_url=args.run_url,
            )
        )
        return 0
    if args.report is None:
        print("::error::findings needs the Grype JSON report")
        return 1
    rows = findings_from_report(json.loads(args.report.read_text()), args.fail_on)
    if not rows:
        # The scan said findings; an empty table would be a contradiction
        # (a severity Grype ranks differently from this script). Fail loudly
        # rather than file an issue with nothing in it.
        print(f"::error::the report has no match at or above {args.fail_on}")
        return 1
    print(
        report_findings(
            api,
            rows=rows,
            image=args.image,
            digest=args.digest,
            revision=args.revision,
            fail_on=args.fail_on,
            run_url=args.run_url,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
