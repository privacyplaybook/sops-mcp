"""Print the CHANGELOG.md section body for a given version.

Used by the create-release workflow to populate GitHub Release notes from
the hand-written changelog, so the release body always matches CHANGELOG.md
and nothing has to be retyped.

  python3 lib/extract_changelog.py 0.10.1        # -> section body on stdout
  python3 lib/extract_changelog.py v0.10.1       # leading 'v' is tolerated
  python3 lib/extract_changelog.py v0.10.1-rc1   # falls back to the [0.10.1] section

A pre-release / build tag (e.g. 0.10.1-rc1) reuses the base version's
section, since the changelog tracks the final version, not each RC.

Exits non-zero if neither the exact version nor its base has a
`## [x.y.z]` section, so the workflow fails loudly rather than publishing
an empty release.
"""

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def extract(text: str, version: str) -> str | None:
    header = re.compile(r"^## \[([^\]]+)\]")
    lines = text.splitlines()
    body: list[str] | None = None
    for line in lines:
        m = header.match(line)
        if m:
            if body is not None:  # reached the next release -> stop
                break
            if m.group(1) == version:
                body = []
            continue
        if body is not None:
            body.append(line)
    if body is None:
        return None
    return "\n".join(body).strip()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extract_changelog.py <version>", file=sys.stderr)
        return 2
    version = sys.argv[1].lstrip("v")
    text = CHANGELOG.read_text()
    section = extract(text, version)
    if not section:
        # Pre-release/build tag (0.10.1-rc1, 0.10.1+build) -> base version.
        base = re.split(r"[-+]", version, maxsplit=1)[0]
        if base != version:
            section = extract(text, base)
    if not section:
        print(f"ERROR: no CHANGELOG.md section for [{version}]", file=sys.stderr)
        return 1
    print(section)
    return 0


if __name__ == "__main__":
    sys.exit(main())
