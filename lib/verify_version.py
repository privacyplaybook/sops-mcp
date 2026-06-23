"""Keep the project version single-sourced from pyproject.toml.

`pyproject.toml` is the one place a release version is hand-edited. This
script propagates that version into the other committed copy (server.json)
and, in CI, fails if they have drifted.

  python3 lib/verify_version.py            # check (CI gate); exit 1 on drift
  python3 lib/verify_version.py --write    # rewrite server.json to match

Notes:
- src/sops_mcp/__init__.py is NOT checked here: it derives __version__ from
  installed package metadata at runtime, so it can't drift.
- server.json's committed version is also rewritten from the git tag at
  publish time (see publish-mcp-registry.yml). Syncing it here just keeps
  the committed source accurate and reviewable.
- The OCI package identifier (if present) keeps its v-prefixed tag, matching
  how publish.yml tags the GHCR image; only its tag suffix is synced.
"""

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
SERVER_JSON = ROOT / "server.json"


def pyproject_version() -> str:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def synced_server_json(data: dict, version: str) -> dict:
    """Return server.json content with every version field set to `version`."""
    data = json.loads(json.dumps(data))  # deep copy
    data["version"] = version
    for pkg in data.get("packages", []):
        if pkg.get("registryType") == "oci" and ":" in pkg.get("identifier", ""):
            base = pkg["identifier"].split(":", 1)[0]
            pkg["identifier"] = f"{base}:v{version}"
        elif "version" in pkg:
            pkg["version"] = version
    return data


def main() -> int:
    write = "--write" in sys.argv[1:]
    version = pyproject_version()

    current = json.loads(SERVER_JSON.read_text())
    desired = synced_server_json(current, version)

    if current == desired:
        print(f"OK: server.json matches pyproject version {version}")
        return 0

    if write:
        SERVER_JSON.write_text(json.dumps(desired, indent=2) + "\n")
        print(f"Wrote server.json at version {version}")
        return 0

    print(
        f"ERROR: server.json is out of sync with pyproject version {version}.\n"
        f"  Run: python3 lib/verify_version.py --write",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
