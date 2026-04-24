"""Verify that requirements lockfiles are well-formed and cover all .in sources.

Checks that each .lock.txt:
  1. Exists for its corresponding .in file
  2. Every package in .in appears (by name) in the lockfile
  3. All entries in the lockfile are pinned with == and have --hash lines

This avoids re-running pip-compile (which produces environment-dependent
output) and instead validates the structural integrity of the lockfiles.
"""

import os
import re
import subprocess
import sys

IN_FILES = [
    "requirements.in",
]

# Matches a package pin line like "flask==3.1.3 \"
PIN_RE = re.compile(r"^([a-zA-Z0-9_.-]+)==[\d]")
# Matches a hash line like "    --hash=sha256:abc123..."
HASH_RE = re.compile(r"^\s+--hash=sha256:")


def parse_in_packages(in_file: str) -> list[str]:
    """Extract package names from a .in file (ignoring comments/options)."""
    packages = []
    with open(in_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Extract package name (before any version specifier)
            name = re.split(r"[><=!;\[]", line)[0].strip().lower()
            # Normalize underscores/hyphens
            name = name.replace("-", "_")
            if name:
                packages.append(name)
    return packages


def verify_lockfile(in_file: str) -> tuple[bool, list[str]]:
    """Verify a lockfile's integrity. Returns (ok, list_of_errors)."""
    lock_file = in_file.removesuffix(".in") + ".lock.txt"
    errors = []

    if not os.path.exists(lock_file):
        return False, [f"Missing lockfile: {lock_file}"]

    # Parse the lockfile
    pinned_packages = set()
    has_hash = set()
    current_pkg = None

    with open(lock_file) as f:
        for line in f:
            pin_match = PIN_RE.match(line)
            if pin_match:
                current_pkg = pin_match.group(1).lower().replace("-", "_")
                pinned_packages.add(current_pkg)
            elif HASH_RE.match(line) and current_pkg:
                has_hash.add(current_pkg)

    # Check 1: All packages in .in appear in lockfile
    in_packages = parse_in_packages(in_file)
    for pkg in in_packages:
        if pkg not in pinned_packages:
            errors.append(f"Package '{pkg}' from {in_file} not found in {lock_file}")

    # Check 2: All pinned packages have hashes
    missing_hashes = pinned_packages - has_hash
    if missing_hashes:
        errors.append(f"Packages without hashes: {', '.join(sorted(missing_hashes))}")

    # Check 3: At least one pinned package exists
    if not pinned_packages:
        errors.append(f"No pinned packages found in {lock_file}")

    return len(errors) == 0, errors


def main():
    # Change to repo root
    repo_root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    os.chdir(repo_root)

    failed = []
    for in_file in IN_FILES:
        if not os.path.exists(in_file):
            print(f"  MISSING: {in_file} (skipping)")
            continue
        print(f"Checking {in_file}...")
        ok, errors = verify_lockfile(in_file)
        if ok:
            print(f"  OK")
        else:
            for err in errors:
                print(f"  ERROR: {err}")
            failed.append(in_file)

    if failed:
        print(f"\n{len(failed)} lockfile(s) have issues:")
        for f in failed:
            print(f"  - {f}")
        print("\nRun 'lib/compile_requirements.sh' to regenerate lockfiles.")
        sys.exit(1)

    print("\nAll lockfiles are valid.")


if __name__ == "__main__":
    main()
