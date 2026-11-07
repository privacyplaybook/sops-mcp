"""Verify the Dockerfile base images against base-images.lock.json.

Checks that every FROM line is pinned by digest, and that each pinned
digest is the one base-images.lock.json records for that image (and that
neither side has an image the other lacks). A Dependabot base-image PR
changes only the Dockerfile, so it fails here until the lock is
regenerated with lib/pin_base_images.py.

Optionally runs cosign verification for images recorded as signed
in base-images.lock.json.

This is a CI check — it validates structure and (when cosign is
available) provenance. It does NOT re-resolve digests from registries.
"""

import glob
import json
import os
import re
import subprocess
import sys

FROM_RE = re.compile(
    r"^FROM\s+(\S+)",
    re.IGNORECASE,
)

PINNED_RE = re.compile(r"^(?P<base>[^@]+)@(?P<digest>sha256:[a-f0-9]{64})$")

LOCK_FILE = "base-images.lock.json"
FIX_HINT = (
    "Run 'python3 lib/pin_base_images.py' on this branch and commit the "
    "resulting Dockerfile and base-images.lock.json (see \"Base image "
    "updates from Dependabot\" in README.md)."
)


def find_dockerfiles(root: str) -> list[str]:
    patterns = ["**/Dockerfile", "**/Dockerfile.*", "**/Dockerfile_*"]
    files = set()
    for pattern in patterns:
        files.update(glob.glob(os.path.join(root, pattern), recursive=True))
    return sorted(files)


def check_digest_pins(root: str) -> list[str]:
    """Check all FROM lines have @sha256: digests. Returns list of errors."""
    errors = []
    for df in find_dockerfiles(root):
        relpath = os.path.relpath(df, root)
        with open(df) as f:
            for i, line in enumerate(f, 1):
                m = FROM_RE.match(line)
                if not m:
                    continue
                image_ref = m.group(1)
                # Skip scratch and ARG-based refs
                if image_ref.lower() == "scratch" or image_ref.startswith("$"):
                    continue
                if not PINNED_RE.match(image_ref):
                    errors.append(f"{relpath}:{i}: {image_ref} is not digest-pinned")
    return errors


def check_lock_agreement(root: str) -> list[str]:
    """Check the Dockerfile digests and base-images.lock.json agree.

    Every digest-pinned FROM image must have a lock entry with the same
    digest, and every lock entry must be used by some FROM line. FROM lines
    that are not digest-pinned are left to check_digest_pins. Returns a
    list of errors.
    """
    lock_path = os.path.join(root, LOCK_FILE)
    if not os.path.exists(lock_path):
        return [f"{LOCK_FILE} not found"]
    try:
        with open(lock_path) as f:
            lock_data = json.load(f)
    except (OSError, ValueError) as e:
        return [f"{LOCK_FILE} could not be read: {e}"]
    if not isinstance(lock_data, dict):
        return [f"{LOCK_FILE} is not a JSON object"]

    errors = []
    seen = set()
    for df in find_dockerfiles(root):
        relpath = os.path.relpath(df, root)
        with open(df) as f:
            for i, line in enumerate(f, 1):
                m = FROM_RE.match(line)
                if not m:
                    continue
                image_ref = m.group(1)
                # Same skips as check_digest_pins and pin_base_images.py.
                if image_ref.lower() == "scratch" or image_ref.startswith("$"):
                    continue
                pinned = PINNED_RE.match(image_ref)
                if not pinned:
                    # Unpinned: check_digest_pins reports it. Count the image
                    # as used so its lock entry is not reported a second time.
                    seen.add(image_ref.split("@", 1)[0])
                    continue
                base, digest = pinned.group("base"), pinned.group("digest")
                seen.add(base)
                entry = lock_data.get(base)
                if entry is None:
                    errors.append(
                        f"{relpath}:{i}: {base} is not in {LOCK_FILE}"
                    )
                    continue
                locked = entry.get("digest") if isinstance(entry, dict) else None
                if locked != digest:
                    errors.append(
                        f"{relpath}:{i}: {base} is pinned to {digest}, "
                        f"but {LOCK_FILE} records {locked}"
                    )

    for base in sorted(set(lock_data) - seen):
        errors.append(f"{LOCK_FILE}: {base} is not used by any FROM line")
    return errors


def check_cosign_signatures(root: str) -> list[str]:
    """Verify cosign signatures for images marked as signed in lock file.
    Returns list of warnings (non-fatal)."""
    lock_path = os.path.join(root, "base-images.lock.json")
    if not os.path.exists(lock_path):
        return ["base-images.lock.json not found — skipping cosign checks"]

    # Check if cosign is available
    try:
        subprocess.run(["cosign", "version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ["cosign not available — skipping signature checks"]

    with open(lock_path) as f:
        lock_data = json.load(f)

    warnings = []
    for ref, info in lock_data.items():
        if not info.get("cosign_signed"):
            continue
        digest = info.get("digest")
        if not digest:
            continue

        # Build the full ref for cosign
        parts = ref.split("/")
        if "." not in parts[0] and len(parts) <= 2:
            # Docker Hub image
            repo = ref if "/" in ref else f"library/{ref}"
            cosign_ref = f"docker.io/{repo.split(':')[0]}@{digest}"
        else:
            cosign_ref = f"{ref.split(':')[0]}@{digest}"

        result = subprocess.run(
            [
                "cosign", "verify",
                "--certificate-identity-regexp", ".*",
                "--certificate-oidc-issuer-regexp", ".*",
                cosign_ref,
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            warnings.append(f"Cosign verification FAILED for {ref}: {result.stderr.strip().split(chr(10))[-1]}")
        else:
            print(f"  Cosign OK: {ref}")

    return warnings


def main(root: str | None = None) -> int:
    if root is None:
        root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    os.chdir(root)

    # Check 1: Digest pins (mandatory)
    print("Checking digest pins...")
    errors = check_digest_pins(root)
    if errors:
        for err in errors:
            print(f"  ERROR: {err}")
    else:
        print("  All FROM lines are digest-pinned.")

    # Check 2: Dockerfile digests match the lock (mandatory). The cosign
    # check below verifies the lock's digests, so a stale lock would have
    # it vouch for images the Dockerfile no longer uses.
    print(f"\nChecking Dockerfile digests against {LOCK_FILE}...")
    lock_errors = check_lock_agreement(root)
    if lock_errors:
        for err in lock_errors:
            print(f"  ERROR: {err}")
    else:
        print(f"  Dockerfile digests match {LOCK_FILE}.")

    # Check 3: Cosign signatures (advisory for now)
    print("\nChecking cosign signatures...")
    # Only once the lock agrees: on a malformed lock this would crash, and
    # on a stale one it would verify digests the Dockerfile no longer uses.
    if lock_errors:
        warnings = ["skipped until the Dockerfile and lock agree"]
    else:
        warnings = check_cosign_signatures(root)
    if warnings:
        for w in warnings:
            print(f"  WARNING: {w}")

    if errors or lock_errors:
        print(
            f"\n{len(errors)} digest pin error(s), "
            f"{len(lock_errors)} lock mismatch error(s) found."
        )
        print(FIX_HINT)
        return 1

    print("\nAll base image checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
