"""Verify that all Dockerfile FROM lines are digest-pinned.

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

DIGEST_RE = re.compile(r"@sha256:[a-f0-9]{64}")


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
                if not DIGEST_RE.search(image_ref):
                    errors.append(f"{relpath}:{i}: {image_ref} is not digest-pinned")
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


def main():
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

    # Check 2: Cosign signatures (advisory for now)
    print("\nChecking cosign signatures...")
    warnings = check_cosign_signatures(root)
    if warnings:
        for w in warnings:
            print(f"  WARNING: {w}")

    if errors:
        print(f"\n{len(errors)} digest pin error(s) found.")
        print("Run 'python3 lib/pin_base_images.py' to pin all base images.")
        sys.exit(1)

    print("\nAll base image checks passed.")


if __name__ == "__main__":
    main()
