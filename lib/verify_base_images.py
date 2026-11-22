"""Verify the Dockerfile base images against base-images.lock.json.

Checks that every FROM line is pinned by digest, and that each pinned
digest is the one base-images.lock.json records for that image (and that
neither side has an image the other lacks). A Dependabot base-image PR
changes only the Dockerfile, so it fails here until the lock is
regenerated with lib/pin_base_images.py.

Then verifies, with cosign, that every locked digest is signed by the
identity pinned for its registry (TRUSTED_SIGNERS): for cgr.dev/chainguard,
Chainguard's release workflow. A missing cosign, an unsigned image, a
registry with no pinned signer, or a signature from anyone else fails the
check.

This is a CI check: it validates structure and provenance. It does NOT
re-resolve tags to digests from registries.
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
COSIGN_HINT = (
    "Every base image must verify with cosign against the signer pinned for "
    "its registry (TRUSTED_SIGNERS). Check cosign is on PATH and the "
    "registry is reachable; if the signature itself fails, do not merge: "
    "the image is not the one its publisher signed."
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
                # Same skips as check_digest_pins.
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


# The signer each registry's images must carry, as (certificate identity,
# OIDC issuer). cosign verify takes both exactly, never as regexps, so a
# signature from any other Sigstore identity fails. A base image from a
# registry not listed here is refused: there is no signer to pin it to.
#
# Chainguard's public images are signed keylessly by the release workflow of
# chainguard-images/images on main, through GitHub Actions OIDC. Read from
# the signing certificates of the pinned cgr.dev/chainguard/python digests
# and of the current :latest and :latest-dev (2026-11-22): `cosign verify
# --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'
# <image> | jq '.[].optional | {Issuer, Subject}'`. If Chainguard changes
# its signer, this check fails closed until the pin here is updated.
# The trailing slash keeps cgr.dev/chainguard-private/... and the like out.
TRUSTED_SIGNERS = {
    "cgr.dev/chainguard/": (
        "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    ),
}

COSIGN_TIMEOUT = 60
# The check reaches cgr.dev, Rekor and Sigstore's TUF CDN on every PR, so a
# timeout or other non-signature failure is retried; a signature that
# doesn't match the pinned signer is not.
COSIGN_ATTEMPTS = 3
NO_MATCH = "no matching signatures"
UNSIGNED = "records it as not cosign-signed"


def signer_for(image: str) -> tuple[str, str] | None:
    """The (identity, issuer) an image must be signed by, or None.

    `image` is a fully qualified reference (registry included), with or
    without a tag or digest.
    """
    for prefix, signer in TRUSTED_SIGNERS.items():
        if image.startswith(prefix):
            return signer
    return None


def cosign_verify(image_with_digest: str) -> tuple[bool, str]:
    """Verify `image_with_digest` was signed by its registry's pinned signer.

    Returns (ok, detail). Never raises for a cosign failure: a missing
    cosign, a timeout, an unlisted registry and a wrong signer all come
    back as (False, reason).
    """
    signer = signer_for(image_with_digest)
    if signer is None:
        return False, (
            "no pinned signer for this registry (TRUSTED_SIGNERS in "
            "lib/verify_base_images.py)"
        )
    identity, issuer = signer
    args = [
        "cosign", "verify",
        "--certificate-identity", identity,
        "--certificate-oidc-issuer", issuer,
        image_with_digest,
    ]
    detail = ""
    for _attempt in range(COSIGN_ATTEMPTS):
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=COSIGN_TIMEOUT,
            )
        except FileNotFoundError:
            return False, "cosign not installed"
        except subprocess.TimeoutExpired:
            detail = f"verification timed out after {COSIGN_TIMEOUT}s"
            continue
        if result.returncode == 0:
            # The identity is not in the detail: it is printed, and CodeQL
            # reads the issuer URL as a secret (clear-text logging).
            return True, "verified against the pinned signer"
        lines = result.stderr.strip().splitlines()
        detail = lines[-1] if lines else f"cosign exited {result.returncode}"
        if NO_MATCH in detail:
            # A real answer, not a network blip: the signature is not the
            # pinned signer's, and retrying won't change that.
            break
    return False, detail


def _cosign_ref(ref: str, digest: str) -> str:
    """The fully qualified ref@digest cosign needs for a lock key."""
    parts = ref.split("/")
    if "." not in parts[0] and len(parts) <= 2:
        # Docker Hub image
        repo = ref if "/" in ref else f"library/{ref}"
        return f"docker.io/{repo.split(':')[0]}@{digest}"
    return f"{ref.split(':')[0]}@{digest}"


def check_cosign_signatures(root: str) -> list[str]:
    """Verify every lock entry's digest against its pinned signer.

    Returns a list of errors. Every base image must verify: an entry the
    lock records as unsigned is an error too, so `"cosign_signed": false`
    can't be used to skip the check. Runs only once check_lock_agreement
    has passed, so the lock is a JSON object of entries with digests.
    """
    with open(os.path.join(root, LOCK_FILE)) as f:
        lock_data = json.load(f)

    errors = []
    for ref, info in sorted(lock_data.items()):
        if not info.get("cosign_signed"):
            errors.append(
                f"{ref}: {LOCK_FILE} {UNSIGNED}; every base image must "
                f"carry a signature from its pinned signer"
            )
            continue
        ok, detail = cosign_verify(_cosign_ref(ref, info["digest"]))
        if ok:
            print(f"  Cosign OK: {ref} ({detail})")
        else:
            errors.append(f"{ref}: cosign verification failed: {detail}")
    return errors


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

    # Check 3: Cosign signatures (mandatory). Only once both checks pass:
    # on a malformed lock this would crash, and on a stale lock or an
    # unpinned FROM it would verify digests the Dockerfile does not use.
    print("\nChecking cosign signatures...")
    if errors or lock_errors:
        print("  Skipped until the checks above pass.")
        cosign_errors = []
    else:
        cosign_errors = check_cosign_signatures(root)
        if cosign_errors:
            for err in cosign_errors:
                print(f"  ERROR: {err}")
        else:
            print("  Every base image is signed by its pinned signer.")

    if errors or lock_errors or cosign_errors:
        print(
            f"\n{len(errors)} digest pin error(s), "
            f"{len(lock_errors)} lock mismatch error(s), "
            f"{len(cosign_errors)} signature error(s) found."
        )
        if errors or lock_errors or any(UNSIGNED in e for e in cosign_errors):
            print(FIX_HINT)
        if cosign_errors:
            print(COSIGN_HINT)
        return 1

    print("\nAll base image checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
