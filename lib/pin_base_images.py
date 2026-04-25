#!/usr/bin/env python3
"""Pin base Docker images by digest and check cosign signatures.

Finds all Dockerfiles in the repo, resolves the current digest for each
base image tag via the registry v2 API, and rewrites FROM lines to include
@sha256:... digests. Also attempts cosign signature verification for each
image and records the results in base-images.lock.json.

Usage:
    python3 lib/pin_base_images.py          # from repo root
"""

import glob
import json
import os
import re
import subprocess
import sys

import requests

# --- Registry helpers ---

DOCKER_HUB_AUTH = "https://auth.docker.io/token"
DOCKER_HUB_REGISTRY = "https://registry-1.docker.io"
GHCR_AUTH = "https://ghcr.io/token"
GHCR_REGISTRY = "https://ghcr.io"
QUAY_AUTH = "https://quay.io/v2/auth"
QUAY_REGISTRY = "https://quay.io"
CGR_AUTH = "https://cgr.dev/token"
CGR_REGISTRY = "https://cgr.dev"

# Accept headers for manifest list (multi-arch) and single manifest
MANIFEST_ACCEPT = ",".join([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
])


def _parse_image_ref(image_ref: str) -> tuple[str, str, str]:
    """Parse image reference into (registry, repository, tag).

    Returns registry as '' for Docker Hub images.
    """
    # Strip any existing digest
    image_ref = re.sub(r"@sha256:[a-f0-9]+", "", image_ref)

    # Split tag
    if ":" in image_ref.split("/")[-1]:
        base, tag = image_ref.rsplit(":", 1)
    else:
        base, tag = image_ref, "latest"

    # Determine registry
    parts = base.split("/")
    if len(parts) == 1:
        # e.g. "python" -> Docker Hub library image
        return "", f"library/{parts[0]}", tag
    elif "." in parts[0] or ":" in parts[0]:
        # e.g. "ghcr.io/open-webui/open-webui" or "quay.io/jupyter/base-notebook"
        registry = parts[0]
        repo = "/".join(parts[1:])
        return registry, repo, tag
    elif len(parts) == 2 and parts[0] == "docker.io":
        return "", f"library/{parts[1]}" if "/" not in parts[1] else parts[1], tag
    else:
        # e.g. "grafana/grafana" -> Docker Hub non-library image
        return "", "/".join(parts), tag


def _get_token(registry: str, repository: str) -> str:
    """Get an anonymous bearer token for the registry."""
    if registry == "" or registry == "docker.io":
        resp = requests.get(DOCKER_HUB_AUTH, params={
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        })
    elif registry == "ghcr.io":
        resp = requests.get(GHCR_AUTH, params={
            "scope": f"repository:{repository}:pull",
        })
    elif registry == "quay.io":
        resp = requests.get(QUAY_AUTH, params={
            "service": "quay.io",
            "scope": f"repository:{repository}:pull",
        })
    elif registry == "cgr.dev":
        resp = requests.get(CGR_AUTH, params={
            "service": "cgr.dev",
            "scope": f"repository:{repository}:pull",
        })
    else:
        raise ValueError(f"Unknown registry: {registry}")

    resp.raise_for_status()
    return resp.json()["token"]


def _get_registry_url(registry: str) -> str:
    if registry == "" or registry == "docker.io":
        return DOCKER_HUB_REGISTRY
    elif registry == "ghcr.io":
        return GHCR_REGISTRY
    elif registry == "quay.io":
        return QUAY_REGISTRY
    elif registry == "cgr.dev":
        return CGR_REGISTRY
    else:
        raise ValueError(f"Unknown registry: {registry}")


def resolve_digest(image_ref: str) -> str | None:
    """Resolve the manifest digest for an image reference."""
    registry, repo, tag = _parse_image_ref(image_ref)
    token = _get_token(registry, repo)
    registry_url = _get_registry_url(registry)

    resp = requests.head(
        f"{registry_url}/v2/{repo}/manifests/{tag}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": MANIFEST_ACCEPT,
        },
    )
    if resp.status_code != 200:
        # Try GET instead of HEAD (some registries don't support HEAD)
        resp = requests.get(
            f"{registry_url}/v2/{repo}/manifests/{tag}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": MANIFEST_ACCEPT,
            },
        )
    if resp.status_code != 200:
        print(f"  WARNING: Failed to resolve digest for {image_ref}: HTTP {resp.status_code}")
        return None

    digest = resp.headers.get("Docker-Content-Digest")
    if not digest:
        print(f"  WARNING: No Docker-Content-Digest header for {image_ref}")
        return None

    return digest


# --- Cosign verification ---

def check_cosign(image_with_digest: str) -> tuple[bool, str]:
    """Attempt keyless cosign verification. Returns (success, details)."""
    try:
        result = subprocess.run(
            [
                "cosign", "verify",
                "--certificate-identity-regexp", ".*",
                "--certificate-oidc-issuer-regexp", ".*",
                image_with_digest,
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, "keyless verification passed"
        return False, result.stderr.strip().split("\n")[-1] if result.stderr else "unknown error"
    except FileNotFoundError:
        return False, "cosign not installed"
    except subprocess.TimeoutExpired:
        return False, "verification timed out"


# --- Dockerfile processing ---

FROM_RE = re.compile(
    r"^(FROM\s+)"           # FROM keyword
    r"(\S+)"                # image reference
    r"(\s+AS\s+\S+)?"      # optional AS alias
    r"(\s*#.*)?"            # optional comment
    r"\s*$",
    re.IGNORECASE,
)


def find_dockerfiles(root: str) -> list[str]:
    """Find all Dockerfiles in the repo."""
    patterns = ["**/Dockerfile", "**/Dockerfile.*", "**/Dockerfile_*"]
    files = set()
    for pattern in patterns:
        files.update(glob.glob(os.path.join(root, pattern), recursive=True))
    return sorted(files)


def extract_from_refs(dockerfile: str) -> list[tuple[int, str, str]]:
    """Extract (line_number, full_line, image_ref) from FROM lines."""
    results = []
    with open(dockerfile) as f:
        for i, line in enumerate(f.readlines()):
            m = FROM_RE.match(line)
            if m:
                image_ref = m.group(2)
                # Skip scratch and ARG-based refs
                if image_ref.lower() == "scratch" or image_ref.startswith("$"):
                    continue
                results.append((i, line, image_ref))
    return results


def update_dockerfile(dockerfile: str, updates: dict[str, str]):
    """Rewrite FROM lines in a Dockerfile with digest-pinned refs."""
    with open(dockerfile) as f:
        lines = f.readlines()

    changed = False
    for i, line in enumerate(lines):
        m = FROM_RE.match(line)
        if not m:
            continue
        image_ref = m.group(2)
        # Strip existing digest to get the base ref for lookup
        base_ref = re.sub(r"@sha256:[a-f0-9]+", "", image_ref)
        if base_ref in updates:
            digest = updates[base_ref]
            new_ref = f"{base_ref}@{digest}"
            as_clause = m.group(3) or ""
            comment = m.group(4) or ""
            new_line = f"{m.group(1)}{new_ref}{as_clause}{comment}\n"
            if lines[i] != new_line:
                lines[i] = new_line
                changed = True

    if changed:
        with open(dockerfile, "w") as f:
            f.writelines(lines)

    return changed


# --- Main ---

def main():
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    os.chdir(root)

    dockerfiles = find_dockerfiles(root)
    print(f"Found {len(dockerfiles)} Dockerfiles\n")

    # Collect unique image refs
    all_refs: dict[str, list[str]] = {}  # base_ref -> [dockerfiles]
    for df in dockerfiles:
        for _, _, image_ref in extract_from_refs(df):
            base_ref = re.sub(r"@sha256:[a-f0-9]+", "", image_ref)
            all_refs.setdefault(base_ref, []).append(os.path.relpath(df, root))

    print(f"Found {len(all_refs)} unique base images:\n")

    # Resolve digests and check cosign
    lock_data = {}
    updates = {}

    for ref, used_in in sorted(all_refs.items()):
        print(f"  {ref}")
        print(f"    Used in: {', '.join(used_in)}")

        digest = resolve_digest(ref)
        if digest:
            print(f"    Digest: {digest}")
            updates[ref] = digest

            # Determine full image ref for cosign (need registry prefix for Docker Hub)
            registry, repo, tag = _parse_image_ref(ref)
            if registry:
                cosign_ref = f"{registry}/{repo}@{digest}"
            else:
                cosign_ref = f"docker.io/{repo}@{digest}"

            cosign_ok, cosign_detail = check_cosign(cosign_ref)
            status = "signed" if cosign_ok else "unsigned"
            print(f"    Cosign: {status} ({cosign_detail})")

            lock_data[ref] = {
                "digest": digest,
                "cosign_signed": cosign_ok,
                "cosign_detail": cosign_detail,
                "used_in": used_in,
            }
        else:
            print(f"    Digest: FAILED TO RESOLVE")
            lock_data[ref] = {
                "digest": None,
                "cosign_signed": False,
                "cosign_detail": "digest resolution failed",
                "used_in": used_in,
            }
        print()

    # Update Dockerfiles
    print("Updating Dockerfiles...")
    for df in dockerfiles:
        relpath = os.path.relpath(df, root)
        if update_dockerfile(df, updates):
            print(f"  Updated: {relpath}")
        else:
            print(f"  No changes: {relpath}")

    # Write lock file
    lock_path = os.path.join(root, "base-images.lock.json")
    with open(lock_path, "w") as f:
        json.dump(lock_data, f, indent=2, sort_keys=True)
    print(f"\nWrote {lock_path}")

    # Summary
    total = len(lock_data)
    pinned = sum(1 for v in lock_data.values() if v["digest"])
    signed = sum(1 for v in lock_data.values() if v["cosign_signed"])
    print(f"\nSummary: {pinned}/{total} pinned, {signed}/{total} cosign verified")

    if pinned < total:
        print("WARNING: Some images could not be pinned!")
        sys.exit(1)


if __name__ == "__main__":
    main()
