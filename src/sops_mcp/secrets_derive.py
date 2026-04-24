"""Derive secrets by applying transforms to other secrets.

A `derived` secret is computed from another secret in the same file via a
named transform (e.g. a PBKDF2 hash of a password). The transform is recorded
in `_meta_unencrypted`, so the derived value is automatically recomputed when
the source secret is rotated.
"""

import hashlib
from collections.abc import Callable

from .authelia_hash import generate_authelia_pbkdf2_hash


def _sha256_hex(source: str) -> str:
    return hashlib.sha256(source.encode()).hexdigest()


TRANSFORMS: dict[str, dict] = {
    "pbkdf2_sha512_authelia": {
        "fn": generate_authelia_pbkdf2_hash,
        "description": "PBKDF2-SHA512 hash in Authelia configuration format",
        "deterministic": False,
    },
    "sha256_hex": {
        "fn": _sha256_hex,
        "description": "Hex-encoded SHA-256 digest",
        "deterministic": True,
    },
}

VALID_TRANSFORMS = tuple(TRANSFORMS.keys())


def derive_secret(source_value: str, transform: str) -> str:
    """Apply the named transform to a source value.

    Args:
        source_value: Plaintext value of the source secret.
        transform: Name of the transform (must be in TRANSFORMS).

    Returns:
        The derived value.

    Raises:
        ValueError: If transform is not recognized.
    """
    spec = TRANSFORMS.get(transform)
    if spec is None:
        raise ValueError(
            f"Unknown transform {transform!r}. "
            f"Valid options: {', '.join(sorted(TRANSFORMS))}"
        )
    fn: Callable[[str], str] = spec["fn"]
    return fn(source_value)


def topological_order(meta_secrets: dict) -> list[str]:
    """Return secret keys in dependency order: non-derived first, then
    derived in order such that each derived key's source already precedes it.

    Raises ValueError on circular or dangling references.
    """
    pending: dict[str, str] = {}
    ordered: list[str] = []
    seen: set[str] = set()

    for key, meta in meta_secrets.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("source") == "derived":
            derivation = meta.get("derivation") or {}
            source_key = derivation.get("from")
            if not source_key:
                raise ValueError(
                    f"Derived secret {key!r} has no 'from' reference"
                )
            pending[key] = source_key
        else:
            ordered.append(key)
            seen.add(key)

    while pending:
        progressed = False
        for key in list(pending):
            if pending[key] in seen:
                ordered.append(key)
                seen.add(key)
                del pending[key]
                progressed = True
        if not progressed:
            raise ValueError(
                "Circular or dangling derivations: "
                + ", ".join(
                    f"{k}->{src}" for k, src in pending.items()
                )
            )

    return ordered


def dependents_of(meta_secrets: dict, source_key: str) -> list[str]:
    """Return keys of derived secrets that reference source_key."""
    return [
        key
        for key, meta in meta_secrets.items()
        if isinstance(meta, dict)
        and meta.get("source") == "derived"
        and (meta.get("derivation") or {}).get("from") == source_key
    ]
