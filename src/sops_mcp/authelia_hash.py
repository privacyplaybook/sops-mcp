"""Authelia PBKDF2-SHA512 password hashing with adapted base64 encoding."""

import base64
import hashlib
import os


def _adapted_b64encode(data: bytes) -> str:
    """Encode bytes using passlib's adapted base64 (no padding, + replaced with .)."""
    return base64.b64encode(data).decode().rstrip("=").replace("+", ".")


def generate_authelia_pbkdf2_hash(password: str) -> str:
    """Generate a PBKDF2-SHA512 hash in Authelia's expected format.

    Args:
        password: The plaintext password to hash.

    Returns:
        Hash string in format: $pbkdf2-sha512$310000$<salt_ab64>$<hash_ab64>
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 310000, dklen=64)
    return f"$pbkdf2-sha512$310000${_adapted_b64encode(salt)}${_adapted_b64encode(dk)}"
