"""Tests for the secrets_derive module."""

import hashlib
import re

import pytest

from sops_mcp.secrets_derive import (
    TRANSFORMS,
    derive_secret,
    dependents_of,
    topological_order,
)


def test_sha256_hex_matches_hashlib():
    result = derive_secret("hello world", "sha256_hex")
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert result == expected


def test_pbkdf2_sha512_authelia_format():
    h = derive_secret("my-password", "pbkdf2_sha512_authelia")
    assert re.match(
        r"^\$pbkdf2-sha512\$310000\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", h
    )


def test_unknown_transform_rejected():
    with pytest.raises(ValueError, match="Unknown transform"):
        derive_secret("x", "md5")


def test_pbkdf2_each_call_differs():
    """PBKDF2 uses a random salt, so each call must produce a new hash."""
    a = derive_secret("same-input", "pbkdf2_sha512_authelia")
    b = derive_secret("same-input", "pbkdf2_sha512_authelia")
    assert a != b


def test_sha256_deterministic():
    a = derive_secret("same-input", "sha256_hex")
    b = derive_secret("same-input", "sha256_hex")
    assert a == b


def test_topological_order_simple():
    meta = {
        "A": {"source": "generated"},
        "B": {"source": "external"},
        "C": {
            "source": "derived",
            "derivation": {"from": "A", "transform": "sha256_hex"},
        },
    }
    order = topological_order(meta)
    assert order.index("A") < order.index("C")
    assert "B" in order


def test_topological_order_chain():
    meta = {
        "A": {"source": "generated"},
        "B": {
            "source": "derived",
            "derivation": {"from": "A", "transform": "sha256_hex"},
        },
        "C": {
            "source": "derived",
            "derivation": {"from": "B", "transform": "sha256_hex"},
        },
    }
    order = topological_order(meta)
    assert order.index("A") < order.index("B") < order.index("C")


def test_topological_order_rejects_dangling():
    meta = {
        "A": {
            "source": "derived",
            "derivation": {"from": "NONEXISTENT", "transform": "sha256_hex"},
        },
    }
    with pytest.raises(ValueError, match="Circular or dangling"):
        topological_order(meta)


def test_topological_order_rejects_cycle():
    meta = {
        "A": {
            "source": "derived",
            "derivation": {"from": "B", "transform": "sha256_hex"},
        },
        "B": {
            "source": "derived",
            "derivation": {"from": "A", "transform": "sha256_hex"},
        },
    }
    with pytest.raises(ValueError, match="Circular or dangling"):
        topological_order(meta)


def test_dependents_of():
    meta = {
        "A": {"source": "generated"},
        "B": {
            "source": "derived",
            "derivation": {"from": "A", "transform": "sha256_hex"},
        },
        "C": {"source": "external"},
        "D": {
            "source": "derived",
            "derivation": {"from": "A", "transform": "pbkdf2_sha512_authelia"},
        },
    }
    assert sorted(dependents_of(meta, "A")) == ["B", "D"]
    assert dependents_of(meta, "C") == []


def test_all_transforms_callable():
    for name in TRANSFORMS:
        result = derive_secret("test", name)
        assert isinstance(result, str)
        assert len(result) > 0
