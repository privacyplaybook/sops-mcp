"""Tests for the secrets generator module."""

import math
import string

import pytest

from sops_mcp.secrets_generator import (
    CHARSETS,
    MIN_RECOMMENDED_ENTROPY_BITS,
    entropy_bits,
    entropy_warning,
    generate_secret,
)


def test_default_length():
    secret = generate_secret()
    assert len(secret) == 32


def test_custom_length():
    secret = generate_secret(length=16)
    assert len(secret) == 16


def test_alphanumeric_charset():
    secret = generate_secret(length=100, charset="alphanumeric")
    assert all(c.isalnum() for c in secret)


def test_hex_charset():
    secret = generate_secret(length=100, charset="hex")
    assert all(c in "0123456789abcdef" for c in secret)


def test_numeric_charset():
    secret = generate_secret(length=100, charset="numeric")
    assert all(c.isdigit() for c in secret)


def test_exclude_chars():
    secret = generate_secret(
        length=100, charset="alphanumeric", exclude_chars="aeiouAEIOU"
    )
    assert not any(c in "aeiouAEIOU" for c in secret)


def test_uniqueness():
    secrets = {generate_secret() for _ in range(10)}
    assert len(secrets) == 10


# --- Charsets: 'base64' is an alphabet, 'urlsafe' its URL-safe twin (#62) ---

def test_base64_charset_still_works():
    # Existing callers pass 'base64'; its alphabet is unchanged.
    assert CHARSETS["base64"] == string.ascii_letters + string.digits + "+/"
    secret = generate_secret(length=200, charset="base64")
    assert set(secret) <= set(CHARSETS["base64"])


def test_urlsafe_charset_is_the_rfc4648_url_alphabet():
    assert CHARSETS["urlsafe"] == string.ascii_letters + string.digits + "-_"
    secret = generate_secret(length=500, charset="urlsafe")
    assert set(secret) <= set(CHARSETS["urlsafe"])
    assert not set(secret) & set("+/=")


# --- Effective entropy and the weak-secret warning (#62) ---


@pytest.mark.parametrize(
    ("length", "charset", "bits"),
    [
        (1, "numeric", math.log2(10)),
        (16, "hex", 64.0),
        (32, "alphanumeric", 32 * math.log2(62)),
        (10, "base64", 60.0),
        (11, "urlsafe", 66.0),
    ],
)
def test_entropy_bits(length, charset, bits):
    assert entropy_bits(length, charset) == pytest.approx(bits)


def test_entropy_counts_the_alphabet_after_exclusions():
    # 16 hex chars is 64 bits; dropping 8 of the 16 symbols halves it.
    assert entropy_bits(16, "hex", exclude_chars="01234567") == pytest.approx(48)


def test_threshold_is_64_bits():
    assert MIN_RECOMMENDED_ENTROPY_BITS == 64
    assert entropy_warning(16, "hex") is None  # exactly 64 bits
    assert entropy_warning(15, "hex") is not None  # 60 bits


def test_default_parameters_do_not_warn():
    assert entropy_warning(32, "alphanumeric") is None


def test_warning_describes_the_parameters():
    warning = entropy_warning(1, "numeric")
    assert warning is not None
    assert "3 bits" in warning
    assert "1 chars" in warning
    assert "'numeric'" in warning
    assert "64" in warning


def test_exclusions_can_trigger_the_warning():
    assert entropy_warning(16, "hex") is None
    assert entropy_warning(16, "hex", exclude_chars="0") is not None


def test_weak_secret_is_still_generated():
    # A warning, never a refusal: the operator's decision on #62.
    assert len(generate_secret(length=1, charset="numeric")) == 1


def test_entropy_rejects_an_unknown_charset():
    with pytest.raises(ValueError, match="Unknown charset"):
        entropy_bits(10, "nope")


# --- Metadata of the wrong type is a ValueError, not a TypeError (#77) ---


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"charset": ["numeric"]}, "charset must be a string"),
        ({"charset": {"a": 1}}, "charset must be a string"),
        ({"exclude_chars": 123456789.0}, "exclude_chars must be a string"),
        ({"exclude_chars": 12}, "exclude_chars must be a string"),
        ({"exclude_chars": ["a"]}, "exclude_chars must be a string"),
        ({"length": "8"}, "Length must be an integer"),
        ({"length": 8.0}, "Length must be an integer"),
        ({"length": True}, "Length must be an integer"),
    ],
)
def test_wrong_types_are_value_errors(kwargs, match):
    with pytest.raises(ValueError, match=match):
        generate_secret(**kwargs)
    if "length" not in kwargs:
        with pytest.raises(ValueError, match=match):
            entropy_warning(8, **kwargs)
