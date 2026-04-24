"""Tests for the secrets generator module."""

from sops_mcp.secrets_generator import generate_secret


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
    secret = generate_secret(length=100, charset="alphanumeric", exclude_chars="aeiouAEIOU")
    assert not any(c in "aeiouAEIOU" for c in secret)


def test_uniqueness():
    secrets = {generate_secret() for _ in range(10)}
    assert len(secrets) == 10
