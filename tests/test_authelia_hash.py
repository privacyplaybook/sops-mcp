"""Tests for the Authelia PBKDF2-SHA512 hash generation."""

import base64
import hashlib
import re

from sops_mcp.authelia_hash import generate_authelia_pbkdf2_hash


def test_hash_format():
    h = generate_authelia_pbkdf2_hash("test-password")
    assert re.match(r"^\$pbkdf2-sha512\$310000\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", h)


def test_hash_verifies():
    password = "my-secret-password"
    h = generate_authelia_pbkdf2_hash(password)
    parts = h.split("$")
    # parts: ['', 'pbkdf2-sha512', '310000', '<salt>', '<hash>']
    salt_ab64 = parts[3]
    hash_ab64 = parts[4]

    # Reverse adapted base64: replace . with + and add padding
    salt_b64 = salt_ab64.replace(".", "+")
    salt_b64 += "=" * (-len(salt_b64) % 4)
    salt = base64.b64decode(salt_b64)

    hash_b64 = hash_ab64.replace(".", "+")
    hash_b64 += "=" * (-len(hash_b64) % 4)
    expected_hash = base64.b64decode(hash_b64)

    derived = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 310000, dklen=64)
    assert derived == expected_hash


def test_adapted_base64_no_padding_or_plus():
    h = generate_authelia_pbkdf2_hash("test")
    parts = h.split("$")
    salt_ab64 = parts[3]
    hash_ab64 = parts[4]
    assert "=" not in salt_ab64
    assert "+" not in salt_ab64
    assert "=" not in hash_ab64
    assert "+" not in hash_ab64


def test_different_passwords_produce_different_hashes():
    h1 = generate_authelia_pbkdf2_hash("password-one")
    h2 = generate_authelia_pbkdf2_hash("password-two")
    assert h1 != h2


def test_salt_is_16_bytes():
    h = generate_authelia_pbkdf2_hash("test")
    salt_ab64 = h.split("$")[3]
    salt_b64 = salt_ab64.replace(".", "+")
    salt_b64 += "=" * (-len(salt_b64) % 4)
    salt = base64.b64decode(salt_b64)
    assert len(salt) == 16
