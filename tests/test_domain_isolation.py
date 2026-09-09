"""Integration tests for per-domain key isolation.

These exercise the real sops CLI. They are the tests that matter most in
this change: they assert that a domain can decrypt only what it was
encrypted to, and that no key reachable through the ambient environment
can widen that.
"""

import os
import subprocess

import pytest

from sops_mcp.domains import Domain
from sops_mcp.sops import SopsEncryptor, SopsError, recipients_of


def _require(binary: str) -> None:
    if subprocess.run(["which", binary], capture_output=True).returncode != 0:
        pytest.skip(f"{binary} not installed")


def _keypair() -> tuple[str, str]:
    out = subprocess.run(
        ["age-keygen"], capture_output=True, text=True, check=True
    ).stdout
    ident = next(
        line.strip() for line in out.splitlines() if line.startswith("AGE-SECRET-KEY-")
    )
    pub = subprocess.run(
        ["age-keygen", "-y"], input=ident, capture_output=True, text=True, check=True
    ).stdout.strip()
    return ident, pub


@pytest.fixture
def two_domains():
    _require("sops")
    _require("age-keygen")
    ident_a, pub_a = _keypair()
    ident_b, pub_b = _keypair()
    return (
        Domain(name="alpha", recipients=(pub_a,), keys=(ident_a,)),
        Domain(name="beta", recipients=(pub_b,), keys=(ident_b,)),
    )


@pytest.fixture
def encryptor():
    return SopsEncryptor()


PAYLOAD = {"API_TOKEN": "s3cr3t-value", "_meta_unencrypted": {"version": 1}}


def test_round_trip_within_a_domain(encryptor, two_domains):
    alpha, _ = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    assert "s3cr3t-value" not in blob
    assert encryptor.decrypt(blob, alpha)["API_TOKEN"] == "s3cr3t-value"


def test_other_domain_cannot_decrypt(encryptor, two_domains):
    """The core isolation property."""
    alpha, beta = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    with pytest.raises(SopsError, match="sops decrypt failed"):
        encryptor.decrypt(blob, beta)


def test_ambient_sops_age_key_is_ignored(encryptor, two_domains, monkeypatch):
    """A key in the parent environment must not widen a domain's reach.

    Before domains, sops inherited SOPS_AGE_KEY from the server process, so
    whatever was in it could decrypt anything.
    """
    alpha, beta = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    monkeypatch.setenv("SOPS_AGE_KEY", alpha.keys[0])
    with pytest.raises(SopsError, match="sops decrypt failed"):
        encryptor.decrypt(blob, beta)


def test_ambient_key_file_is_ignored(encryptor, two_domains, monkeypatch, tmp_path):
    alpha, beta = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    keyfile = tmp_path / "keys.txt"
    keyfile.write_text(alpha.keys[0] + "\n")
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(keyfile))
    with pytest.raises(SopsError, match="sops decrypt failed"):
        encryptor.decrypt(blob, beta)


def test_default_age_keys_file_is_ignored(encryptor, two_domains, monkeypatch, tmp_path):
    """sops falls back to ~/.config/sops/age/keys.txt when no env key is set.

    The scratch HOME handed to each invocation is what closes that path.
    """
    alpha, beta = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)

    fake_home = tmp_path / "home"
    keydir = fake_home / ".config" / "sops" / "age"
    keydir.mkdir(parents=True)
    (keydir / "keys.txt").write_text(alpha.keys[0] + "\n")
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(fake_home / ".config"))

    with pytest.raises(SopsError, match="sops decrypt failed"):
        encryptor.decrypt(blob, beta)


def test_default_age_keys_file_would_otherwise_have_worked(tmp_path, monkeypatch):
    """Control for the previous test: prove the planted key really is usable.

    Without this, that test could pass because the key file was malformed
    rather than because the isolation worked.
    """
    _require("sops")
    _require("age-keygen")
    ident, pub = _keypair()
    encryptor = SopsEncryptor()
    domain = Domain(name="alpha", recipients=(pub,), keys=(ident,))
    blob = encryptor.encrypt(PAYLOAD, domain)

    fake_home = tmp_path / "home"
    keydir = fake_home / ".config" / "sops" / "age"
    keydir.mkdir(parents=True)
    (keydir / "keys.txt").write_text(ident + "\n")

    # Invoke sops directly, the way it behaved before this change.
    target = tmp_path / "secrets.enc.yaml"
    target.write_text(blob)
    env = dict(os.environ)
    env.pop("SOPS_AGE_KEY", None)
    env["HOME"] = str(fake_home)
    env["XDG_CONFIG_HOME"] = str(fake_home / ".config")
    result = subprocess.run(
        ["sops", "decrypt", "--input-type", "yaml", "--output-type", "yaml", str(target)],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "s3cr3t-value" in result.stdout


def test_encrypt_only_domain_refuses_to_decrypt(encryptor, two_domains):
    alpha, _ = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    encrypt_only = Domain(name="archive", recipients=alpha.recipients)
    with pytest.raises(SopsError, match="no private key configured"):
        encryptor.decrypt(blob, encrypt_only)


def test_multi_recipient_encrypt_readable_by_each(encryptor, two_domains):
    """A two-recipient domain produces a file either key can open."""
    alpha, beta = two_domains
    shared = Domain(
        name="shared",
        recipients=alpha.recipients + beta.recipients,
        keys=alpha.keys,
    )
    blob = encryptor.encrypt(PAYLOAD, shared)
    assert len(recipients_of(blob)) == 2

    for holder in (alpha, beta):
        solo = Domain(name="shared", recipients=shared.recipients, keys=holder.keys)
        assert encryptor.decrypt(blob, solo)["API_TOKEN"] == "s3cr3t-value"


def test_recipients_of_reads_envelope_without_a_key(encryptor, two_domains):
    alpha, _ = two_domains
    blob = encryptor.encrypt(PAYLOAD, alpha)
    assert recipients_of(blob) == alpha.recipients


def test_recipients_of_rejects_non_sops_content():
    with pytest.raises(SopsError, match="no 'sops' metadata block"):
        recipients_of("KEY: value\n")


def test_recipients_of_rejects_invalid_yaml():
    with pytest.raises(SopsError, match="not valid YAML"):
        recipients_of("key: [unclosed\n")


def test_scratch_dirs_are_cleaned_up(encryptor, two_domains):
    alpha, _ = two_domains
    before = set(os.listdir("/dev/shm")) if os.path.isdir("/dev/shm") else set()
    blob = encryptor.encrypt(PAYLOAD, alpha)
    encryptor.decrypt(blob, alpha)
    after = set(os.listdir("/dev/shm")) if os.path.isdir("/dev/shm") else set()
    assert not {d for d in after - before if d.startswith("sops-mcp-")}


def test_unencrypted_metadata_is_covered_by_the_mac(encryptor, two_domains):
    """sops MACs unencrypted values too, so tampering is caught on decrypt.

    This is not a sops feature the server opts into — it is the default,
    and `--mac-only-encrypted` would turn it off. The assertion exists so
    that adding that flag cannot silently make the `_meta_unencrypted`
    block forgeable. Note the MAC is only checked when decrypting: tools
    that read metadata without a key still see unauthenticated data, which
    is why mutations verify recipients before trusting the recorded domain.
    """
    alpha, _ = two_domains
    blob = encryptor.encrypt(
        {
            "TOKEN": "v",
            "_meta_unencrypted": {
                "version": 1,
                "domain": "alpha",
                "secrets": {"TOKEN": {"source": "generated"}},
            },
        },
        alpha,
    )
    assert encryptor.decrypt(blob, alpha)["TOKEN"] == "v"

    for original, replacement in [
        ("domain: alpha", "domain: beta"),
        ("source: generated", "source: external"),
    ]:
        tampered = blob.replace(original, replacement)
        assert tampered != blob
        with pytest.raises(SopsError, match="MAC mismatch"):
            encryptor.decrypt(tampered, alpha)
