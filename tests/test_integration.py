"""End-to-end integration tests exercising the real sops CLI with a
throwaway age keypair. Requires `sops` and `age-keygen` on PATH.
"""

import hashlib
import subprocess

import pytest
import yaml

from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor


def _require(binary: str) -> None:
    if subprocess.run(["which", binary], capture_output=True).returncode != 0:
        pytest.skip(f"{binary} not installed")


@pytest.fixture
def age_keys(tmp_path, monkeypatch):
    _require("sops")
    _require("age-keygen")
    key_file = tmp_path / "age.key"
    subprocess.run(
        ["age-keygen", "-o", str(key_file)],
        capture_output=True, text=True, check=True,
    )
    private_key = None
    public_key = None
    for line in key_file.read_text().splitlines():
        line = line.strip()
        if line.startswith("AGE-SECRET-KEY-"):
            private_key = line
        elif line.startswith("# public key: "):
            public_key = line.split(": ", 1)[1]
    assert private_key and public_key
    monkeypatch.setenv("SOPS_AGE_KEY", private_key)
    monkeypatch.setenv("SOPS_MCP_AGE_PUBLIC_KEY", public_key)
    return public_key


@pytest.fixture
def server(age_keys):
    return SopsMcpServer(SopsEncryptor(age_keys))


async def test_full_lifecycle(server):
    # 1. Create with generated + external + derived (sha256_hex)
    result = await server._create_secrets({
        "secrets": [
            {"key_name": "DB_PASSWORD", "source": "generated", "length": 32},
            {
                "key_name": "SMTP_USER",
                "source": "external",
                "value": "user@example.com",
            },
            {
                "key_name": "DB_PASSWORD_HASH",
                "source": "derived",
                "transform": "sha256_hex",
                "from": "DB_PASSWORD",
            },
        ]
    })
    encrypted = result[0].text
    values = server.encryptor.decrypt(encrypted)
    assert len(values["DB_PASSWORD"]) == 32
    assert values["SMTP_USER"] == "user@example.com"
    assert values["DB_PASSWORD_HASH"] == hashlib.sha256(
        values["DB_PASSWORD"].encode()
    ).hexdigest()

    # 2. List without decryption
    listed = await server._list_secrets({"encrypted_content": encrypted})
    listing = listed[0].text
    assert "DB_PASSWORD" in listing
    assert "SMTP_USER" in listing
    assert "derived" in listing

    # 3. Rotate — generated changes, derived cascades, external preserved
    rotated_result = await server._rotate_generated(
        {"encrypted_content": encrypted}
    )
    rotated = rotated_result[0].text
    values_before = values
    values_after = server.encryptor.decrypt(rotated)
    assert values_after["DB_PASSWORD"] != values_before["DB_PASSWORD"]
    assert values_after["SMTP_USER"] == values_before["SMTP_USER"]
    assert values_after["DB_PASSWORD_HASH"] == hashlib.sha256(
        values_after["DB_PASSWORD"].encode()
    ).hexdigest()

    # 4. Add another secret
    added_result = await server._add_secrets({
        "encrypted_content": rotated,
        "secrets": [
            {"key_name": "API_KEY", "source": "external", "value": "abc123"},
        ],
    })
    added = added_result[0].text
    values = server.encryptor.decrypt(added)
    assert values["API_KEY"] == "abc123"
    assert values["DB_PASSWORD"] == values_after["DB_PASSWORD"]  # preserved

    # 5. Update external
    updated_result = await server._update_external({
        "encrypted_content": added,
        "key_name": "API_KEY",
        "value": "new-value",
    })
    updated = updated_result[0].text
    values = server.encryptor.decrypt(updated)
    assert values["API_KEY"] == "new-value"

    # 6. Rename — derivation reference must update
    renamed_result = await server._rename_secret({
        "encrypted_content": updated,
        "old_name": "DB_PASSWORD",
        "new_name": "DATABASE_PASSWORD",
    })
    renamed = renamed_result[0].text
    parsed = yaml.safe_load(renamed)
    assert "DATABASE_PASSWORD" in parsed
    assert "DB_PASSWORD" not in parsed
    assert (
        parsed["_meta_unencrypted"]["secrets"]["DB_PASSWORD_HASH"]
        ["derivation"]["from"] == "DATABASE_PASSWORD"
    )

    # 7. Delete — deleting a source without its dependent must fail
    with pytest.raises(ValueError, match="depend on it"):
        await server._delete_secrets({
            "encrypted_content": renamed,
            "key_names": ["DATABASE_PASSWORD"],
        })

    # 8. Deleting both together works
    deleted_result = await server._delete_secrets({
        "encrypted_content": renamed,
        "key_names": ["DATABASE_PASSWORD", "DB_PASSWORD_HASH"],
    })
    deleted = deleted_result[0].text
    parsed = yaml.safe_load(deleted)
    assert "DATABASE_PASSWORD" not in parsed
    assert "DB_PASSWORD_HASH" not in parsed
    values = server.encryptor.decrypt(deleted)
    assert values["SMTP_USER"] == "user@example.com"
    assert values["API_KEY"] == "new-value"


async def test_update_external_cascades_to_derived(server):
    """Updating an external secret must recompute derived secrets that
    reference it."""
    result = await server._create_secrets({
        "secrets": [
            {
                "key_name": "UPSTREAM_KEY",
                "source": "external",
                "value": "original",
            },
            {
                "key_name": "UPSTREAM_KEY_HASH",
                "source": "derived",
                "transform": "sha256_hex",
                "from": "UPSTREAM_KEY",
            },
        ]
    })
    encrypted = result[0].text
    values = server.encryptor.decrypt(encrypted)
    assert values["UPSTREAM_KEY_HASH"] == hashlib.sha256(
        b"original"
    ).hexdigest()

    updated = await server._update_external({
        "encrypted_content": encrypted,
        "key_name": "UPSTREAM_KEY",
        "value": "new-upstream",
    })
    values = server.encryptor.decrypt(updated[0].text)
    assert values["UPSTREAM_KEY"] == "new-upstream"
    assert values["UPSTREAM_KEY_HASH"] == hashlib.sha256(
        b"new-upstream"
    ).hexdigest()


async def test_update_external_rejects_generated(server):
    result = await server._create_secrets({
        "secrets": [
            {"key_name": "TOKEN", "source": "generated", "length": 16},
        ]
    })
    with pytest.raises(ValueError, match="not 'external'"):
        await server._update_external({
            "encrypted_content": result[0].text,
            "key_name": "TOKEN",
            "value": "anything",
        })


async def test_oidc_convenience_creates_pair(server):
    result = await server._create_oidc_secret({
        "key_name": "GRAFANA_OIDC_CLIENT_SECRET",
        "description": "OIDC client secret for Grafana",
    })
    encrypted = result[0].text
    values = server.encryptor.decrypt(encrypted)
    assert len(values["GRAFANA_OIDC_CLIENT_SECRET"]) == 64
    assert values["GRAFANA_OIDC_CLIENT_SECRET"].isalnum()
    assert values["GRAFANA_OIDC_CLIENT_SECRET_HASH"].startswith(
        "$pbkdf2-sha512$310000$"
    )
    # The hash must be returned in the response so the user can paste it.
    all_text = "\n".join(r.text for r in result)
    assert "GRAFANA_OIDC_CLIENT_SECRET_HASH = $pbkdf2-sha512$" in all_text


async def test_derived_is_not_recomputed_when_source_unchanged(server):
    """When rotate_generated is called and a derived secret's source is
    unchanged (e.g. external), the derived value must be preserved, not
    recomputed — important for non-deterministic transforms."""
    result = await server._create_secrets({
        "secrets": [
            {"key_name": "GEN_TOKEN", "source": "generated", "length": 16},
            {
                "key_name": "FIXED_PASSWORD",
                "source": "external",
                "value": "my-fixed-password",
            },
            {
                "key_name": "FIXED_PASSWORD_HASH",
                "source": "derived",
                "transform": "pbkdf2_sha512_authelia",
                "from": "FIXED_PASSWORD",
            },
        ]
    })
    encrypted = result[0].text
    hash_before = server.encryptor.decrypt(encrypted)["FIXED_PASSWORD_HASH"]

    rotated = await server._rotate_generated(
        {"encrypted_content": encrypted}
    )
    values = server.encryptor.decrypt(rotated[0].text)
    assert values["FIXED_PASSWORD_HASH"] == hash_before


async def test_add_metadata_accepts_derived(server):
    """Retrofitting metadata onto an existing file must accept 'derived'
    entries with transform + from."""
    # Bootstrap an encrypted file without _meta_unencrypted by creating one
    # and stripping it.
    first = await server._create_secrets({
        "secrets": [
            {"key_name": "PASSWORD", "source": "external", "value": "p"},
            {"key_name": "PASSWORD_HASH", "source": "external", "value": "h"},
        ]
    })
    encrypted = first[0].text
    # Decrypt, drop _meta_unencrypted, re-encrypt (simulating legacy file).
    values = server.encryptor.decrypt(encrypted)
    values.pop("_meta_unencrypted", None)
    legacy = server.encryptor.encrypt(values)

    result = await server._add_metadata({
        "encrypted_content": legacy,
        "secret_metadata": {
            "PASSWORD": {"source": "external"},
            "PASSWORD_HASH": {
                "source": "derived",
                "transform": "sha256_hex",
                "from": "PASSWORD",
            },
        },
    })
    parsed = yaml.safe_load(result[0].text)
    meta = parsed["_meta_unencrypted"]["secrets"]
    assert meta["PASSWORD"]["source"] == "external"
    assert meta["PASSWORD_HASH"]["source"] == "derived"
    assert meta["PASSWORD_HASH"]["derivation"]["from"] == "PASSWORD"
    assert meta["PASSWORD_HASH"]["derivation"]["transform"] == "sha256_hex"
