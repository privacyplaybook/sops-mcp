"""End-to-end integration tests exercising the real sops CLI with a
throwaway age keypair. Requires `sops` and `age-keygen` on PATH.
"""

import hashlib
import subprocess

import pytest
import yaml

import sops_mcp.sops as sops_module
from sops_mcp.domains import load_domains
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor


def _require(binary: str) -> None:
    if subprocess.run(
        ["which", binary], capture_output=True, check=False
    ).returncode != 0:
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
    for raw in key_file.read_text().splitlines():
        line = raw.strip()
        if line.startswith("AGE-SECRET-KEY-"):
            private_key = line
        elif line.startswith("# public key: "):
            public_key = line.split(": ", 1)[1]
    assert private_key
    assert public_key
    monkeypatch.setenv("SOPS_AGE_KEY", private_key)
    monkeypatch.setenv("SOPS_MCP_AGE_PUBLIC_KEY", public_key)
    return public_key


def _domain(server):
    """The server's only domain — these tests run single-domain."""
    return server.domains["default"]


@pytest.fixture
def server(age_keys):
    """Server built the way main() builds it, from the patched environment."""
    return SopsMcpServer(SopsEncryptor(), load_domains())


async def test_full_lifecycle(server):
    # 1. Create with generated + external + derived (sha256_hex)
    result = await server._create_secrets({
        "secrets": [
            {"key_name": "DB_ACCESS_KEY", "source": "generated", "length": 32},
            {
                "key_name": "SMTP_USER",
                "source": "external",
                "value": "user@example.com",
            },
            {
                "key_name": "DB_ACCESS_KEY_HASH",
                "source": "derived",
                "transform": "sha256_hex",
                "from": "DB_ACCESS_KEY",
            },
        ]
    })
    encrypted = result[0].text
    values = server.encryptor.decrypt(encrypted, _domain(server))
    assert len(values["DB_ACCESS_KEY"]) == 32
    assert values["SMTP_USER"] == "user@example.com"
    assert values["DB_ACCESS_KEY_HASH"] == hashlib.sha256(
        values["DB_ACCESS_KEY"].encode()
    ).hexdigest()

    # 2. List without decryption
    listed = await server._list_secrets({"encrypted_content": encrypted})
    listing = listed[0].text
    assert "DB_ACCESS_KEY" in listing
    assert "SMTP_USER" in listing
    assert "derived" in listing

    # 3. Rotate — generated changes, derived cascades, external preserved
    rotated_result = await server._rotate_generated(
        {"encrypted_content": encrypted}
    )
    rotated = rotated_result[0].text
    values_before = values
    values_after = server.encryptor.decrypt(rotated, _domain(server))
    assert values_after["DB_ACCESS_KEY"] != values_before["DB_ACCESS_KEY"]
    assert values_after["SMTP_USER"] == values_before["SMTP_USER"]
    assert values_after["DB_ACCESS_KEY_HASH"] == hashlib.sha256(
        values_after["DB_ACCESS_KEY"].encode()
    ).hexdigest()

    # 4. Add another secret
    added_result = await server._add_secrets({
        "encrypted_content": rotated,
        "secrets": [
            {"key_name": "API_KEY", "source": "external", "value": "abc123"},
        ],
    })
    added = added_result[0].text
    values = server.encryptor.decrypt(added, _domain(server))
    assert values["API_KEY"] == "abc123"
    assert values["DB_ACCESS_KEY"] == values_after["DB_ACCESS_KEY"]  # preserved

    # 5. Update external
    updated_result = await server._update_external({
        "encrypted_content": added,
        "key_name": "API_KEY",
        "value": "new-value",
    })
    updated = updated_result[0].text
    values = server.encryptor.decrypt(updated, _domain(server))
    assert values["API_KEY"] == "new-value"

    # 6. Rename — derivation reference must update
    renamed_result = await server._rename_secret({
        "encrypted_content": updated,
        "old_name": "DB_ACCESS_KEY",
        "new_name": "DATABASE_ACCESS_KEY",
    })
    renamed = renamed_result[0].text
    parsed = yaml.safe_load(renamed)
    assert "DATABASE_ACCESS_KEY" in parsed
    assert "DB_ACCESS_KEY" not in parsed
    assert (
        parsed["_meta_unencrypted"]["secrets"]["DB_ACCESS_KEY_HASH"]
        ["derivation"]["from"] == "DATABASE_ACCESS_KEY"
    )

    # 7. Delete — deleting a source without its dependent must fail
    with pytest.raises(ValueError, match="depend on it"):
        await server._delete_secrets({
            "encrypted_content": renamed,
            "key_names": ["DATABASE_ACCESS_KEY"],
        })

    # 8. Deleting both together works
    deleted_result = await server._delete_secrets({
        "encrypted_content": renamed,
        "key_names": ["DATABASE_ACCESS_KEY", "DB_ACCESS_KEY_HASH"],
    })
    deleted = deleted_result[0].text
    parsed = yaml.safe_load(deleted)
    assert "DATABASE_ACCESS_KEY" not in parsed
    assert "DB_ACCESS_KEY_HASH" not in parsed
    values = server.encryptor.decrypt(deleted, _domain(server))
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
    values = server.encryptor.decrypt(encrypted, _domain(server))
    assert values["UPSTREAM_KEY_HASH"] == hashlib.sha256(
        b"original"
    ).hexdigest()

    updated = await server._update_external({
        "encrypted_content": encrypted,
        "key_name": "UPSTREAM_KEY",
        "value": "new-upstream",
    })
    values = server.encryptor.decrypt(updated[0].text, _domain(server))
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
    values = server.encryptor.decrypt(encrypted, _domain(server))
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
    hash_before = server.encryptor.decrypt(encrypted, _domain(server))[
        "FIXED_PASSWORD_HASH"
    ]

    rotated = await server._rotate_generated(
        {"encrypted_content": encrypted}
    )
    values = server.encryptor.decrypt(rotated[0].text, _domain(server))
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
    values = server.encryptor.decrypt(encrypted, _domain(server))
    values.pop("_meta_unencrypted", None)
    legacy = server.encryptor.encrypt(values, _domain(server))

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


# --- Weak generated secrets come back with a warning, never refused (#62) ---

# Letters only, so the decrypted YAML value is always a string: an
# all-digit value would load as an int. The 'Z' keeps exclude_chars itself
# from being all digits, which rotation reads back as a number (a
# pre-existing bug, filed separately).
_LETTERS = {"charset": "alphanumeric", "exclude_chars": "Z0123456789"}


async def test_create_warns_on_weak_secret_without_the_value(server):
    result = await server._create_secrets({
        "secrets": [
            {"key_name": "PIN", "source": "generated",
             "length": 5, **_LETTERS},
            {"key_name": "STRONG", "source": "generated", "length": 32},
        ]
    })
    values = server.encryptor.decrypt(result[0].text, _domain(server))
    assert len(values["PIN"]) == 5  # created, not refused
    summary = "\n".join(r.text for r in result[1:])
    warnings = [line for line in summary.splitlines() if "WARNING" in line]
    assert len(warnings) == 1  # only PIN; STRONG is above 64 bits
    assert "28 bits" in warnings[0]
    assert summary.index("PIN:") < summary.index("WARNING") < summary.index(
        "STRONG:"
    )
    for text in (r.text for r in result[1:]):
        assert values["PIN"] not in text.replace("PIN", "")


async def test_add_secrets_warns_on_weak_secret(server):
    created = await server._create_secrets({
        "secrets": [{"key_name": "A", "source": "generated"}]
    })
    added = await server._add_secrets({
        "encrypted_content": created[0].text,
        "secrets": [{"key_name": "B", "source": "generated",
                     "length": 8, "charset": "hex"}],
    })
    summary = "\n".join(r.text for r in added[1:])
    assert "WARNING: about 32 bits" in summary


async def test_strong_secrets_get_no_warning(server):
    result = await server._create_secrets({
        "secrets": [{"key_name": "A", "source": "generated",
                     "length": 11, "charset": "urlsafe"}]
    })
    assert not any("WARNING" in r.text for r in result[1:])


async def test_rotate_warns_on_weak_secret(server):
    created = await server._create_secrets({
        "secrets": [
            {"key_name": "PIN", "source": "generated",
             "length": 4, **_LETTERS},
            {"key_name": "STRONG", "source": "generated"},
            {"key_name": "EXT", "source": "external", "value": "x"},
        ]
    })
    rotated = await server._rotate_generated(
        {"encrypted_content": created[0].text}
    )
    values = server.encryptor.decrypt(rotated[0].text, _domain(server))
    assert len(values["PIN"]) == 4
    summary = "\n".join(r.text for r in rotated[1:])
    warnings = [line for line in summary.splitlines() if "WARNING" in line]
    assert len(warnings) == 1
    assert warnings[0].startswith("    PIN: WARNING: about 23 bits")
    # Listed under the Rotated line, not after Preserved.
    lines = summary.splitlines()
    rotated_at = next(i for i, ln in enumerate(lines) if "Rotated:" in ln)
    assert lines[rotated_at + 1] == warnings[0]
    assert values["PIN"] not in summary.replace("PIN", "")


def test_charset_schema_lists_urlsafe_and_documents_base64():
    from sops_mcp.server import SECRET_ITEM_SCHEMA

    charset = SECRET_ITEM_SCHEMA["properties"]["charset"]
    assert "urlsafe" in charset["enum"]
    assert "base64" in charset["enum"]
    assert "not base64 encoding" in charset["description"]
    assert "warning" in charset["description"]


async def test_rotate_refuses_keys_the_metadata_block_does_not_describe(server):
    """#46: sops_add_secrets on a legacy file writes a block that lists only
    the new key. Rotation used to rebuild the file from that block alone, so
    it returned a file without the legacy keys. It must refuse instead, name
    the undescribed keys (never their values), and drop nothing."""
    domain = _domain(server)
    legacy = server.encryptor.encrypt(
        {"LEGACY_A": "value-a-zz91", "LEGACY_B": "value-b-zz92"}, domain
    )

    added = await server._add_secrets({
        "encrypted_content": legacy,
        "secrets": [
            {"key_name": "NEW_TOKEN", "source": "generated", "length": 24},
        ],
    })
    partial = added[0].text
    assert set(yaml.safe_load(partial)["_meta_unencrypted"]["secrets"]) == {
        "NEW_TOKEN"
    }
    before = server.encryptor.decrypt(partial, domain)

    with pytest.raises(ValueError, match="does not describe") as excinfo:
        await server._rotate_generated({"encrypted_content": partial})
    message = str(excinfo.value)
    assert "LEGACY_A" in message
    assert "LEGACY_B" in message
    assert "NEW_TOKEN" not in message
    for value in before.values():
        if isinstance(value, str):
            assert value not in message

    # Nothing returned, so nothing dropped: the input still decrypts to
    # every key it held.
    after = server.encryptor.decrypt(partial, domain)
    assert after == before
    assert {"LEGACY_A", "LEGACY_B", "NEW_TOKEN"} <= set(after)


async def _with_extra(server, extra, entries=None):
    """A file made by sops_create_secrets (so its block is complete), then
    re-encrypted with `extra` keys added and `entries` merged into the
    block's secrets, the way a hand edit with the sops CLI would."""
    domain = _domain(server)
    created = await server._create_secrets({
        "secrets": [
            {"key_name": "TOKEN", "source": "generated", "length": 16},
        ],
    })
    values = server.encryptor.decrypt(created[0].text, domain)
    values.update(extra)
    values["_meta_unencrypted"]["secrets"].update(entries or {})
    return server.encryptor.encrypt(values, domain)


@pytest.mark.parametrize(
    ("extra", "entries", "named"),
    [
        # A bare or scalar entry doesn't describe the key: topological_order
        # skips it, so rotating would drop the value and keep the entry.
        ({"LEGACY_A": "value-zz93"}, {"LEGACY_A": None}, "LEGACY_A"),
        ({"LEGACY_A": "value-zz93"}, {"LEGACY_A": "external"}, "LEGACY_A"),
        # '_'-prefixed keys would be dropped too.
        ({"_note": "value-zz94"}, {}, "_note"),
        # An unquoted NO, which PyYAML (YAML 1.1) would load as False. sops
        # keeps it a string key and quotes it on decrypt, so it is named as
        # written (the guard's str() is only a backstop).
        ({"NO": "value-zz95", "LEGACY_B": "value-zz96"}, {}, "NO"),
    ],
)
async def test_rotate_refuses_each_kind_of_undescribed_key(
    server, extra, entries, named, monkeypatch
):
    real_dump = sops_module.yaml.dump

    def unquoted_no(data, *args, **kwargs):
        # yaml.dump quotes 'NO'; a hand-written file wouldn't.
        return real_dump(data, *args, **kwargs).replace("'NO':", "NO:")

    monkeypatch.setattr(sops_module.yaml, "dump", unquoted_no)
    content = await _with_extra(server, extra, entries)
    monkeypatch.setattr(sops_module.yaml, "dump", real_dump)
    with pytest.raises(ValueError, match="does not describe") as excinfo:
        await server._rotate_generated({"encrypted_content": content})
    message = str(excinfo.value)
    assert named in message
    assert "TOKEN" not in message
    for value in extra.values():
        assert value not in message
