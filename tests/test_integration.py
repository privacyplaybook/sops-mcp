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
    block's secrets, the way a hand edit with the sops CLI would.

    encrypt() refuses root keys no tool may write, such as '_note' (#65),
    so `extra` is passed as `carried`, as for any legacy file: the sops
    CLI writes such keys, and rotate has to cope with them."""
    domain = _domain(server)
    created = await server._create_secrets({
        "secrets": [
            {"key_name": "TOKEN", "source": "generated", "length": 16},
        ],
    })
    values = server.encryptor.decrypt(created[0].text, domain)
    values.update(extra)
    values["_meta_unencrypted"]["secrets"].update(entries or {})
    return server.encryptor.encrypt(values, domain, carried=set(extra))


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

    with monkeypatch.context() as patch:
        if "NO" in extra:
            patch.setattr(sops_module.yaml, "dump", unquoted_no)
        content = await _with_extra(server, extra, entries)
    with pytest.raises(ValueError, match="does not describe") as excinfo:
        await server._rotate_generated({"encrypted_content": content})
    message = str(excinfo.value)
    assert named in message
    assert "TOKEN" not in message
    for value in extra.values():
        assert value not in message


# --- sops_add_metadata repairs a partial block (#72) ----------------------


async def _partial(server):
    """A legacy file given one new key by sops_add_secrets: its block lists
    only NEW_TOKEN, so rotation refuses it (#46)."""
    legacy = server.encryptor.encrypt(
        {"LEGACY_A": "value-a-zz91", "LEGACY_B": "value-b-zz92"},
        _domain(server),
    )
    return await server._add_secrets({
        "encrypted_content": legacy,
        "secrets": [
            {"key_name": "NEW_TOKEN", "source": "generated", "length": 24},
        ],
    })


async def test_add_secrets_says_the_block_leaves_keys_out(server):
    added = await _partial(server)
    summary = "\n".join(r.text for r in added[1:])
    assert "does not describe 2 key(s): LEGACY_A, LEGACY_B" in summary
    assert "sops_add_metadata" in summary
    assert "value-a-zz91" not in summary

    # A file whose block is complete gets no such note.
    again = await server._add_secrets({
        "encrypted_content": (await server._create_secrets({
            "secrets": [{"key_name": "A", "source": "generated"}],
        }))[0].text,
        "secrets": [{"key_name": "B", "source": "generated"}],
    })
    assert "does not describe" not in "\n".join(r.text for r in again[1:])


async def test_partial_block_can_be_repaired_then_rotated(server):
    domain = _domain(server)
    partial = (await _partial(server))[0].text
    before = server.encryptor.decrypt(partial, domain)
    new_token_entry = yaml.safe_load(partial)["_meta_unencrypted"]["secrets"][
        "NEW_TOKEN"
    ]

    repaired = await server._add_metadata({
        "encrypted_content": partial,
        "secret_metadata": {
            "LEGACY_A": {"source": "external", "description": "kept"},
            "LEGACY_B": {"source": "generated"},
        },
    })
    summary = repaired[1].text
    assert "LEGACY_A: external - kept" in summary
    assert "Kept existing entries: NEW_TOKEN" in summary
    block = yaml.safe_load(repaired[0].text)["_meta_unencrypted"]
    assert block["domain"] == "default"
    # The existing entry is kept exactly; the new ones are added.
    assert block["secrets"]["NEW_TOKEN"] == new_token_entry
    assert block["secrets"]["LEGACY_A"]["source"] == "external"
    assert block["secrets"]["LEGACY_B"]["source"] == "generated"
    # Nothing dropped, nothing changed.
    after_repair = server.encryptor.decrypt(repaired[0].text, domain)
    assert {k: v for k, v in after_repair.items() if k != "_meta_unencrypted"} == {
        k: v for k, v in before.items() if k != "_meta_unencrypted"
    }

    rotated = await server._rotate_generated(
        {"encrypted_content": repaired[0].text}
    )
    values = server.encryptor.decrypt(rotated[0].text, domain)
    assert set(values) == {"LEGACY_A", "LEGACY_B", "NEW_TOKEN", "_meta_unencrypted"}
    assert values["LEGACY_A"] == "value-a-zz91"  # external: kept
    assert values["LEGACY_B"] != "value-b-zz92"  # generated: rotated
    assert len(values["LEGACY_B"]) == 32
    assert values["NEW_TOKEN"] != before["NEW_TOKEN"]
    assert len(values["NEW_TOKEN"]) == 24  # its own entry still governs it


async def test_add_metadata_never_replaces_a_described_key(server):
    partial = (await _partial(server))[0].text
    with pytest.raises(ValueError, match="already describes NEW_TOKEN"):
        await server._add_metadata({
            "encrypted_content": partial,
            "secret_metadata": {
                "LEGACY_A": {"source": "external"},
                "LEGACY_B": {"source": "external"},
                "NEW_TOKEN": {"source": "external"},
            },
        })


async def test_add_metadata_must_describe_every_undescribed_key(server):
    partial = (await _partial(server))[0].text
    with pytest.raises(
        ValueError, match="Keys in file but not in metadata: LEGACY_B"
    ):
        await server._add_metadata({
            "encrypted_content": partial,
            "secret_metadata": {"LEGACY_A": {"source": "external"}},
        })
    with pytest.raises(ValueError, match="Keys in metadata but not in file: X"):
        await server._add_metadata({
            "encrypted_content": partial,
            "secret_metadata": {
                "LEGACY_A": {"source": "external"},
                "LEGACY_B": {"source": "external"},
                "X": {"source": "external"},
            },
        })


async def test_add_metadata_refuses_a_complete_block(server):
    created = await server._create_secrets({
        "secrets": [{"key_name": "A", "source": "generated"}],
    })
    with pytest.raises(ValueError, match="already describes every key"):
        await server._add_metadata({
            "encrypted_content": created[0].text,
            "secret_metadata": {"A": {"source": "external"}},
        })


async def test_add_metadata_derives_from_a_described_key(server):
    partial = (await _partial(server))[0].text
    repaired = await server._add_metadata({
        "encrypted_content": partial,
        "secret_metadata": {
            "LEGACY_A": {"source": "external"},
            "LEGACY_B": {
                "source": "derived",
                "transform": "sha256_hex",
                "from": "NEW_TOKEN",
            },
        },
    })
    rotated = await server._rotate_generated(
        {"encrypted_content": repaired[0].text}
    )
    values = server.encryptor.decrypt(rotated[0].text, _domain(server))
    assert values["LEGACY_B"] == hashlib.sha256(
        values["NEW_TOKEN"].encode()
    ).hexdigest()


async def test_add_metadata_replaces_a_non_mapping_entry(server):
    """A bare entry doesn't describe its key (rotation refuses it), so it
    counts as undescribed and gets its new entry."""
    content = await _with_extra(
        server, {"LEGACY_A": "value-zz93"}, {"LEGACY_A": "external"}
    )
    repaired = await server._add_metadata({
        "encrypted_content": content,
        "secret_metadata": {"LEGACY_A": {"source": "external"}},
    })
    block = yaml.safe_load(repaired[0].text)["_meta_unencrypted"]["secrets"]
    assert block["LEGACY_A"] == {"source": "external"}
    assert block["TOKEN"]["source"] == "generated"
    rotated = await server._rotate_generated(
        {"encrypted_content": repaired[0].text}
    )
    values = server.encryptor.decrypt(rotated[0].text, _domain(server))
    assert values["LEGACY_A"] == "value-zz93"


@pytest.mark.parametrize("with_block", [True, False])
async def test_add_metadata_refuses_rather_than_drops_underscore_keys(
    server, with_block
):
    """Entries need ^[A-Z]... names, so a '_'-prefixed key can't be
    described. It used to be dropped from the file silently; now it is
    refused and named, never its value."""
    domain = _domain(server)
    if with_block:
        content = await _with_extra(
            server, {"_note": "value-zz94", "LEGACY_A": "value-zz95"}
        )
    else:
        content = server.encryptor.encrypt(
            {"_note": "value-zz94", "LEGACY_A": "value-zz95"},
            domain,
            carried={"_note"},
        )
    with pytest.raises(ValueError, match="no metadata entry can describe") as e:
        await server._add_metadata({
            "encrypted_content": content,
            "secret_metadata": {"LEGACY_A": {"source": "external"}},
        })
    assert "_note" in str(e.value)
    assert "value-zz94" not in str(e.value)


async def test_add_metadata_refuses_a_malformed_block(server):
    domain = _domain(server)
    content = server.encryptor.encrypt(
        {"A": "v", "_meta_unencrypted": {"version": 1, "secrets": ["A"]}},
        domain,
    )
    with pytest.raises(ValueError, match="block is malformed"):
        await server._add_metadata({
            "encrypted_content": content,
            "secret_metadata": {"A": {"source": "external"}},
        })


async def test_add_metadata_names_a_key_it_cannot_describe(server):
    """A legacy name an entry can't take is refused up front with the way
    out (rename), and once renamed the repair works (#72 review)."""
    domain = _domain(server)
    legacy = server.encryptor.encrypt(
        {"db_password": "value-zz97"}, domain, carried={"db_password"}
    )
    added = await server._add_secrets({
        "encrypted_content": legacy,
        "secrets": [{"key_name": "NEW", "source": "generated"}],
    })
    assert "sops_rename_secret" in added[1].text
    with pytest.raises(ValueError, match="describe: db_password") as e:
        await server._add_metadata({
            "encrypted_content": added[0].text,
            "secret_metadata": {"db_password": {"source": "external"}},
        })
    assert "sops_rename_secret" in str(e.value)
    assert "value-zz97" not in str(e.value)

    renamed = await server._rename_secret({
        "encrypted_content": added[0].text,
        "old_name": "db_password",
        "new_name": "DB_PASSWORD",
    })
    repaired = await server._add_metadata({
        "encrypted_content": renamed[0].text,
        "secret_metadata": {"DB_PASSWORD": {"source": "external"}},
    })
    rotated = await server._rotate_generated(
        {"encrypted_content": repaired[0].text}
    )
    values = server.encryptor.decrypt(rotated[0].text, domain)
    assert values["DB_PASSWORD"] == "value-zz97"


async def test_add_metadata_refuses_a_derivation_cycle(server):
    """A new derived entry may name a described key, but not one whose
    entry derives from it: rotation would refuse the result."""
    domain = _domain(server)
    legacy = server.encryptor.encrypt({"PW": "value-zz98"}, domain)
    added = await server._add_secrets({
        "encrypted_content": legacy,
        "secrets": [{"key_name": "HASH", "source": "derived",
                     "transform": "sha256_hex", "from": "PW"}],
    })
    with pytest.raises(ValueError, match="would not rotate"):
        await server._add_metadata({
            "encrypted_content": added[0].text,
            "secret_metadata": {
                "PW": {"source": "derived", "transform": "sha256_hex",
                       "from": "HASH"},
            },
        })


async def test_add_metadata_names_stale_entries(server):
    """An entry for a key no longer in the file is kept (it isn't this
    tool's to remove) but named, since rotation refuses an external one."""
    content = await _with_extra(
        server,
        {"LEGACY_A": "value-zz99"},
        {"GONE": {"source": "external"}},
    )
    repaired = await server._add_metadata({
        "encrypted_content": content,
        "secret_metadata": {"LEGACY_A": {"source": "external"}},
    })
    assert "not in the file: GONE" in repaired[1].text
    block = yaml.safe_load(repaired[0].text)["_meta_unencrypted"]["secrets"]
    assert block["GONE"] == {"source": "external"}


async def test_add_metadata_refuses_two_new_entries_deriving_from_each_other(
    server,
):
    legacy = server.encryptor.encrypt({"A": "va", "B": "vb"}, _domain(server))
    with pytest.raises(ValueError, match="would not rotate"):
        await server._add_metadata({
            "encrypted_content": legacy,
            "secret_metadata": {
                "A": {"source": "derived", "transform": "sha256_hex",
                      "from": "B"},
                "B": {"source": "derived", "transform": "sha256_hex",
                      "from": "A"},
            },
        })


async def test_add_metadata_names_but_accepts_an_existing_dangling_entry(
    server,
):
    """A derivation the block already got wrong isn't this call's to
    refuse: the repair goes ahead, and the summary names the problem."""
    content = await _with_extra(
        server,
        {"LEGACY_A": "value-zz99"},
        {"X": {"source": "derived",
               "derivation": {"transform": "sha256_hex", "from": "GONE"}}},
    )
    repaired = await server._add_metadata({
        "encrypted_content": content,
        "secret_metadata": {"LEGACY_A": {"source": "external"}},
    })
    assert "already fails rotation's derivation check" in repaired[1].text
    assert "X" in yaml.safe_load(repaired[0].text)["_meta_unencrypted"][
        "secrets"
    ]


async def test_rename_hint_avoids_rename_when_underscore_keys_exist(server):
    """sops_rename_secret drops '_'-prefixed keys, so it isn't offered for
    a file that holds one."""
    content = server.encryptor.encrypt(
        {"db_password": "value-zz97", "_note": "value-zz94"},
        _domain(server),
        carried={"db_password", "_note"},
    )
    with pytest.raises(ValueError, match="sops CLI") as e:
        await server._add_metadata({
            "encrypted_content": content,
            "secret_metadata": {"DB": {"source": "external"}},
        })
    assert "sops_rename_secret" not in str(e.value)


async def test_rotate_refusal_offers_rename_for_a_plain_bad_name(server):
    content = await _with_extra(server, {"db_password": "value-zz97"})
    with pytest.raises(ValueError, match="does not describe") as e:
        await server._rotate_generated({"encrypted_content": content})
    assert "with sops_rename_secret" in str(e.value)
