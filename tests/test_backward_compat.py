"""Backward-compatibility tests for the key-domains change.

"v1" here means sops-mcp 0.10.1 and earlier: no key domains, no ``domain``
field in ``_meta_unencrypted``, and a single recipient taken from
``SOPS_MCP_AGE_PUBLIC_KEY``.

Three properties matter, and each is pinned below:

1. A file written by v1 still works with every tool.
2. The metadata schema grew by exactly one key, so a v1 reader that
   ignores unknown keys still understands a file this version writes.
3. No tool gained a required argument, so a v1 client's calls still
   validate.
"""

import subprocess

import pytest
import yaml

from sops_mcp.domains import Domain
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor

# Exactly what sops-mcp 0.10.1 wrote: version + secrets, and nothing else.
V1_META_KEYS = {"version", "secrets"}

# The required-argument set of every tool, pinned. A v1 client supplies no
# 'domain', so 'domain' must not appear here for any pre-existing tool.
# Changing this map is a client-visible break; do it deliberately.
EXPECTED_REQUIRED = {
    "sops_create_secrets": {"secrets"},
    "sops_list_secrets": {"encrypted_content"},
    "sops_rotate_generated": {"encrypted_content"},
    "sops_add_secrets": {"encrypted_content", "secrets"},
    "sops_add_metadata": {"encrypted_content", "secret_metadata"},
    "sops_delete_secrets": {"encrypted_content", "key_names"},
    "sops_rename_secret": {"encrypted_content", "old_name", "new_name"},
    "sops_update_external": {"encrypted_content", "key_name", "value"},
    "sops_create_oidc_secret": {"key_name"},
    # Added in this version, so no v1 client can be broken by it.
    "sops_list_domains": set(),
    "sops_rekey": {"encrypted_content", "domain"},
}


def _require(binary: str) -> None:
    if subprocess.run(["which", binary], capture_output=True, check=False).returncode:
        pytest.skip(f"{binary} not installed")


def _keypair() -> tuple[str, str]:
    out = subprocess.run(
        ["age-keygen"], capture_output=True, text=True, check=True
    ).stdout
    ident = next(
        line.strip()
        for line in out.splitlines()
        if line.startswith("AGE-SECRET-KEY-")
    )
    pub = subprocess.run(
        ["age-keygen", "-y"], input=ident, capture_output=True, text=True, check=True
    ).stdout.strip()
    return ident, pub


@pytest.fixture
def server():
    _require("sops")
    _require("age-keygen")
    ident, pub = _keypair()
    domains = {"default": Domain("default", (pub,), (ident,))}
    return SopsMcpServer(SopsEncryptor(), domains)


@pytest.fixture
def v1_file(server):
    """A file exactly as sops-mcp 0.10.1 would have written it."""
    blob = server.encryptor.encrypt(
        {
            "DB_PASSWORD": "original-value",
            "SMTP_USER": "alice@example.com",
            "DB_PASSWORD_HASH": "abc123",
            "_meta_unencrypted": {
                "version": 1,
                "secrets": {
                    "DB_PASSWORD": {
                        "source": "generated",
                        "generation": {"length": 14, "charset": "alphanumeric"},
                    },
                    "SMTP_USER": {
                        "source": "external",
                        "description": "SMTP login",
                    },
                    "DB_PASSWORD_HASH": {
                        "source": "derived",
                        "derivation": {
                            "transform": "sha256_hex",
                            "from": "DB_PASSWORD",
                        },
                    },
                },
            },
        },
        server.domains["default"],
    )
    assert set(yaml.safe_load(blob)["_meta_unencrypted"]) == V1_META_KEYS
    return blob


# --- 1. a v1 file works with every tool ----------------------------------

# Every mutation, with arguments a v1 client would have sent (no 'domain').
MUTATIONS = [
    ("rotate_generated", {"key_names": ["DB_PASSWORD"]}),
    ("add_secrets", {"secrets": [
        {"key_name": "NEW_KEY", "source": "external", "value": "v"},
    ]}),
    ("update_external", {"key_name": "SMTP_USER", "value": "bob@example.com"}),
    ("rename_secret", {"old_name": "SMTP_USER", "new_name": "SMTP_LOGIN"}),
    ("delete_secrets", {"key_names": ["SMTP_USER", "DB_PASSWORD_HASH"]}),
]


@pytest.mark.parametrize(("tool", "extra"), MUTATIONS, ids=[m[0] for m in MUTATIONS])
async def test_v1_file_survives_every_mutation(server, v1_file, tool, extra):
    """Only rotate was covered before; the rest are the regression risk."""
    handler = getattr(server, f"_{tool}")
    result = await handler({"encrypted_content": v1_file, **extra})

    parsed = yaml.safe_load(result[0].text)
    assert parsed["_meta_unencrypted"]["domain"] == "default"
    assert parsed["_meta_unencrypted"]["version"] == 1
    assert len(parsed["sops"]["age"]) == 1


async def test_v1_file_lists_without_a_key(server, v1_file):
    text = (await server._list_secrets({"encrypted_content": v1_file}))[0].text
    assert "DB_PASSWORD" in text
    assert "not recorded (pre-domains file" in text
    assert "Recipients match the configured domain." in text


async def test_v1_file_rekeys(server, v1_file):
    result = await server._rekey(
        {"encrypted_content": v1_file, "domain": "default"}
    )
    assert yaml.safe_load(result[0].text)["_meta_unencrypted"]["domain"] == "default"


async def test_v1_file_values_are_preserved_across_a_mutation(server, v1_file):
    """A v1 file must not lose data on the way through the new code path."""
    domain = server.domains["default"]
    result = await server._update_external(
        {"encrypted_content": v1_file, "key_name": "SMTP_USER", "value": "bob@x.com"}
    )
    after = server.encryptor.decrypt(result[0].text, domain)
    assert after["DB_PASSWORD"] == "original-value"
    assert after["SMTP_USER"] == "bob@x.com"


# --- 2. the metadata schema grew by exactly one key ----------------------


async def test_metadata_schema_adds_only_the_domain_key(server):
    """A v1 reader ignoring unknown keys still understands our output.

    If this version ever adds a second field, a v1 sops-mcp reading the
    file would silently drop it on the next mutation, so the addition has
    to be a deliberate decision rather than a side effect.
    """
    created = await server._create_secrets(
        {"secrets": [{"key_name": "TOKEN", "source": "generated", "length": 8}]}
    )
    meta = yaml.safe_load(created[0].text)["_meta_unencrypted"]
    assert set(meta) - V1_META_KEYS == {"domain"}


async def test_a_file_round_tripped_by_an_old_version_still_works(server):
    """The mixed-version case, pinned.

    sops-mcp 0.10.1 reads a file this version writes, then rebuilds the
    metadata block from its own schema on the next mutation — dropping
    `domain` and re-encrypting. The result is a v1-shaped file, which this
    version must still accept.

    Note the drop has to be modelled as decrypt-rebuild-encrypt rather
    than a textual edit: sops MACs unencrypted values, so deleting the
    line from the ciphertext would fail to decrypt rather than reproduce
    what an old version does.
    """
    domain = server.domains["default"]
    created = await server._create_secrets(
        {"secrets": [{"key_name": "TOKEN", "source": "generated", "length": 8}]}
    )
    blob = created[0].text
    original = server.encryptor.decrypt(blob, domain)["TOKEN"]

    # What 0.10.1 writes back: the same content, its own metadata schema.
    plaintext = server.encryptor.decrypt(blob, domain)
    meta = dict(plaintext["_meta_unencrypted"])
    del meta["domain"]
    plaintext["_meta_unencrypted"] = meta
    as_v1 = server.encryptor.encrypt(plaintext, domain)
    assert set(yaml.safe_load(as_v1)["_meta_unencrypted"]) == V1_META_KEYS

    rotated = await server._rotate_generated(
        {"encrypted_content": as_v1, "key_names": ["TOKEN"]}
    )
    parsed = yaml.safe_load(rotated[0].text)
    assert parsed["_meta_unencrypted"]["domain"] == "default"
    assert server.encryptor.decrypt(rotated[0].text, domain)["TOKEN"] != original


@pytest.mark.parametrize(("tool", "extra"), MUTATIONS, ids=[m[0] for m in MUTATIONS])
async def test_metadata_version_is_preserved(server, v1_file, tool, extra):
    handler = getattr(server, f"_{tool}")
    result = await handler({"encrypted_content": v1_file, **extra})
    assert yaml.safe_load(result[0].text)["_meta_unencrypted"]["version"] == 1


# --- 3. no tool gained a required argument -------------------------------


async def _tool_schemas(server):
    from mcp.types import ListToolsRequest

    result = await server.server.request_handlers[ListToolsRequest](
        ListToolsRequest(method="tools/list")
    )
    return {t.name: t.inputSchema for t in result.root.tools}


async def test_tool_required_arguments_are_unchanged(server):
    """A v1 client sends no 'domain'; its calls must still validate."""
    schemas = await _tool_schemas(server)
    actual = {name: set(s.get("required", [])) for name, s in schemas.items()}
    assert actual == EXPECTED_REQUIRED


async def test_domain_is_optional_on_every_pre_existing_tool(server):
    schemas = await _tool_schemas(server)
    for name, schema in schemas.items():
        if name in {"sops_rekey", "sops_list_domains"}:
            continue
        assert "domain" not in schema.get("required", []), name
        assert "domain" in schema["properties"], name


async def test_no_tool_was_removed(server):
    """Every v1 tool still exists under the same name."""
    schemas = await _tool_schemas(server)
    v1_tools = set(EXPECTED_REQUIRED) - {"sops_list_domains", "sops_rekey"}
    assert v1_tools <= set(schemas)
