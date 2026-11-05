"""sops_copy_secret: a value moves from one file to another, server-side.

Runs against the real sops CLI. The property that matters most is the one
the server exists for: the copied plaintext never reaches the client, in
a result, an error, or a log line.
"""

import logging
import subprocess

import pytest
import yaml
from mcp.types import CallToolRequest, CallToolRequestParams

from sops_mcp.domains import Domain
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor

# Distinctive, so a substring search cannot match anything by accident.
PLAINTEXT = "cOpY-pl41ntext-9f3e1c7a"
DEST_PLAINTEXT = "dest-only-value-55b2"


def _require(binary: str) -> None:
    if subprocess.run(
        ["which", binary], capture_output=True, check=False
    ).returncode != 0:
        pytest.skip(f"{binary} not installed")


def _keypair() -> tuple[str, str]:
    out = subprocess.run(
        ["age-keygen"], capture_output=True, text=True, check=True
    ).stdout
    ident = next(
        line.strip() for line in out.splitlines()
        if line.startswith("AGE-SECRET-KEY-")
    )
    pub = subprocess.run(
        ["age-keygen", "-y"], input=ident, capture_output=True, text=True,
        check=True,
    ).stdout.strip()
    return ident, pub


@pytest.fixture
def server():
    _require("sops")
    _require("age-keygen")
    ident_a, pub_a = _keypair()
    ident_b, pub_b = _keypair()
    domains = {
        "default": Domain("default", (pub_a,), (ident_a,)),
        "beta": Domain("beta", (pub_b,), (ident_b,)),
    }
    srv = SopsMcpServer(SopsEncryptor(), domains)
    srv.test_pub_b = pub_b
    return srv


async def _call(server: SopsMcpServer, name: str, arguments: dict) -> list[str]:
    """Go through the MCP dispatcher, as a client would."""
    handler = server.server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name=name, arguments=arguments),
        )
    )
    return [c.text for c in result.root.content]


async def _source(server, domain=None) -> str:
    args = {
        "secrets": [
            {
                "key_name": "OLLAMA_TOKEN",
                "source": "external",
                "value": PLAINTEXT,
                "description": "Ollama bearer token",
            },
            {"key_name": "OTHER", "source": "generated", "length": 16},
        ]
    }
    if domain:
        args["domain"] = domain
    return (await server._create_secrets(args))[0].text


async def _dest(server, domain=None) -> str:
    args = {
        "secrets": [
            {"key_name": "DB_PASSWORD", "source": "external",
             "value": DEST_PLAINTEXT},
        ]
    }
    if domain:
        args["domain"] = domain
    return (await server._create_secrets(args))[0].text


def _decrypt(server, blob, domain="default") -> dict:
    return server.encryptor.decrypt(blob, server.domains[domain])


def _count_decrypts(server, monkeypatch) -> list[int]:
    calls = [0]
    real = server.encryptor.decrypt

    def counting(*args, **kwargs):
        calls[0] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(server.encryptor, "decrypt", counting)
    return calls


# --- the copy itself ------------------------------------------------------


async def test_copies_the_value_and_records_its_origin(server):
    source, dest = await _source(server), await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
        "key_name": "OLLAMA_TOKEN_PRIVATE_FEED",
        "source_repo": "owen/capsyshome",
        "source_file": "portainer/ollama/secrets.enc.yaml",
    })
    assert len(texts) == 2
    out = texts[0]

    values = _decrypt(server, out)
    assert values["OLLAMA_TOKEN_PRIVATE_FEED"] == PLAINTEXT
    assert values["DB_PASSWORD"] == DEST_PLAINTEXT
    assert "OLLAMA_TOKEN" not in values
    assert "OTHER" not in values

    meta = yaml.safe_load(out)["_meta_unencrypted"]
    assert meta["domain"] == "default"
    entry = meta["secrets"]["OLLAMA_TOKEN_PRIVATE_FEED"]
    assert entry["source"] == "copied"
    assert entry["description"] == "Ollama bearer token"
    assert entry["copied_from"] == {
        "key": "OLLAMA_TOKEN",
        "repo": "owen/capsyshome",
        "file": "portainer/ollama/secrets.enc.yaml",
    }
    assert "last_rotated" in entry
    assert meta["secrets"]["DB_PASSWORD"]["source"] == "external"
    assert "OLLAMA_TOKEN_PRIVATE_FEED: copied from OLLAMA_TOKEN" in texts[1]


async def test_key_name_defaults_to_source_key(server):
    source, dest = await _source(server), await _dest(server)
    out = (await server._copy_secret({
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
        "description": "mine",
    }))[0].text
    assert _decrypt(server, out)["OLLAMA_TOKEN"] == PLAINTEXT
    entry = yaml.safe_load(out)["_meta_unencrypted"]["secrets"]["OLLAMA_TOKEN"]
    assert entry["description"] == "mine"
    assert entry["copied_from"] == {"key": "OLLAMA_TOKEN"}


# --- plaintext never crosses the boundary -------------------------------


async def test_plaintext_is_in_no_result_and_no_log(server, caplog):
    source, dest = await _source(server), await _dest(server)
    with caplog.at_level(logging.DEBUG):
        texts = await _call(server, "sops_copy_secret", {
            "encrypted_content": dest,
            "source_content": source,
            "source_key": "OLLAMA_TOKEN",
        })
    assert not any(t.startswith("Error") for t in texts), texts
    for text in texts:
        assert PLAINTEXT not in text
        assert DEST_PLAINTEXT not in text
    assert PLAINTEXT not in caplog.text


async def test_plaintext_is_not_leaked_when_encryption_fails(
    server, caplog, monkeypatch
):
    """The value is in memory by then: the failure must not carry it."""
    source, dest = await _source(server), await _dest(server)

    def boom(data, domain, **kwargs):
        raise RuntimeError(f"encrypt failed for {sorted(data)}")

    monkeypatch.setattr(server.encryptor, "encrypt", boom)
    with caplog.at_level(logging.DEBUG):
        texts = await _call(server, "sops_copy_secret", {
            "encrypted_content": dest,
            "source_content": source,
            "source_key": "OLLAMA_TOKEN",
        })
    assert texts == ["Internal error — check the server log."]
    assert PLAINTEXT not in caplog.text
    assert DEST_PLAINTEXT not in caplog.text


# --- refusals --------------------------------------------------------------


async def test_refuses_an_existing_key_without_decrypting(server, monkeypatch):
    source = await _source(server)
    dest = await _dest(server)
    calls = _count_decrypts(server, monkeypatch)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
        "key_name": "DB_PASSWORD",
    })
    assert texts[0].startswith("Error: Key 'DB_PASSWORD' already exists")
    assert calls[0] == 0


async def test_refuses_a_missing_source_key_without_decrypting(
    server, monkeypatch
):
    source, dest = await _source(server), await _dest(server)
    calls = _count_decrypts(server, monkeypatch)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "NOPE",
    })
    assert texts[0] == "Error: Key 'NOPE' not found in source file"
    assert calls[0] == 0


@pytest.mark.parametrize("bad", ["lower_case", "1ABC", "A-B"])
async def test_validates_the_destination_key_name(server, bad):
    source, dest = await _source(server), await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
        "key_name": bad,
    })
    assert texts[0].startswith("Error: Invalid key name")


async def test_refuses_metadata_keys_as_source(server):
    source, dest = await _source(server), await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "_meta_unencrypted",
        "key_name": "META",
    })
    assert texts[0].startswith("Error: Key '_meta_unencrypted' not found")


async def test_refuses_to_copy_between_domains(server, monkeypatch):
    source = await _source(server, domain="beta")
    dest = await _dest(server)
    calls = _count_decrypts(server, monkeypatch)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
    })
    assert "only copies within one domain" in texts[0]
    assert calls[0] == 0


async def test_explicit_domain_does_not_bypass_the_recipient_check(server):
    """Naming one domain for both cannot pull a value out of another."""
    source = await _source(server, domain="beta")
    dest = await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
        "domain": "default",
    })
    assert texts[0].startswith("Error: Source file: File is encrypted to")
    assert PLAINTEXT not in texts[0]


async def test_refuses_a_source_readable_by_fewer_parties(server):
    """A source encrypted more narrowly than its domain would be widened."""
    default = server.domains["default"]
    wide = Domain("default", (*default.recipients, server.test_pub_b), default.keys)
    server.domains["default"] = wide
    dest = await _dest(server)
    # Same domain name, but only the first recipient can read the source.
    source = server.encryptor.encrypt(
        {
            "OLLAMA_TOKEN": PLAINTEXT,
            "_meta_unencrypted": {"version": 1, "domain": "default",
                                  "secrets": {}},
        },
        default,
    )
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
    })
    assert texts[0].startswith("Error: Source file: File is encrypted to 1")


async def test_refuses_a_destination_off_its_domain(server):
    dest = await _dest(server)
    source = await _source(server)
    old = server.domains["default"]
    server.domains["default"] = Domain(
        "default", (*old.recipients, server.test_pub_b), old.keys
    )
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
    })
    # The source is checked first; both are off the domain here.
    assert "do not match domain 'default'" in texts[0]


async def test_refuses_plaintext_source(server):
    dest = await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": f"OLLAMA_TOKEN: {PLAINTEXT}\n",
        "source_key": "OLLAMA_TOKEN",
    })
    assert texts[0].startswith("Error: Source content is not a SOPS")
    assert PLAINTEXT not in texts[0]


async def test_refuses_unparseable_source_without_echoing_it(server):
    dest = await _dest(server)
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": f"OLLAMA_TOKEN: [{PLAINTEXT}\n",
        "source_key": "OLLAMA_TOKEN",
    })
    assert texts == ["Error: Source content is not valid YAML"]


async def test_refuses_a_k8s_manifest_source(server):
    dest = await _dest(server)
    manifest = (await server._create_k8s_secret({
        "name": "web",
        "secrets": [{"key_name": "TOKEN", "source": "external",
                     "value": PLAINTEXT}],
    }))[0].text
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": manifest,
        "source_key": "TOKEN",
    })
    assert "Kubernetes Secret manifest" in texts[0]


@pytest.mark.parametrize("bad", ["a\nb", "a\x1bb", " lead", "x" * 257, 7])
async def test_validates_origin_fields(server, bad):
    """Called directly: the MCP layer would reject the int by schema."""
    source, dest = await _source(server), await _dest(server)
    with pytest.raises(ValueError, match="Invalid source_repo"):
        await server._copy_secret({
            "encrypted_content": dest,
            "source_content": source,
            "source_key": "OLLAMA_TOKEN",
            "source_repo": bad,
        })


async def test_require_domain_applies(server):
    server.require_domain = True
    source, dest = await _source(server, "default"), await _dest(server, "default")
    texts = await _call(server, "sops_copy_secret", {
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
    })
    assert "SOPS_MCP_REQUIRE_DOMAIN" in texts[0]


# --- how the other tools treat a copy ------------------------------------


async def _copied(server) -> str:
    source, dest = await _source(server), await _dest(server)
    return (await server._copy_secret({
        "encrypted_content": dest,
        "source_content": source,
        "source_key": "OLLAMA_TOKEN",
    }))[0].text


async def test_rotation_preserves_a_copy_and_says_so(server):
    out = await _rotate(server, await _copied(server))
    assert _decrypt(server, out[0])["OLLAMA_TOKEN"] == PLAINTEXT
    assert "Not rotated (copied from another file): OLLAMA_TOKEN" in out[1]


async def _rotate(server, blob) -> list[str]:
    return await _call(server, "sops_rotate_generated", {
        "encrypted_content": blob,
    })


async def test_update_external_refuses_a_copy(server):
    texts = await _call(server, "sops_update_external", {
        "encrypted_content": await _copied(server),
        "key_name": "OLLAMA_TOKEN",
        "value": "new",
    })
    assert "run sops_copy_secret again" in texts[0]


async def test_a_copy_can_be_refreshed_by_delete_then_copy(server):
    copied = await _copied(server)
    deleted = (await server._delete_secrets({
        "encrypted_content": copied, "key_names": ["OLLAMA_TOKEN"],
    }))[0].text
    rotated_source = (await server._rotate_generated({
        "encrypted_content": await _source(server),
    }))[0].text
    again = (await server._copy_secret({
        "encrypted_content": deleted,
        "source_content": rotated_source,
        "source_key": "OTHER",
    }))[0].text
    assert _decrypt(server, again)["OTHER"] == _decrypt(
        server, rotated_source
    )["OTHER"]


async def test_list_shows_the_copy(server):
    texts = await _call(server, "sops_list_secrets", {
        "encrypted_content": await _copied(server),
    })
    line = next(x for x in texts[0].splitlines() if x.startswith("OLLAMA_TOKEN"))
    assert "copied" in line
