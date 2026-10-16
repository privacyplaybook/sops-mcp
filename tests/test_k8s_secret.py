"""sops_create_k8s_secret, and every other tool's handling of its output.

The integration half runs the real sops CLI with a throwaway age key and
proves three things: `sops -d` turns the result into an applyable Secret
manifest with the values at their nested paths; what kubectl reads before
decryption (apiVersion, kind, metadata, type) stays plaintext; and every
mutation tool refuses the file, from its envelope alone.

The unit half needs no sops binary: the refusal is decided before any
decryption, so a hand-made envelope is enough to exercise it.
"""

import hashlib
import json
import os
import subprocess

import pytest
import yaml
from mcp.types import CallToolRequest, CallToolRequestParams

from sops_mcp.domains import Domain
from sops_mcp.server import K8S_META_ANNOTATION, SopsMcpServer
from sops_mcp.sops import (
    K8S_ENCRYPTED_REGEX,
    SopsEncryptor,
    encryption_mode_features,
    unsupported_key_features,
)
from tests.helpers import DUMMY_RECIPIENT, make_server

EXTERNAL_VALUE = "s3cr3t-external-value"

# Every tool that re-encrypts a file, with arguments that would otherwise
# be valid for a flat file holding DB_PASSWORD.
MUTATIONS = {
    "sops_rotate_generated": {},
    "sops_add_secrets": {
        "secrets": [{"key_name": "NEW_KEY", "source": "generated"}],
    },
    "sops_add_metadata": {
        "secret_metadata": {"DB_PASSWORD": {"source": "generated"}},
    },
    "sops_delete_secrets": {"key_names": ["DB_PASSWORD"]},
    "sops_rename_secret": {"old_name": "DB_PASSWORD", "new_name": "DB_PASS"},
    "sops_update_external": {"key_name": "API_TOKEN", "value": "changed"},
    "sops_rekey": {"domain": "default"},
}


def _require(binary: str) -> None:
    if subprocess.run(
        ["which", binary], capture_output=True, check=False
    ).returncode:
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
        ["age-keygen", "-y"], input=ident, capture_output=True, text=True,
        check=True,
    ).stdout.strip()
    return ident, pub


async def _call(server: SopsMcpServer, name: str, arguments: dict) -> list:
    """Go through the MCP dispatcher, as a client would."""
    handler = server.server.request_handlers[CallToolRequest]
    result = await handler(
        CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name=name, arguments=arguments),
        )
    )
    return [c.text for c in result.root.content]


@pytest.fixture
def keys():
    _require("sops")
    _require("age-keygen")
    return _keypair()


@pytest.fixture
def server(keys):
    ident, pub = keys
    return SopsMcpServer(
        SopsEncryptor(), {"default": Domain("default", (pub,), (ident,))}
    )


def _sops_decrypt(content: str, ident: str, tmp_path) -> dict:
    """Decrypt with the sops CLI itself, as ksops or Flux would."""
    enc = tmp_path / "secret.enc.yaml"
    enc.write_text(content)
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    out = subprocess.run(
        ["sops", "--config", str(empty), "decrypt", str(enc)],
        capture_output=True, text=True, check=True,
        env={
            **{k: v for k, v in os.environ.items() if not k.startswith("SOPS_")},
            "SOPS_AGE_KEY": ident,
            "HOME": str(tmp_path),
        },
    )
    return yaml.safe_load(out.stdout)


@pytest.fixture
async def manifest(server):
    return [
        r.text
        for r in await server._create_k8s_secret({
            "name": "web-app",
            "namespace": "prod",
            "labels": {"app.kubernetes.io/name": "web"},
            "annotations": {"example.com/owner": "team-a"},
            "secrets": [
                {
                    "key_name": "DB_PASSWORD",
                    "source": "generated",
                    "length": 24,
                    "description": "database password",
                },
                {
                    "key_name": "API_TOKEN",
                    "source": "external",
                    "value": EXTERNAL_VALUE,
                },
                {
                    "key_name": "DB_PASSWORD_HASH",
                    "source": "derived",
                    "transform": "sha256_hex",
                    "from": "DB_PASSWORD",
                },
            ],
        })
    ]


# --- integration: real sops -----------------------------------------------


async def test_sops_decrypt_yields_an_applyable_secret(
    server, keys, manifest, tmp_path
):
    plain = _sops_decrypt(manifest[0], keys[0], tmp_path)

    # Exactly the fields a v1 Secret has, so kubectl's strict validation
    # has nothing to reject: no root _meta_unencrypted, no sops block.
    assert set(plain) == {"apiVersion", "kind", "metadata", "type", "stringData"}
    assert plain["apiVersion"] == "v1"
    assert plain["kind"] == "Secret"
    assert plain["type"] == "Opaque"
    assert plain["metadata"]["name"] == "web-app"
    assert plain["metadata"]["namespace"] == "prod"
    assert plain["metadata"]["labels"] == {"app.kubernetes.io/name": "web"}

    data = plain["stringData"]
    assert list(data) == ["DB_PASSWORD", "API_TOKEN", "DB_PASSWORD_HASH"]
    assert len(data["DB_PASSWORD"]) == 24
    assert data["API_TOKEN"] == EXTERNAL_VALUE
    assert data["DB_PASSWORD_HASH"] == hashlib.sha256(
        data["DB_PASSWORD"].encode()
    ).hexdigest()


async def test_kubectl_fields_stay_plaintext(manifest):
    enc = yaml.safe_load(manifest[0])

    assert enc["apiVersion"] == "v1"
    assert enc["kind"] == "Secret"
    assert enc["type"] == "Opaque"
    assert enc["metadata"]["name"] == "web-app"
    assert enc["metadata"]["namespace"] == "prod"
    assert enc["metadata"]["labels"] == {"app.kubernetes.io/name": "web"}
    assert enc["metadata"]["annotations"]["example.com/owner"] == "team-a"
    assert enc["sops"]["encrypted_regex"] == K8S_ENCRYPTED_REGEX
    assert "_meta_unencrypted" not in enc
    for key, value in enc["stringData"].items():
        assert value.startswith("ENC[AES256_GCM,"), key


async def test_metadata_annotation_holds_no_value(server, keys, manifest, tmp_path):
    plain = _sops_decrypt(manifest[0], keys[0], tmp_path)
    raw = plain["metadata"]["annotations"][K8S_META_ANNOTATION]
    meta = json.loads(raw)

    assert meta["domain"] == "default"
    assert meta["secrets"]["DB_PASSWORD"]["source"] == "generated"
    assert meta["secrets"]["DB_PASSWORD"]["generation"]["length"] == 24
    assert meta["secrets"]["API_TOKEN"] == {"source": "external"}
    assert meta["secrets"]["DB_PASSWORD_HASH"]["derivation"] == {
        "transform": "sha256_hex", "from": "DB_PASSWORD",
    }
    for value in plain["stringData"].values():
        assert value not in raw


async def test_no_plaintext_crosses_the_boundary(server, keys, manifest, tmp_path):
    plain = _sops_decrypt(manifest[0], keys[0], tmp_path)
    returned = "\n".join(manifest)

    assert EXTERNAL_VALUE not in returned
    assert plain["stringData"]["DB_PASSWORD"] not in returned
    # Derived values are the documented exception, as for flat files.
    assert plain["stringData"]["DB_PASSWORD_HASH"] in manifest[-1]


async def test_mac_covers_the_plaintext_metadata(server, keys, manifest, tmp_path):
    tampered = manifest[0].replace("namespace: prod", "namespace: other")
    assert tampered != manifest[0]
    with pytest.raises(subprocess.CalledProcessError):
        _sops_decrypt(tampered, keys[0], tmp_path)


@pytest.mark.parametrize("tool", sorted(MUTATIONS))
async def test_every_mutation_refuses_the_manifest(server, manifest, tool):
    texts = await _call(
        server, tool, {"encrypted_content": manifest[0], **MUTATIONS[tool]}
    )
    assert len(texts) == 1
    assert texts[0].startswith("Error: This is a Kubernetes Secret manifest")
    assert "create-only" in texts[0]


async def test_list_secrets_reads_the_manifest(server, manifest):
    texts = await _call(
        server, "sops_list_secrets", {"encrypted_content": manifest[0]}
    )
    out = texts[0]
    assert "Kubernetes Secret prod/web-app (type: Opaque)" in out
    assert "Create-only" in out
    assert "DB_PASSWORD " in out
    assert "generated" in out
    assert "database password" in out
    assert "API_TOKEN" in out
    assert "derived" in out
    assert "Domain: default" in out
    assert "Recipients match the configured domain." in out
    # Neither the manifest's own fields nor the envelope read as secrets.
    for field in ("apiVersion", "kind ", "stringData", "sops "):
        assert field not in out.split("Secrets in file:")[1]
    assert "WARNING" not in out


async def test_list_secrets_flags_recipients_that_moved_on(keys, manifest):
    ident, _ = keys
    _, other_pub = _keypair()
    moved = SopsMcpServer(
        SopsEncryptor(),
        {"default": Domain("default", (other_pub,), (ident,))},
    )
    texts = await _call(
        moved, "sops_list_secrets", {"encrypted_content": manifest[0]}
    )
    assert "do not match domain 'default'" in texts[0]
    assert "sops_create_k8s_secret" in texts[0]
    assert "sops_rekey" not in texts[0]


async def test_typed_secret_with_kubernetes_key_names(server, keys, tmp_path):
    texts = await _call(server, "sops_create_k8s_secret", {
        "name": "registry",
        "type": "kubernetes.io/dockerconfigjson",
        "secrets": [{
            "key_name": ".dockerconfigjson",
            "source": "external",
            "value": '{"auths":{}}',
        }],
    })
    plain = _sops_decrypt(texts[0], keys[0], tmp_path)
    assert plain["type"] == "kubernetes.io/dockerconfigjson"
    assert plain["stringData"] == {".dockerconfigjson": '{"auths":{}}'}
    assert "namespace" not in plain["metadata"]
    assert "labels" not in plain["metadata"]


# --- unit: no sops binary needed --------------------------------------------


def _fake_manifest(**envelope_extra) -> str:
    """A manifest whose envelope looks like sops wrote it in regex mode."""
    envelope = {
        "age": [{"recipient": DUMMY_RECIPIENT, "enc": "x"}],
        "pgp": [],
        "kms": [],
        "encrypted_regex": K8S_ENCRYPTED_REGEX,
        "unencrypted_suffix": "_unencrypted",
        "version": "3.9.4",
        **envelope_extra,
    }
    return yaml.safe_dump({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "x"},
        "type": "Opaque",
        "stringData": {"DB_PASSWORD": "ENC[AES256_GCM,data:x]"},
        "sops": envelope,
    })


@pytest.mark.parametrize("tool", sorted(MUTATIONS))
async def test_refusal_is_decided_from_the_envelope(tool):
    """The dummy server holds no private key, so reaching decryption would
    give a different error: the refusal must come first."""
    texts = await _call(
        make_server(), tool,
        {"encrypted_content": _fake_manifest(), **MUTATIONS[tool]},
    )
    assert texts[0].startswith("Error: This is a Kubernetes Secret manifest")


@pytest.mark.parametrize(
    "extra",
    [
        {"encrypted_regex": None, "unencrypted_regex": "^kind$"},
        {"encrypted_regex": None, "encrypted_suffix": "_enc"},
        {"encrypted_regex": None, "unencrypted_suffix": "_plain"},
        {"encrypted_regex": "^password$"},
        {"encrypted_regex": None, "encrypted_comment_regex": "^ENC"},
    ],
)
async def test_other_encryption_modes_are_refused(extra):
    content = _fake_manifest(**extra)
    texts = await _call(
        make_server(), "sops_rotate_generated", {"encrypted_content": content}
    )
    assert texts[0].startswith("Error: File chooses which values sops encrypts")


def test_encryption_mode_features():
    flat = yaml.safe_dump({"sops": {"unencrypted_suffix": "_unencrypted"}})
    assert encryption_mode_features(flat) == ()
    assert unsupported_key_features(flat) == ()
    assert encryption_mode_features(_fake_manifest()) == ("encrypted_regex",)
    assert "encrypted_regex" in unsupported_key_features(_fake_manifest())
    odd = yaml.safe_dump({"sops": {"unencrypted_suffix": "_plain"}})
    assert encryption_mode_features(odd) == ("unencrypted_suffix",)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"name": "Bad_Name"}, "Invalid Secret name"),
        ({"name": "ok", "namespace": "a.b"}, "Invalid namespace"),
        ({"name": "ok", "labels": {"data": "x"}}, "not allowed"),
        ({"name": "ok", "annotations": {"stringData": "x"}}, "not allowed"),
        ({"name": "ok", "labels": {"app": "has space"}}, "Invalid value for label"),
        ({"name": "ok", "labels": {"app": 3}}, "string value"),
        ({"name": "ok", "labels": {"/x": "y"}}, "empty prefix"),
        (
            {"name": "ok", "annotations": {K8S_META_ANNOTATION: "{}"}},
            "is reserved",
        ),
        ({"name": "ok", "type": "bad type"}, "Invalid Secret type"),
    ],
)
async def test_manifest_fields_are_validated(arguments, message):
    """Called directly: the MCP layer's schema check would catch some of
    these first, and the handler must not rely on it."""
    arguments = {
        "secrets": [{"key_name": "K", "source": "generated"}], **arguments,
    }
    with pytest.raises(ValueError, match=message):
        await make_server()._create_k8s_secret(arguments)


@pytest.mark.parametrize("key", ["..x", ".", "has space", "a/b", ""])
async def test_secret_keys_follow_kubernetes_rules(key):
    texts = await _call(make_server(), "sops_create_k8s_secret", {
        "name": "ok",
        "secrets": [{"key_name": key, "source": "generated"}],
    })
    assert texts[0].startswith("Error: Invalid Secret key")


async def test_duplicate_keys_are_refused():
    texts = await _call(make_server(), "sops_create_k8s_secret", {
        "name": "ok",
        "secrets": [
            {"key_name": "K", "source": "generated"},
            {"key_name": "K", "source": "external", "value": "v"},
        ],
    })
    assert texts[0] == "Error: Duplicate key names: K"


async def test_malformed_annotation_lists_as_unknown():
    content = _fake_manifest()
    parsed = yaml.safe_load(content)
    parsed["metadata"]["annotations"] = {K8S_META_ANNOTATION: "not json"}
    texts = await _call(
        make_server(), "sops_list_secrets",
        {"encrypted_content": yaml.safe_dump(parsed)},
    )
    assert "DB_PASSWORD" in texts[0]
    assert "unknown" in texts[0]
