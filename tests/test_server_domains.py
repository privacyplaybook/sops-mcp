"""Server-level domain behaviour: resolution, the recipient guard, rekey.

Exercises the real sops CLI so the recipient guard is checked against
envelopes sops actually produced.
"""

import subprocess

import pytest
import yaml

from sops_mcp.domains import Domain
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor


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
        line.strip() for line in out.splitlines() if line.startswith("AGE-SECRET-KEY-")
    )
    pub = subprocess.run(
        ["age-keygen", "-y"], input=ident, capture_output=True, text=True, check=True
    ).stdout.strip()
    return ident, pub


@pytest.fixture
def env():
    """Two single-recipient domains plus a two-recipient 'shared' domain."""
    _require("sops")
    _require("age-keygen")
    ident_a, pub_a = _keypair()
    ident_b, pub_b = _keypair()
    domains = {
        "alpha": Domain("alpha", (pub_a,), (ident_a,)),
        "beta": Domain("beta", (pub_b,), (ident_b,)),
        "shared": Domain("shared", (pub_a, pub_b), (ident_a,)),
        "default": Domain("default", (pub_a,), (ident_a,)),
    }
    return SopsMcpServer(SopsEncryptor(), domains)


SPEC = {"secrets": [{"key_name": "TOKEN", "source": "generated", "length": 16}]}


async def _create(server, domain=None):
    args = dict(SPEC)
    if domain:
        args["domain"] = domain
    result = await server._create_secrets(args)
    return result[0].text


# --- domain stamping and resolution --------------------------------------


async def test_create_stamps_domain_into_metadata(env):
    blob = await _create(env, "alpha")
    assert yaml.safe_load(blob)["_meta_unencrypted"]["domain"] == "alpha"


async def test_create_without_domain_uses_default(env):
    blob = await _create(env)
    assert yaml.safe_load(blob)["_meta_unencrypted"]["domain"] == "default"


async def test_mutation_follows_the_recorded_domain(env):
    """No 'domain' argument: the file's own metadata selects the key."""
    blob = await _create(env, "beta")
    rotated = await env._rotate_generated(
        {"encrypted_content": blob, "key_names": ["TOKEN"]}
    )
    assert yaml.safe_load(rotated[0].text)["_meta_unencrypted"]["domain"] == "beta"


async def test_explicit_argument_overrides_the_recorded_domain(env):
    """An alpha file mislabelled 'beta' is still refused, not mis-keyed."""
    blob = await _create(env, "alpha")
    tampered = blob.replace("domain: alpha", "domain: beta")

    with pytest.raises(ValueError, match="do not match domain 'beta'"):
        await env._rotate_generated(
            {"encrypted_content": tampered, "key_names": ["TOKEN"]}
        )


async def test_tampered_domain_hint_cannot_redirect_reencryption(env):
    """The recipient guard is what makes trusting the plaintext hint safe."""
    blob = await _create(env, "alpha")
    tampered = blob.replace("domain: alpha", "domain: shared")

    with pytest.raises(ValueError, match="Refusing to re-encrypt"):
        await env._rotate_generated(
            {"encrypted_content": tampered, "key_names": ["TOKEN"]}
        )


async def test_unknown_domain_is_reported_with_the_configured_list(env):
    with pytest.raises(ValueError, match="Unknown domain 'nope'"):
        await _create(env, "nope")


async def test_require_domain_mode_rejects_the_fallback(env):
    strict = SopsMcpServer(env.encryptor, env.domains, require_domain=True)
    with pytest.raises(ValueError, match="SOPS_MCP_REQUIRE_DOMAIN"):
        await _create(strict)


# --- the recipient guard --------------------------------------------------


async def test_mismatched_recipients_refuse_every_mutation(env):
    """This is the bug the design set out to fix: silent recipient drop."""
    blob = await _create(env, "shared")
    mislabelled = blob.replace("domain: shared", "domain: alpha")

    calls = [
        (env._rotate_generated, {"key_names": ["TOKEN"]}),
        (env._delete_secrets, {"key_names": ["TOKEN"]}),
        (env._rename_secret, {"old_name": "TOKEN", "new_name": "TOKEN2"}),
        (env._add_secrets, {"secrets": [
            {"key_name": "OTHER", "source": "external", "value": "x"}
        ]}),
    ]
    for handler, extra in calls:
        with pytest.raises(ValueError, match="Refusing to re-encrypt"):
            await handler({"encrypted_content": mislabelled, **extra})


async def test_guard_message_does_not_list_other_domains_recipients(env):
    blob = await _create(env, "shared")
    mislabelled = blob.replace("domain: shared", "domain: alpha")

    with pytest.raises(ValueError) as excinfo:
        await env._rotate_generated(
            {"encrypted_content": mislabelled, "key_names": ["TOKEN"]}
        )
    message = str(excinfo.value)
    for domain in env.domains.values():
        for recipient in domain.recipients:
            assert recipient not in message


async def test_matching_recipients_allow_mutation(env):
    blob = await _create(env, "shared")
    rotated = await env._rotate_generated(
        {"encrypted_content": blob, "key_names": ["TOKEN"], "domain": "shared"}
    )
    assert len(yaml.safe_load(rotated[0].text)["sops"]["age"]) == 2


# --- sops_rekey -----------------------------------------------------------


async def test_rekey_adds_a_recipient(env):
    """The updatekeys workflow: widen a domain, then rekey the file."""
    blob = await _create(env, "alpha")
    assert len(yaml.safe_load(blob)["sops"]["age"]) == 1

    # alpha's key also opens 'shared', which has both recipients.
    result = await env._rekey({"encrypted_content": blob, "domain": "shared"})
    rekeyed = result[0].text
    parsed = yaml.safe_load(rekeyed)
    assert len(parsed["sops"]["age"]) == 2
    assert parsed["_meta_unencrypted"]["domain"] == "shared"
    assert "1 added" in result[1].text


async def test_rekey_clears_the_mutation_refusal(env):
    blob = await _create(env, "alpha")
    rekeyed = (await env._rekey({"encrypted_content": blob, "domain": "shared"}))[0].text
    rotated = await env._rotate_generated(
        {"encrypted_content": rekeyed, "key_names": ["TOKEN"]}
    )
    assert len(yaml.safe_load(rotated[0].text)["sops"]["age"]) == 2


async def test_rekey_preserves_secret_values_and_metadata(env):
    created = await env._create_secrets({
        "secrets": [
            {"key_name": "TOKEN", "source": "generated", "length": 16},
            {"key_name": "USER", "source": "external", "value": "alice",
             "description": "the operator"},
        ],
        "domain": "alpha",
    })
    blob = created[0].text
    before = env.encryptor.decrypt(blob, env.domains["alpha"])

    rekeyed = (await env._rekey({"encrypted_content": blob, "domain": "shared"}))[0].text
    after = env.encryptor.decrypt(rekeyed, env.domains["shared"])

    assert after["TOKEN"] == before["TOKEN"]
    assert after["USER"] == "alice"
    meta = yaml.safe_load(rekeyed)["_meta_unencrypted"]["secrets"]
    assert meta["USER"]["description"] == "the operator"
    assert meta["TOKEN"]["generation"]["length"] == 16


async def test_rekey_cannot_move_a_file_between_domains(env):
    """beta's keys are the only ones offered, so an alpha file stays shut."""
    blob = await _create(env, "alpha")
    from sops_mcp.sops import SopsError

    with pytest.raises(SopsError, match="sops decrypt failed"):
        await env._rekey({"encrypted_content": blob, "domain": "beta"})


async def test_rekey_requires_an_explicit_domain(env):
    blob = await _create(env, "alpha")
    with pytest.raises(ValueError, match="requires an explicit 'domain'"):
        await env._rekey({"encrypted_content": blob})


async def test_rekey_reports_removed_recipients(env):
    blob = await _create(env, "shared")
    result = await env._rekey({"encrypted_content": blob, "domain": "alpha"})
    assert len(yaml.safe_load(result[0].text)["sops"]["age"]) == 1
    assert "1 removed" in result[1].text
    assert "can no longer read" in result[1].text


# --- sops_list_domains ----------------------------------------------------


async def test_list_domains_shows_recipients_never_keys(env):
    text = (await env._list_domains({}))[0].text
    for domain in env.domains.values():
        for key in domain.keys:
            assert key not in text
        for recipient in domain.recipients:
            assert recipient in text
    assert "encrypt-only" not in text  # every fixture domain holds a key


async def test_list_domains_marks_encrypt_only(env):
    env.domains["archive"] = Domain("archive", env.domains["beta"].recipients)
    text = (await env._list_domains({}))[0].text
    assert "archive  (encrypt-only)" in text


# --- sops_list_secrets reporting -----------------------------------------


async def test_list_secrets_reports_a_matching_domain(env):
    blob = await _create(env, "shared")
    text = (await env._list_secrets({"encrypted_content": blob}))[0].text
    assert "Domain: shared" in text
    assert "Recipients: 2" in text
    assert "Recipients match the configured domain." in text


async def test_list_secrets_warns_on_mismatch_before_a_mutation_fails(env):
    blob = await _create(env, "shared")
    mislabelled = blob.replace("domain: shared", "domain: alpha")
    text = (await env._list_secrets({"encrypted_content": mislabelled}))[0].text
    assert "WARNING" in text
    assert "run sops_rekey" in text


async def test_list_secrets_warns_on_unconfigured_domain(env):
    blob = await _create(env, "alpha")
    mislabelled = blob.replace("domain: alpha", "domain: ghost")
    text = (await env._list_secrets({"encrypted_content": mislabelled}))[0].text
    assert "is not configured on this server" in text


# --- tool surface ---------------------------------------------------------


async def test_every_tool_but_the_listing_accepts_a_domain(env):
    from mcp.types import ListToolsRequest

    result = await env.server.request_handlers[ListToolsRequest](
        ListToolsRequest(method="tools/list")
    )
    for tool in result.root.tools:
        properties = tool.inputSchema.get("properties", {})
        if tool.name == "sops_list_domains":
            assert "domain" not in properties
        else:
            assert "domain" in properties, tool.name


async def test_rekey_requires_domain_in_its_schema(env):
    from mcp.types import ListToolsRequest

    result = await env.server.request_handlers[ListToolsRequest](
        ListToolsRequest(method="tools/list")
    )
    rekey = next(t for t in result.root.tools if t.name == "sops_rekey")
    assert set(rekey.inputSchema["required"]) == {"encrypted_content", "domain"}


# --- v1 files -------------------------------------------------------------


def _legacy_file(env, domain_name):
    """A genuine pre-domains file: valid MAC, no 'domain' in its metadata."""
    return env.encryptor.encrypt(
        {
            "TOKEN": "old-value",
            "_meta_unencrypted": {
                "version": 1,
                "secrets": {
                    "TOKEN": {
                        "source": "generated",
                        "generation": {"length": 9, "charset": "alphanumeric"},
                    }
                },
            },
        },
        env.domains[domain_name],
    )


async def test_v1_file_without_a_recorded_domain_still_rotates(env):
    """A pre-domains file whose recipients match 'default' works untouched."""
    legacy = _legacy_file(env, "default")

    rotated = await env._rotate_generated(
        {"encrypted_content": legacy, "key_names": ["TOKEN"]}
    )
    assert yaml.safe_load(rotated[0].text)["_meta_unencrypted"]["domain"] == "default"


async def test_v1_file_for_another_key_is_refused_not_silently_rekeyed(env):
    """The one behaviour change: this used to drop the original recipient.

    Before domains, a mutation re-encrypted to whatever the server was
    configured with, so a file belonging to another key came back readable
    only by this server's key, with no error.
    """
    legacy = _legacy_file(env, "beta")

    with pytest.raises(ValueError, match="Refusing to re-encrypt"):
        await env._rotate_generated(
            {"encrypted_content": legacy, "key_names": ["TOKEN"]}
        )
