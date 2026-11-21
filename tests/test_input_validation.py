"""Validation of input that is written into SOPS files (#58).

Python's `$` also matches just before a trailing newline, so a pattern
applied with `.match()` lets `NAME\\n` through; every name check here uses
`fullmatch`. And `SopsEncryptor.encrypt()` refuses a root key no tool may
write, as a last guard behind the handlers' own checks.
"""

import subprocess

import pytest

from sops_mcp import server as server_module
from sops_mcp.domains import DomainConfigError, _validate_domain, load_domains
from sops_mcp.server import SopsMcpServer, _process_batch, _validate_key_name
from sops_mcp.sops import SopsEncryptor, SopsError
from tests.helpers import DUMMY_RECIPIENT, make_domain, make_server

# --- key names -------------------------------------------------------------


@pytest.mark.parametrize("name", ["DB_PASSWORD\n", "DB_PASSWORD\r\n", "A\nB"])
def test_key_name_with_newline_is_refused(name):
    with pytest.raises(ValueError, match="Invalid key name"):
        _validate_key_name(name)


def test_key_name_that_is_not_a_string_is_a_validation_error():
    with pytest.raises(ValueError, match="Invalid key name"):
        _validate_key_name(123)  # type: ignore[arg-type]


def test_valid_key_name_passes():
    _validate_key_name("DB_PASSWORD")


async def test_create_secrets_refuses_key_name_with_newline():
    with pytest.raises(ValueError, match="Invalid key name"):
        await make_server()._create_secrets({
            "secrets": [{"key_name": "DB_PASSWORD\n", "source": "generated"}],
        })


# --- domain names ----------------------------------------------------------


@pytest.mark.parametrize("name", ["prod\n", "prod\r\n"])
def test_domain_name_with_newline_is_refused(name):
    with pytest.raises(DomainConfigError, match="invalid domain name"):
        _validate_domain(name, (DUMMY_RECIPIENT,), ())


def test_valid_domain_name_passes():
    assert _validate_domain("prod", (DUMMY_RECIPIENT,), ()).name == "prod"


# --- spec shape ------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "field"),
    [
        ({"source": "generated"}, "key_name"),
        ({"key_name": None, "source": "generated"}, "key_name"),
        ({"key_name": "DB_PASSWORD"}, "source"),
    ],
)
def test_process_batch_refuses_spec_missing_a_field(spec, field):
    with pytest.raises(ValueError, match=f"Secret 1 needs a '{field}'"):
        _process_batch([spec], {}, {}, "now")


def test_process_batch_refuses_spec_that_is_not_an_object():
    with pytest.raises(ValueError, match="Secret 1 is not an object"):
        _process_batch(["DB_PASSWORD"], {}, {}, "now")  # type: ignore[list-item]


async def test_create_secrets_refuses_spec_without_key_name():
    with pytest.raises(ValueError, match="needs a 'key_name'"):
        await make_server()._create_secrets({
            "secrets": [{"source": "generated"}],
        })


async def test_add_secrets_refuses_spec_without_key_name():
    with pytest.raises(ValueError, match="needs a 'key_name'"):
        await make_server()._add_secrets({
            "encrypted_content": "A: 1\n",
            "secrets": [{"source": "generated"}],
        })


async def test_create_k8s_secret_refuses_spec_without_key_name():
    with pytest.raises(ValueError, match="needs a 'key_name'"):
        await make_server()._create_k8s_secret({
            "name": "web",
            "secrets": [{"source": "generated"}],
        })


# --- encrypt() guard -------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "db_password",
        "DB_PASSWORD\n",
        "_other_unencrypted",
        "sops",
        123,
    ],
)
def test_encrypt_refuses_invalid_root_key(key, monkeypatch):
    def no_sops(*_args, **_kwargs):
        raise AssertionError("sops must not run")

    monkeypatch.setattr("sops_mcp.sops.subprocess.run", no_sops)
    with pytest.raises(SopsError, match="invalid key name"):
        SopsEncryptor().encrypt({key: "value"}, make_domain())


def test_encrypt_guard_names_the_key_escaped(monkeypatch):
    monkeypatch.setattr(
        "sops_mcp.sops.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("sops ran")),
    )
    with pytest.raises(SopsError) as excinfo:
        SopsEncryptor().encrypt({"DB_PASSWORD\n": "v"}, make_domain())
    assert "'DB_PASSWORD\\n'" in str(excinfo.value)


def test_encrypt_refuses_a_new_key_even_when_others_are_carried(monkeypatch):
    monkeypatch.setattr(
        "sops_mcp.sops.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("sops ran")),
    )
    with pytest.raises(SopsError, match="invalid key name 'new_key'"):
        SopsEncryptor().encrypt(
            {"db_url": "a", "new_key": "b"}, make_domain(), carried={"db_url"}
        )


def test_encrypt_refuses_data_that_is_not_a_mapping(monkeypatch):
    monkeypatch.setattr(
        "sops_mcp.sops.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("sops ran")),
    )
    with pytest.raises(SopsError, match="not a mapping"):
        SopsEncryptor().encrypt(["A"], make_domain())  # type: ignore[arg-type]


# --- legacy files through the handlers (real sops) --------------------------


def _require(binary: str) -> None:
    if subprocess.run(
        ["which", binary], capture_output=True, check=False
    ).returncode != 0:
        pytest.skip(f"{binary} not installed")


@pytest.fixture
def real_server(tmp_path, monkeypatch):
    _require("sops")
    _require("age-keygen")
    out = subprocess.run(
        ["age-keygen"], capture_output=True, text=True, check=True
    ).stdout
    private = next(
        line for line in out.splitlines() if line.startswith("AGE-SECRET-KEY-")
    )
    public = next(
        line.split(": ", 1)[1]
        for line in out.splitlines()
        if line.startswith("# public key: ")
    )
    monkeypatch.setenv("SOPS_AGE_KEY", private)
    monkeypatch.setenv("SOPS_MCP_AGE_PUBLIC_KEY", public)
    return SopsMcpServer(SopsEncryptor(), load_domains())


@pytest.fixture
def legacy_file(real_server):
    """A file made with the sops CLI: lowercase keys, no metadata block."""
    return real_server.encryptor.encrypt(
        {"db_user": "alice", "db_pass": "hunter2"},
        real_server.domains["default"],
        carried={"db_user", "db_pass"},
    )


async def test_legacy_keys_survive_rekey(real_server, legacy_file):
    result = await real_server._rekey(
        {"encrypted_content": legacy_file, "domain": "default"}
    )
    after = real_server.encryptor.decrypt(
        result[0].text, real_server.domains["default"]
    )
    assert after == {"db_user": "alice", "db_pass": "hunter2"}


async def test_legacy_keys_can_be_renamed_one_at_a_time(real_server, legacy_file):
    result = await real_server._rename_secret({
        "encrypted_content": legacy_file,
        "old_name": "db_user",
        "new_name": "DB_USER",
    })
    after = real_server.encryptor.decrypt(
        result[0].text, real_server.domains["default"]
    )
    assert after["DB_USER"] == "alice"
    assert after["db_pass"] == "hunter2"


async def test_guard_catches_a_handler_that_skips_validation(
    real_server, legacy_file, monkeypatch
):
    """With the handler's own check disabled, encrypt() still refuses."""
    monkeypatch.setattr(server_module, "_validate_key_name", lambda _name: None)
    with pytest.raises(SopsError, match="invalid key name 'bad_name'"):
        await real_server._rename_secret({
            "encrypted_content": legacy_file,
            "old_name": "db_user",
            "new_name": "bad_name",
        })
