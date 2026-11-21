"""Validation of input that is written into SOPS files (#58).

Python's `$` also matches just before a trailing newline, so a pattern
applied with `.match()` lets `NAME\\n` through; every name check here uses
`fullmatch`. And `SopsEncryptor.encrypt()` refuses a root key no tool may
write, as a last guard behind the handlers' own checks.
"""

import pytest

from sops_mcp.domains import DomainConfigError, _validate_domain
from sops_mcp.server import _process_batch, _validate_key_name
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
    with pytest.raises(SopsError, match="invalid key name") as excinfo:
        SopsEncryptor().encrypt({key: "value"}, make_domain())
    # The unchecked key is not echoed back.
    assert str(key).strip() not in str(excinfo.value)


def test_encrypt_refuses_data_that_is_not_a_mapping(monkeypatch):
    monkeypatch.setattr(
        "sops_mcp.sops.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("sops ran")),
    )
    with pytest.raises(SopsError, match="not a mapping"):
        SopsEncryptor().encrypt(["A"], make_domain())  # type: ignore[arg-type]
