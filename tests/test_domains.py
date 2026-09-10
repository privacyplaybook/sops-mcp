"""Tests for age key parsing and domain configuration loading."""

import json
import os
import textwrap

import pytest

from sops_mcp.age_keys import (
    AgeKeyError,
    is_plugin_identity,
    is_plugin_recipient,
    parse_recipient,
    recipient_from_identity,
    validate_recipient,
)
from sops_mcp.domains import (
    DEFAULT_DOMAIN,
    Domain,
    DomainConfigError,
    load_domains,
    require_explicit_domain,
)

# A real plugin recipient, from the age-plugin-yubikey README. Public key
# material only; there is no private half to leak.
YUBIKEY_RECIP = (
    "age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9csncp540s5ja0w4cq4dwnhw"
)


@pytest.fixture(scope="module")
def keypairs():
    """Two real age keypairs, from age-keygen when available."""
    import shutil
    import subprocess

    if not shutil.which("age-keygen"):
        pytest.skip("age-keygen not on PATH")

    pairs = []
    for _ in range(2):
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
        pairs.append((ident, pub))
    return pairs


# --- age_keys ------------------------------------------------------------


def test_recipient_derivation_matches_age_keygen(keypairs):
    for ident, pub in keypairs:
        assert recipient_from_identity(ident) == pub


def test_parse_recipient_returns_32_bytes(keypairs):
    _, pub = keypairs[0]
    assert len(parse_recipient(pub)) == 32


def test_recipient_is_case_insensitive(keypairs):
    _, pub = keypairs[0]
    assert parse_recipient(pub.upper()) == parse_recipient(pub)


def test_mixed_case_rejected(keypairs):
    _, pub = keypairs[0]
    mixed = pub[:10].upper() + pub[10:]
    with pytest.raises(AgeKeyError, match="mixes upper and lower"):
        parse_recipient(mixed)


def test_truncated_recipient_rejected(keypairs):
    _, pub = keypairs[0]
    with pytest.raises(AgeKeyError, match="checksum"):
        parse_recipient(pub[:-1])


def test_corrupted_recipient_not_mistaken_for_plugin(keypairs):
    """A typo that inserts a '1' must not be waved through as a plugin key."""
    _, pub = keypairs[0]
    corrupted = pub[:30] + "1" + pub[31:]
    with pytest.raises(AgeKeyError):
        validate_recipient(corrupted)


def test_identity_pasted_as_recipient_is_rejected_without_echoing(keypairs):
    ident, _ = keypairs[0]
    with pytest.raises(AgeKeyError) as excinfo:
        validate_recipient(ident)
    assert ident not in str(excinfo.value)
    assert ident.lower() not in str(excinfo.value).lower()


def test_plugin_recipient_accepted_but_not_derivable():
    assert is_plugin_recipient(YUBIKEY_RECIP)
    validate_recipient(YUBIKEY_RECIP)


def test_plugin_identity_detected(keypairs):
    ident, _ = keypairs[0]
    assert is_plugin_identity("AGE-PLUGIN-YUBIKEY-1ABC")
    assert not is_plugin_identity(ident)


def test_absurdly_long_input_rejected():
    with pytest.raises(AgeKeyError, match="implausibly long"):
        parse_recipient("age1" + "q" * 5000)


# --- Domain --------------------------------------------------------------


def test_domain_repr_hides_private_keys(keypairs):
    ident, pub = keypairs[0]
    domain = Domain(name="d", recipients=(pub,), keys=(ident,))
    assert ident not in repr(domain)
    assert "keys=1" in repr(domain)


def test_public_summary_excludes_key_material(keypairs):
    ident, pub = keypairs[0]
    domain = Domain(name="d", recipients=(pub,), keys=(ident,))
    summary = domain.public_summary()
    assert ident not in str(summary)
    assert summary["key_count"] == 1
    assert summary["recipients"] == [pub]
    assert summary["encrypt_only"] is False


def test_encrypt_only_when_no_keys(keypairs):
    _, pub = keypairs[0]
    assert Domain(name="d", recipients=(pub,)).encrypt_only is True


def test_age_argument_joins_recipients(keypairs):
    (_, pub_a), (_, pub_b) = keypairs
    domain = Domain(name="d", recipients=(pub_a, pub_b))
    assert domain.age_argument == f"{pub_a},{pub_b}"


# --- load_domains: environment -------------------------------------------


def test_v1_env_becomes_default_domain(keypairs):
    ident, pub = keypairs[0]
    domains = load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": pub, "SOPS_AGE_KEY": ident})
    assert set(domains) == {DEFAULT_DOMAIN}
    assert domains[DEFAULT_DOMAIN].recipients == (pub,)
    assert domains[DEFAULT_DOMAIN].keys == (ident,)


def test_sops_age_recipients_alias(keypairs):
    _, pub = keypairs[0]
    domains = load_domains({"SOPS_AGE_RECIPIENTS": pub})
    assert domains[DEFAULT_DOMAIN].recipients == (pub,)


def test_comma_separated_recipients_supported(keypairs):
    (_, pub_a), (_, pub_b) = keypairs
    domains = load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": f"{pub_a}, {pub_b}"})
    assert domains[DEFAULT_DOMAIN].recipients == (pub_a, pub_b)


def test_duplicate_recipients_deduped(keypairs):
    _, pub = keypairs[0]
    domains = load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": f"{pub},{pub}"})
    assert domains[DEFAULT_DOMAIN].recipients == (pub,)


def test_multiline_sops_age_key(keypairs):
    (ident_a, pub_a), (ident_b, pub_b) = keypairs
    domains = load_domains(
        {
            "SOPS_MCP_AGE_PUBLIC_KEY": f"{pub_a},{pub_b}",
            "SOPS_AGE_KEY": f"# a comment\n{ident_a}\n\n{ident_b}\n",
        }
    )
    assert domains[DEFAULT_DOMAIN].keys == (ident_a, ident_b)


def test_no_recipients_is_fatal():
    with pytest.raises(DomainConfigError, match="No age recipients configured"):
        load_domains({})


def test_encrypt_only_default_domain(keypairs):
    _, pub = keypairs[0]
    domains = load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": pub})
    assert domains[DEFAULT_DOMAIN].encrypt_only is True


def test_key_not_matching_recipient_warns_but_still_starts(keypairs, caplog):
    """A rotation-era key must not stop the server from booting.

    Mid recipient-rotation, SOPS_AGE_KEY holds the old identity as well as
    the new one. That key still opens files encrypted before the change,
    and sops_rekey is how they get migrated — refusing to start would
    strand exactly that deployment.
    """
    (ident_a, _), (_, pub_b) = keypairs
    with caplog.at_level("WARNING"):
        domains = load_domains(
            {"SOPS_MCP_AGE_PUBLIC_KEY": pub_b, "SOPS_AGE_KEY": ident_a}
        )
    assert domains[DEFAULT_DOMAIN].keys == (ident_a,)
    assert "matches none of its" in caplog.text
    assert ident_a not in caplog.text


def test_invalid_recipient_is_fatal():
    with pytest.raises(DomainConfigError, match="invalid recipient"):
        load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": "age1nonsense"})


def test_invalid_key_is_fatal_without_echoing_it(keypairs):
    _, pub = keypairs[0]
    bad = "AGE-SECRET-KEY-1NOTAREALKEY"
    with pytest.raises(DomainConfigError) as excinfo:
        load_domains({"SOPS_MCP_AGE_PUBLIC_KEY": pub, "SOPS_AGE_KEY": bad})
    assert bad not in str(excinfo.value)
    assert "private key #1" in str(excinfo.value)


# --- load_domains: domains file ------------------------------------------


def _write(tmp_path, text, mode=0o600, name="domains.yaml"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text))
    os.chmod(path, mode)
    return str(path)


def test_domains_file_multiple_domains(keypairs, tmp_path):
    (ident_a, pub_a), (_, pub_b) = keypairs
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            keys: [{ident_a}]
          archive:
            recipients: [{pub_b}]
        """,
    )
    domains = load_domains({"SOPS_MCP_DOMAINS_FILE": path})
    assert set(domains) == {"homelab", "archive"}
    assert domains["homelab"].keys == (ident_a,)
    assert domains["archive"].encrypt_only is True


def test_domains_file_key_file(keypairs, tmp_path):
    ident_a, pub_a = keypairs[0]
    keyfile = tmp_path / "a.agekey"
    keyfile.write_text(f"# created: whenever\n# public key: {pub_a}\n{ident_a}\n")
    os.chmod(keyfile, 0o600)
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            key_file: {keyfile}
        """,
        mode=0o644,
    )
    domains = load_domains({"SOPS_MCP_DOMAINS_FILE": path})
    assert domains["homelab"].keys == (ident_a,)


def test_world_readable_key_file_is_fatal(keypairs, tmp_path):
    ident_a, pub_a = keypairs[0]
    keyfile = tmp_path / "a.agekey"
    keyfile.write_text(ident_a + "\n")
    os.chmod(keyfile, 0o644)
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            key_file: {keyfile}
        """,
    )
    with pytest.raises(DomainConfigError, match="readable by any user"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_world_readable_domains_file_with_inline_keys_is_fatal(keypairs, tmp_path):
    ident_a, pub_a = keypairs[0]
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            keys: [{ident_a}]
        """,
        mode=0o644,
    )
    with pytest.raises(DomainConfigError, match="readable by any user"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_group_readable_key_file_warns_but_starts(keypairs, tmp_path, caplog):
    """Container secret mounts routinely arrive group-readable.

    Refusing them pushes operators back to putting the key in an
    environment variable, which /proc and `docker inspect` both expose.
    """
    ident_a, pub_a = keypairs[0]
    keyfile = tmp_path / "a.agekey"
    keyfile.write_text(ident_a + "\n")
    os.chmod(keyfile, 0o640)
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            key_file: {keyfile}
        """,
    )
    with caplog.at_level("WARNING"):
        domains = load_domains({"SOPS_MCP_DOMAINS_FILE": path})
    assert domains["homelab"].keys == (ident_a,)
    assert "group-readable" in caplog.text


def test_root_owned_key_file_is_accepted(keypairs, tmp_path, monkeypatch):
    """A Docker secret is typically root-owned, not owned by the runtime user."""
    ident_a, pub_a = keypairs[0]
    keyfile = tmp_path / "a.agekey"
    keyfile.write_text(ident_a + "\n")
    os.chmod(keyfile, 0o600)
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            key_file: {keyfile}
        """,
    )
    real_stat = os.stat

    def as_root(target, *args, **kwargs):
        info = real_stat(target, *args, **kwargs)
        if str(target) in {str(keyfile), path}:
            return type(info)((
                info.st_mode, info.st_ino, info.st_dev, info.st_nlink,
                0, info.st_gid, info.st_size,
                info.st_atime, info.st_mtime, info.st_ctime,
            ))
        return info

    monkeypatch.setattr(os, "stat", as_root)
    assert load_domains({"SOPS_MCP_DOMAINS_FILE": path})["homelab"].keys


def test_group_writable_domains_file_is_fatal_even_without_inline_keys(
    keypairs, tmp_path
):
    """The domains file decides recipients, so its integrity matters alone.

    Anyone who can rewrite it can add their own recipient and have the
    server encrypt to it on the next restart.
    """
    ident_a, pub_a = keypairs[0]
    keyfile = tmp_path / "a.agekey"
    keyfile.write_text(ident_a + "\n")
    os.chmod(keyfile, 0o600)
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            key_file: {keyfile}
        """,
        mode=0o662,
    )
    with pytest.raises(DomainConfigError, match="writable by group or other"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_default_in_both_file_and_env_is_fatal(keypairs, tmp_path):
    _, pub_a = keypairs[0]
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          default:
            recipients: [{pub_a}]
        """,
    )
    with pytest.raises(DomainConfigError, match="defined both in"):
        load_domains(
            {"SOPS_MCP_DOMAINS_FILE": path, "SOPS_MCP_AGE_PUBLIC_KEY": pub_a}
        )


def test_file_and_env_default_coexist_when_file_omits_default(keypairs, tmp_path):
    (_, pub_a), (_, pub_b) = keypairs
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          archive:
            recipients: [{pub_b}]
        """,
    )
    domains = load_domains(
        {"SOPS_MCP_DOMAINS_FILE": path, "SOPS_MCP_AGE_PUBLIC_KEY": pub_a}
    )
    assert set(domains) == {"archive", DEFAULT_DOMAIN}


def test_bad_domain_name_is_fatal(keypairs, tmp_path):
    _, pub_a = keypairs[0]
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          Not_A_Name:
            recipients: [{pub_a}]
        """,
    )
    with pytest.raises(DomainConfigError, match="invalid domain name"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_unknown_field_is_fatal(keypairs, tmp_path):
    _, pub_a = keypairs[0]
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            recipient: oops
        """,
    )
    with pytest.raises(DomainConfigError, match="unknown field"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_wrong_schema_version_is_fatal(keypairs, tmp_path):
    _, pub_a = keypairs[0]
    path = _write(
        tmp_path,
        f"""
        version: 2
        domains:
          homelab:
            recipients: [{pub_a}]
        """,
    )
    with pytest.raises(DomainConfigError, match="version"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_empty_domains_mapping_is_fatal(tmp_path):
    path = _write(tmp_path, "version: 1\ndomains: {}\n")
    with pytest.raises(DomainConfigError, match="non-empty 'domains'"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_missing_domains_file_is_fatal(tmp_path):
    with pytest.raises(DomainConfigError, match="cannot read"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": str(tmp_path / "nope.yaml")})


def test_invalid_yaml_is_fatal(tmp_path):
    path = _write(tmp_path, "version: 1\ndomains: [unclosed\n")
    with pytest.raises(DomainConfigError, match="not valid YAML"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_domain_with_no_recipients_is_fatal(tmp_path):
    path = _write(tmp_path, "version: 1\ndomains:\n  homelab:\n    keys: []\n")
    with pytest.raises(DomainConfigError, match="no recipients"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})


def test_plugin_recipient_domain_needs_no_software_key(tmp_path):
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          hardware:
            recipients: [{YUBIKEY_RECIP}]
        """,
    )
    domains = load_domains({"SOPS_MCP_DOMAINS_FILE": path})
    assert domains["hardware"].encrypt_only is True


def test_software_key_still_warned_when_domain_has_plugin_recipient(
    keypairs, tmp_path, caplog
):
    """The plugin recipient must not suppress the warning for a real key."""
    ident_a, _ = keypairs[0]
    _, pub_b = keypairs[1]
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          mixed:
            recipients: [{YUBIKEY_RECIP}, {pub_b}]
            keys: [{ident_a}]
        """,
    )
    with caplog.at_level("WARNING"):
        load_domains({"SOPS_MCP_DOMAINS_FILE": path})
    assert "matches none of its" in caplog.text


# --- inline SOPS_MCP_DOMAINS -------------------------------------------


def _inline(**domains) -> str:
    """A compact JSON domains document, as it would be set in env."""
    return json.dumps({"version": 1, "domains": domains})


def test_inline_env_yaml(keypairs):
    _, pub_b = keypairs[1]
    domains = load_domains({
        "SOPS_MCP_DOMAINS": textwrap.dedent(f"""
            version: 1
            domains:
              vigil:
                recipients: [{pub_b}]
        """)
    })
    assert set(domains) == {"vigil"}
    assert domains["vigil"].recipients == (pub_b,)
    assert domains["vigil"].encrypt_only is True


def test_inline_env_compact_json_is_equivalent(keypairs):
    """JSON is a YAML subset, which is what makes this practical in env."""
    _, pub_b = keypairs[1]
    as_json = load_domains({
        "SOPS_MCP_DOMAINS": _inline(vigil={"recipients": [pub_b]})
    })
    as_yaml = load_domains({
        "SOPS_MCP_DOMAINS": (
            f"version: 1\ndomains:\n  vigil:\n    recipients: [{pub_b}]\n"
        )
    })
    assert as_json == as_yaml


def test_inline_merges_with_v1_env_default(keypairs):
    (ident_a, pub_a), (_, pub_b) = keypairs
    domains = load_domains({
        "SOPS_MCP_AGE_PUBLIC_KEY": pub_a,
        "SOPS_AGE_KEY": ident_a,
        "SOPS_MCP_DOMAINS": _inline(vigil={"recipients": [pub_b]}),
    })
    assert set(domains) == {DEFAULT_DOMAIN, "vigil"}
    assert domains[DEFAULT_DOMAIN].encrypt_only is False
    assert domains["vigil"].encrypt_only is True


def test_inline_merges_with_domains_file(keypairs, tmp_path):
    (ident_a, pub_a), (_, pub_b) = keypairs
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          homelab:
            recipients: [{pub_a}]
            keys: [{ident_a}]
        """,
    )
    domains = load_domains({
        "SOPS_MCP_DOMAINS_FILE": path,
        "SOPS_MCP_DOMAINS": _inline(vigil={"recipients": [pub_b]}),
    })
    assert set(domains) == {"homelab", "vigil"}
    # The file keeps its private key; the inline domain is encrypt-only.
    assert domains["homelab"].keys == (ident_a,)
    assert domains["vigil"].encrypt_only is True


def test_inline_duplicate_of_file_domain_is_fatal(keypairs, tmp_path):
    (_, pub_a), (_, pub_b) = keypairs
    path = _write(
        tmp_path,
        f"""
        version: 1
        domains:
          vigil:
            recipients: [{pub_a}]
        """,
    )
    with pytest.raises(DomainConfigError, match="defined both in"):
        load_domains({
            "SOPS_MCP_DOMAINS_FILE": path,
            "SOPS_MCP_DOMAINS": _inline(vigil={"recipients": [pub_b]}),
        })


def test_inline_redefining_default_is_fatal(keypairs):
    (ident_a, pub_a), (_, pub_b) = keypairs
    with pytest.raises(DomainConfigError, match="defined both in"):
        load_domains({
            "SOPS_MCP_AGE_PUBLIC_KEY": pub_a,
            "SOPS_AGE_KEY": ident_a,
            "SOPS_MCP_DOMAINS": _inline(default={"recipients": [pub_b]}),
        })


def test_inline_private_keys_refused(keypairs):
    """Key material must go in a file so it keeps its permission checks."""
    (ident_a, _), (_, pub_b) = keypairs
    with pytest.raises(DomainConfigError) as exc:
        load_domains({
            "SOPS_MCP_DOMAINS": _inline(
                vigil={"recipients": [pub_b], "keys": [ident_a]}
            )
        })
    assert "SOPS_MCP_DOMAINS_FILE" in str(exc.value)
    # The refusal must not echo the identity it refused.
    assert ident_a not in str(exc.value)


def test_inline_key_file_refused(keypairs):
    _, pub_b = keypairs[1]
    with pytest.raises(DomainConfigError, match="key_file"):
        load_domains({
            "SOPS_MCP_DOMAINS": _inline(
                vigil={"recipients": [pub_b], "key_file": "/nonexistent"}
            )
        })


def test_inline_malformed_is_fatal():
    with pytest.raises(DomainConfigError, match="not valid YAML"):
        load_domains({"SOPS_MCP_DOMAINS": "not: [a, mapping"})


def test_inline_empty_domains_is_fatal():
    with pytest.raises(DomainConfigError, match="non-empty"):
        load_domains({"SOPS_MCP_DOMAINS": json.dumps({"version": 1, "domains": {}})})


def test_inline_wrong_version_is_fatal(keypairs):
    _, pub_b = keypairs[1]
    with pytest.raises(DomainConfigError, match="version"):
        load_domains({
            "SOPS_MCP_DOMAINS": json.dumps(
                {"version": 2, "domains": {"vigil": {"recipients": [pub_b]}}}
            )
        })


def test_version_error_says_it_is_not_a_key_version(keypairs):
    """`version` reads like a key version to anyone copying an example.

    Acting on that guess -- bumping it while rotating recipients -- stops
    the server dead, so the refusal has to say what the field actually is.
    """
    _, pub_b = keypairs[1]
    with pytest.raises(DomainConfigError) as exc:
        load_domains({
            "SOPS_MCP_DOMAINS": json.dumps(
                {"version": 2, "domains": {"vigil": {"recipients": [pub_b]}}}
            )
        })
    message = str(exc.value)
    assert "not a version of the keys" in message
    assert "rotating recipients does not change it" in message


def test_blank_inline_is_ignored(keypairs):
    """An empty variable is 'unset', not a malformed document."""
    ident_a, pub_a = keypairs[0]
    domains = load_domains({
        "SOPS_MCP_AGE_PUBLIC_KEY": pub_a,
        "SOPS_AGE_KEY": ident_a,
        "SOPS_MCP_DOMAINS": "   ",
    })
    assert set(domains) == {DEFAULT_DOMAIN}


# --- require_explicit_domain ---------------------------------------------


@pytest.mark.parametrize(("value", "expected"), [
    ("1", True), ("true", True), ("TRUE", True), ("yes", True),
    ("0", False), ("", False), ("no", False),
])
def test_require_explicit_domain(value, expected):
    assert require_explicit_domain({"SOPS_MCP_REQUIRE_DOMAIN": value}) is expected
