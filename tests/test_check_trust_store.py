"""lib/check_trust_store.py, the Dockerfile's build-time trust store guard."""

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "trust_store"
G3 = (FIXTURES / "emsign-ecc-g3.pem").read_text()  # distrusted
G1 = (FIXTURES / "emsign-g1.pem").read_text()  # unaffected, stays trusted


def _load_guard():
    spec = importlib.util.spec_from_file_location(
        "check_trust_store", ROOT / "lib" / "check_trust_store.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def test_clean_bundle_passes(tmp_path: Path) -> None:
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(G1)
    assert guard.main([str(bundle)]) == 0


def test_bundle_with_g3_fails(tmp_path: Path, capsys) -> None:
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(G1 + G3)
    assert guard.main([str(bundle)]) == 1
    assert "emSign ECC Root CA - G3" in capsys.readouterr().out


def test_directory_walk_finds_pips_vendored_certifi(tmp_path: Path, capsys) -> None:
    # pip vendors certifi; the guard must find that copy, not only certifi's.
    (tmp_path / "certifi").mkdir()
    (tmp_path / "certifi" / "cacert.pem").write_text(G1)
    vendored = tmp_path / "pip" / "_vendor" / "certifi"
    vendored.mkdir(parents=True)
    (vendored / "cacert.pem").write_text(G3)
    assert guard.main([str(tmp_path)]) == 1
    assert "pip/_vendor/certifi/cacert.pem" in capsys.readouterr().out


def test_no_certificates_fails(tmp_path: Path) -> None:
    # A path that moved must not pass vacuously.
    assert guard.main([str(tmp_path)]) == 1


def test_missing_file_fails_and_scanning_continues(tmp_path: Path, capsys) -> None:
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(G3)
    assert guard.main([str(tmp_path / "absent.crt"), str(bundle)]) == 1
    out = capsys.readouterr().out
    assert "absent.crt: unreadable" in out
    assert "emSign ECC Root CA - G3" in out


def test_capath_hash_entry_is_scanned(tmp_path: Path) -> None:
    (tmp_path / "ca-certificates.crt").write_text(G1)
    (tmp_path / "f2ab3c4d.0").write_text(G3)
    assert guard.main([str(tmp_path)]) == 1


def test_undecodable_block_is_skipped(tmp_path: Path) -> None:
    bad = "-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n"
    (tmp_path / "broken.pem").write_text(bad)
    (tmp_path / "ok.pem").write_text(G1)
    assert guard.main([str(tmp_path)]) == 0


def test_unlistable_directory_fails(tmp_path: Path, capsys) -> None:
    # The runtime stage runs the guard as nonroot: a directory it can't
    # list must fail the build, not be skipped as if empty.
    (tmp_path / "ok.pem").write_text(G1)
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "cacert.pem").write_text(G3)
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as root: permissions are not enforced")
        assert guard.main([str(tmp_path)]) == 1
        assert "unreadable directory" in capsys.readouterr().out
    finally:
        locked.chmod(0o700)


def test_symlinked_directory_is_followed(tmp_path: Path, capsys) -> None:
    # A bundle reachable only through a directory symlink is still trusted
    # by whatever reads that path, so the guard must look behind the link.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "cacert.pem").write_text(G3)
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "ok.pem").write_text(G1)
    (scanned / "certs").symlink_to(elsewhere, target_is_directory=True)
    assert guard.main([str(scanned)]) == 1
    assert "certs/cacert.pem: emSign ECC Root CA - G3" in capsys.readouterr().out


def test_symlink_loop_is_walked_once(tmp_path: Path, capsys) -> None:
    # A link back to an ancestor, and a venv-style `lib64 -> lib`, must end
    # the walk with each real directory scanned once, not recurse.
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "cacert.pem").write_text(G1)
    (tmp_path / "lib64").symlink_to("lib", target_is_directory=True)
    (tmp_path / "lib" / "loop").symlink_to("..", target_is_directory=True)
    assert guard.main([str(tmp_path)]) == 0
    assert "Trust store OK: 1 certificates" in capsys.readouterr().out


def test_link_to_unreachable_directory_fails(tmp_path: Path, capsys) -> None:
    # os.walk can't stat a link whose target sits under a 0700 directory,
    # files it as a non-directory and would drop it: it must fail instead.
    vault = tmp_path / "vault"
    (vault / "certs").mkdir(parents=True)
    (vault / "certs" / "cacert.pem").write_text(G3)
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "ok.pem").write_text(G1)
    (scanned / "certs").symlink_to(vault / "certs", target_is_directory=True)
    vault.chmod(0)
    try:
        if os.access(vault, os.R_OK):
            pytest.skip("running as root: permissions are not enforced")
        assert guard.main([str(scanned)]) == 1
        assert "certs: unreadable link target" in capsys.readouterr().out
    finally:
        vault.chmod(0o700)


def test_links_to_nothing_are_ignored(tmp_path: Path) -> None:
    # Dangling, looping, or through a regular file: nothing is behind them.
    (tmp_path / "ok.pem").write_text(G1)
    (tmp_path / "gone").symlink_to(tmp_path / "absent", target_is_directory=True)
    (tmp_path / "self").symlink_to("self")
    (tmp_path / "through").symlink_to(tmp_path / "ok.pem" / "sub")
    assert guard.main([str(tmp_path)]) == 0


def test_directory_reached_twice_is_scanned_once(tmp_path: Path, capsys) -> None:
    # Two arguments reaching one directory (here through a link) count it
    # once, so the reported total isn't inflated.
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "cacert.pem").write_text(G1)
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "a").symlink_to(tmp_path / "a", target_is_directory=True)
    assert guard.main([str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    assert "Trust store OK: 1 certificates" in capsys.readouterr().out


def test_bundle_named_link_to_unreachable_target_is_reported_once(
    tmp_path: Path, capsys
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "cacert.pem").write_text(G3)
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "ok.pem").write_text(G1)
    (scanned / "cacert.pem").symlink_to(vault / "cacert.pem")
    vault.chmod(0)
    try:
        if os.access(vault, os.R_OK):
            pytest.skip("running as root: permissions are not enforced")
        assert guard.main([str(scanned)]) == 1
        assert capsys.readouterr().out.count("cacert.pem: unreadable") == 1
    finally:
        vault.chmod(0o700)
