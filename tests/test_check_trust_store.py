"""lib/check_trust_store.py, the Dockerfile's build-time trust store guard."""

import importlib.util
import sys
from pathlib import Path

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
