"""lib/verify_base_images.py: Dockerfile digests must match the lock file."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_base_images", ROOT / "lib" / "verify_base_images.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load_verifier()

DEV = "cgr.dev/chainguard/python:latest-dev"
RUN = "cgr.dev/chainguard/python:latest"
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64


def _write(root: Path, dockerfile: str, lock: dict | None) -> None:
    (root / "Dockerfile").write_text(dockerfile)
    if lock is not None:
        (root / "base-images.lock.json").write_text(json.dumps(lock))


def _entry(digest):
    return {"digest": digest, "cosign_signed": True, "used_in": ["Dockerfile"]}


DOCKERFILE = f"FROM {DEV}@{D1} AS build\nRUN true\nFROM {RUN}@{D2}\n"
LOCK = {DEV: _entry(D1), RUN: _entry(D2)}


@pytest.fixture(autouse=True)
def _no_cosign(monkeypatch):
    # main() would otherwise call cosign over the network when it is on PATH.
    monkeypatch.setattr(verifier, "check_cosign_signatures", lambda root: [])
    # main() chdirs into the root it checks; put the cwd back afterwards.
    monkeypatch.chdir(Path.cwd())


def test_matching_lock_passes(tmp_path: Path) -> None:
    _write(tmp_path, DOCKERFILE, LOCK)
    assert verifier.check_lock_agreement(str(tmp_path)) == []
    assert verifier.main(str(tmp_path)) == 0


def test_mismatched_digest_fails(tmp_path: Path, capsys) -> None:
    """The Dependabot case: the Dockerfile moved, the lock did not."""
    _write(tmp_path, DOCKERFILE.replace(D2, D3), LOCK)
    errors = verifier.check_lock_agreement(str(tmp_path))
    assert len(errors) == 1
    assert "Dockerfile:3" in errors[0]
    assert D3 in errors[0]
    assert D2 in errors[0]
    assert verifier.main(str(tmp_path)) == 1
    assert "lib/pin_base_images.py" in capsys.readouterr().out


def test_image_missing_from_lock_fails(tmp_path: Path) -> None:
    _write(tmp_path, DOCKERFILE, {DEV: _entry(D1)})
    errors = verifier.check_lock_agreement(str(tmp_path))
    assert len(errors) == 1
    assert RUN in errors[0]
    assert "not in" in errors[0]
    assert verifier.main(str(tmp_path)) == 1


def test_lock_entry_not_in_dockerfile_fails(tmp_path: Path) -> None:
    extra = "cgr.dev/chainguard/static:latest"
    _write(tmp_path, DOCKERFILE, {**LOCK, extra: _entry(D3)})
    errors = verifier.check_lock_agreement(str(tmp_path))
    assert len(errors) == 1
    assert extra in errors[0]
    assert verifier.main(str(tmp_path)) == 1


def test_null_lock_digest_fails(tmp_path: Path) -> None:
    """pin_base_images.py writes a null digest when a tag fails to resolve."""
    _write(tmp_path, DOCKERFILE, {DEV: _entry(D1), RUN: _entry(None)})
    assert len(verifier.check_lock_agreement(str(tmp_path))) == 1
    assert verifier.main(str(tmp_path)) == 1


def test_missing_lock_file_fails(tmp_path: Path) -> None:
    _write(tmp_path, DOCKERFILE, None)
    assert verifier.check_lock_agreement(str(tmp_path)) != []
    assert verifier.main(str(tmp_path)) == 1


def test_unpinned_from_is_reported_once(tmp_path: Path) -> None:
    """An unpinned FROM is a pin error, not also a lock error for that line."""
    _write(tmp_path, f"FROM {DEV}@{D1} AS build\nFROM {RUN}\n", LOCK)
    assert verifier.check_digest_pins(str(tmp_path)) != []
    assert verifier.check_lock_agreement(str(tmp_path)) == []
    assert verifier.main(str(tmp_path)) == 1


def test_repository_dockerfile_matches_lock() -> None:
    """The committed Dockerfile and lock agree, as the verify job requires."""
    assert verifier.check_lock_agreement(str(ROOT)) == []


def test_malformed_digest_is_a_pin_error(tmp_path: Path) -> None:
    """A digest with trailing junk is neither pinned nor silently skipped."""
    _write(tmp_path, DOCKERFILE.replace(D2, D2 + "x"), LOCK)
    assert verifier.check_digest_pins(str(tmp_path)) != []
    assert verifier.main(str(tmp_path)) == 1


def test_arg_and_scratch_refs_are_skipped(tmp_path: Path) -> None:
    """pin_base_images.py never locks ARG refs, so they cannot be required."""
    dockerfile = DOCKERFILE + f"FROM ${{BASE}}@{D3}\nFROM scratch\n"
    _write(tmp_path, dockerfile, LOCK)
    assert verifier.check_lock_agreement(str(tmp_path)) == []
    assert verifier.main(str(tmp_path)) == 0


@pytest.mark.parametrize("lock_text", ["{not json", '{"x": "not an object"}'])
def test_bad_lock_skips_cosign(tmp_path: Path, monkeypatch, lock_text) -> None:
    """A bad lock fails cleanly instead of crashing in the cosign check."""
    _write(tmp_path, DOCKERFILE, None)
    (tmp_path / "base-images.lock.json").write_text(lock_text)

    def _cosign(root):
        raise AssertionError("cosign check ran on a lock that disagrees")

    monkeypatch.setattr(verifier, "check_cosign_signatures", _cosign)
    assert verifier.main(str(tmp_path)) == 1


def test_pin_error_skips_cosign(tmp_path: Path, monkeypatch) -> None:
    """An unpinned FROM with a bad lock entry fails cleanly, without cosign."""
    _write(tmp_path, f"FROM {DEV}@{D1} AS build\nFROM {RUN}\n", None)
    lock = {DEV: _entry(D1), RUN: "not an object"}
    (tmp_path / "base-images.lock.json").write_text(json.dumps(lock))

    def _cosign(root):
        raise AssertionError("cosign check ran despite a pin error")

    monkeypatch.setattr(verifier, "check_cosign_signatures", _cosign)
    assert verifier.main(str(tmp_path)) == 1
