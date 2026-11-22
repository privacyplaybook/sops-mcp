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


# --- cosign signer pinning (#66) ---

CHAINGUARD_IDENTITY = (
    "https://github.com/chainguard-images/images/.github/workflows/"
    "release.yaml@refs/heads/main"
)
GITHUB_OIDC = "https://token.actions.githubusercontent.com"
EVIL_IDENTITY = (
    "https://github.com/evil/images/.github/workflows/release.yaml@refs/heads/main"
)


class _FakeCosign:
    """Stands in for subprocess.run: passes only Chainguard's real signer.

    Records each call, and fails a verify whose identity or issuer flags
    differ from what Chainguard's certificates carry, as cosign would.
    """

    def __init__(self, signer=(CHAINGUARD_IDENTITY, GITHUB_OIDC)):
        self.signer = signer
        self.calls = []

    def __call__(self, args, **kwargs):
        import subprocess

        self.calls.append(args)
        flags = dict(zip(args[2:-1:2], args[3:-1:2], strict=True))
        ok = (
            flags.get("--certificate-identity") == self.signer[0]
            and flags.get("--certificate-oidc-issuer") == self.signer[1]
            and set(flags) == {"--certificate-identity", "--certificate-oidc-issuer"}
        )
        stderr = "" if ok else (
            "error: no matching signatures: "
            "none of the expected identities matched"
        )
        return subprocess.CompletedProcess(args, 0 if ok else 12, "", stderr)


def _real_cosign_check():
    # The autouse fixture stubs check_cosign_signatures out; these tests
    # exercise the real one, with subprocess.run faked instead.
    return _load_verifier()


def test_chainguard_images_pin_chainguard_signer() -> None:
    assert verifier.signer_for(f"{RUN}@{D1}") == (CHAINGUARD_IDENTITY, GITHUB_OIDC)


@pytest.mark.parametrize(
    "image",
    [
        "docker.io/library/python@" + D1,
        "ghcr.io/chainguard/python@" + D1,
        "cgr.dev/chainguard-private/python@" + D1,
        "cgr.dev/other/python@" + D1,
    ],
)
def test_other_registries_have_no_signer(image) -> None:
    assert verifier.signer_for(image) is None


def test_cosign_is_called_with_exact_identity(tmp_path: Path, monkeypatch) -> None:
    """No regexp flags: the identity and issuer are matched exactly."""
    v = _real_cosign_check()
    fake = _FakeCosign()
    monkeypatch.setattr(v.subprocess, "run", fake)
    _write(tmp_path, DOCKERFILE, LOCK)
    assert v.check_cosign_signatures(str(tmp_path)) == []
    assert len(fake.calls) == 2
    for args in fake.calls:
        assert not any("regexp" in a for a in args)
        assert args[args.index("--certificate-identity") + 1] == CHAINGUARD_IDENTITY
        assert args[args.index("--certificate-oidc-issuer") + 1] == GITHUB_OIDC
    assert {a[-1] for a in fake.calls} == {
        f"cgr.dev/chainguard/python@{D1}",
        f"cgr.dev/chainguard/python@{D2}",
    }


def test_wrong_signer_fails_the_check(tmp_path: Path, monkeypatch) -> None:
    """An image signed by anyone but the pinned identity fails main()."""
    v = _real_cosign_check()
    monkeypatch.setattr(
        v.subprocess, "run",
        _FakeCosign(signer=(EVIL_IDENTITY, GITHUB_OIDC)),
    )
    _write(tmp_path, DOCKERFILE, LOCK)
    errors = v.check_cosign_signatures(str(tmp_path))
    assert len(errors) == 2
    assert all("no matching signatures" in e for e in errors)
    assert v.main(str(tmp_path)) == 1


def test_wrong_issuer_fails_the_check(tmp_path: Path, monkeypatch) -> None:
    v = _real_cosign_check()
    monkeypatch.setattr(
        v.subprocess, "run",
        _FakeCosign(signer=(CHAINGUARD_IDENTITY, "https://accounts.google.com")),
    )
    _write(tmp_path, DOCKERFILE, LOCK)
    assert len(v.check_cosign_signatures(str(tmp_path))) == 2


def test_unsigned_lock_entry_is_an_error(tmp_path: Path, monkeypatch) -> None:
    """cosign_signed: false can't be used to skip verification."""
    v = _real_cosign_check()
    fake = _FakeCosign()
    monkeypatch.setattr(v.subprocess, "run", fake)
    lock = {DEV: _entry(D1), RUN: {**_entry(D2), "cosign_signed": False}}
    _write(tmp_path, DOCKERFILE, lock)
    errors = v.check_cosign_signatures(str(tmp_path))
    assert len(errors) == 1
    assert RUN in errors[0]
    assert v.main(str(tmp_path)) == 1


def test_unlisted_registry_is_an_error(tmp_path: Path, monkeypatch) -> None:
    v = _real_cosign_check()
    fake = _FakeCosign()
    monkeypatch.setattr(v.subprocess, "run", fake)
    other = "docker.io/library/python:3.13"
    _write(tmp_path, f"FROM {other}@{D3}\n", {other: _entry(D3)})
    errors = v.check_cosign_signatures(str(tmp_path))
    assert len(errors) == 1
    assert "no pinned signer" in errors[0]
    assert fake.calls == []
    assert v.main(str(tmp_path)) == 1


def test_missing_cosign_is_an_error(tmp_path: Path, monkeypatch) -> None:
    """Without cosign the check fails; it no longer passes with a warning."""
    v = _real_cosign_check()

    def _missing(args, **kwargs):
        raise FileNotFoundError("cosign")

    monkeypatch.setattr(v.subprocess, "run", _missing)
    _write(tmp_path, DOCKERFILE, LOCK)
    errors = v.check_cosign_signatures(str(tmp_path))
    assert len(errors) == 2
    assert all("cosign not installed" in e for e in errors)
    assert v.main(str(tmp_path)) == 1


def test_cosign_timeout_is_an_error(tmp_path: Path, monkeypatch) -> None:
    import subprocess

    v = _real_cosign_check()

    def _slow(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))

    monkeypatch.setattr(v.subprocess, "run", _slow)
    _write(tmp_path, DOCKERFILE, LOCK)
    assert all("timed out" in e for e in v.check_cosign_signatures(str(tmp_path)))
    assert v.main(str(tmp_path)) == 1


def test_pin_script_uses_the_same_signers() -> None:
    """pin_base_images.py records what verify_base_images.py re-checks."""
    text = (ROOT / "lib" / "pin_base_images.py").read_text()
    assert "from verify_base_images import cosign_verify" in text
    assert "regexp" not in text


def test_transient_failure_is_retried(tmp_path: Path, monkeypatch) -> None:
    """A timeout or network error is retried; the second try can pass."""
    import subprocess

    v = _real_cosign_check()
    fake = _FakeCosign()
    failures = {"left": 2}

    def _flaky(args, **kwargs):
        if failures["left"]:
            failures["left"] -= 1
            if failures["left"]:
                raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))
            return subprocess.CompletedProcess(args, 1, "", "Error: Rekor 503")
        return fake(args, **kwargs)

    monkeypatch.setattr(v.subprocess, "run", _flaky)
    ok, detail = v.cosign_verify(f"cgr.dev/chainguard/python@{D1}")
    assert ok, detail
    assert len(fake.calls) == 1


def test_wrong_signer_is_not_retried(monkeypatch) -> None:
    v = _real_cosign_check()
    fake = _FakeCosign(signer=(EVIL_IDENTITY, GITHUB_OIDC))
    monkeypatch.setattr(v.subprocess, "run", fake)
    ok, _ = v.cosign_verify(f"cgr.dev/chainguard/python@{D1}")
    assert not ok
    assert len(fake.calls) == 1


def test_persistent_network_failure_fails(monkeypatch) -> None:
    import subprocess

    v = _real_cosign_check()
    calls = []

    def _down(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "Error: Rekor 503")

    monkeypatch.setattr(v.subprocess, "run", _down)
    ok, detail = v.cosign_verify(f"cgr.dev/chainguard/python@{D1}")
    assert not ok
    assert "503" in detail
    assert len(calls) == v.COSIGN_ATTEMPTS


def test_unsigned_entry_points_at_pin_script(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The fix for a lock recorded unsigned is regenerating it."""
    v = _real_cosign_check()
    monkeypatch.setattr(v.subprocess, "run", _FakeCosign())
    lock = {DEV: _entry(D1), RUN: {**_entry(D2), "cosign_signed": False}}
    _write(tmp_path, DOCKERFILE, lock)
    assert v.main(str(tmp_path)) == 1
    assert "lib/pin_base_images.py" in capsys.readouterr().out


def test_success_detail_names_no_identity(monkeypatch) -> None:
    """The printed detail carries no identity or issuer (CodeQL, PR #80)."""
    v = _real_cosign_check()
    monkeypatch.setattr(v.subprocess, "run", _FakeCosign())
    ok, detail = v.cosign_verify(f"cgr.dev/chainguard/python@{D1}")
    assert ok
    assert "https://" not in detail
