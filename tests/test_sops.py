"""Tests for the sops module — focused on the temp-dir hardening."""

import math
import os
import stat

import pytest
import yaml

from sops_mcp.sops import _make_secure_tempdir, load_sops_yaml


def test_tempdir_is_0700_and_cleanable(tmp_path):
    d = _make_secure_tempdir()
    try:
        mode = stat.S_IMODE(os.stat(d).st_mode)
        assert mode == 0o700
        assert os.path.isdir(d)
    finally:
        os.rmdir(d)


def test_tempdir_prefers_shm_when_available(monkeypatch):
    """When /dev/shm is a writable directory, mkdtemp must be invoked with
    dir='/dev/shm' so the plaintext temp file lives on tmpfs and never
    touches persistent storage."""
    if not (os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK)):
        pytest.skip("/dev/shm not writable in this environment")

    captured: dict[str, str | None] = {}
    import tempfile as _tempfile

    real_mkdtemp = _tempfile.mkdtemp

    # 'dir' shadows a builtin but must match tempfile.mkdtemp's signature.
    def fake_mkdtemp(prefix=None, dir=None):  # noqa: A002
        captured["dir"] = dir
        return real_mkdtemp(prefix=prefix, dir=dir)

    monkeypatch.setattr(_tempfile, "mkdtemp", fake_mkdtemp)

    d = _make_secure_tempdir()
    try:
        assert captured["dir"] == "/dev/shm"
        assert d.startswith("/dev/shm/sops-mcp-")
    finally:
        os.rmdir(d)


def test_tempdir_falls_back_when_shm_missing(monkeypatch):
    """On platforms without /dev/shm (e.g. macOS, hardened containers),
    the helper must transparently fall back to the default temp dir."""
    monkeypatch.setattr(
        os.path,
        "isdir",
        lambda p: False if p == "/dev/shm" else os.path.isdir(p),
    )

    d = _make_secure_tempdir()
    try:
        assert not d.startswith("/dev/shm")
    finally:
        os.rmdir(d)


# --- load_sops_yaml: YAML 1.2 core scalars, as sops writes them (#77) ---


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"0189"', "0189"),
        ("0123", 123),        # 1.2: decimal, not 1.1 octal (83)
        ("0o17", 15),
        ("0x1f", 31),
        ("-7", -7),
        ("1e3", 1000.0),
        ("1.5", 1.5),
        ("true", True),
        ("FALSE", False),
        ("~", None),
        ("null", None),
        ("", None),
        ("yes", "yes"),       # 1.1-only bools are strings
        ("on", "on"),
        ("1:20", "1:20"),     # no sexagesimals
        ("1_000", "1_000"),
        ("0b101", "0b101"),
        ("2001-12-14", "2001-12-14"),  # no timestamps
        ("=", "="),           # PyYAML's safe_load refuses this
        ("!!merge <<", "<<"),  # how sops writes the string "<<"
    ],
)
def test_load_sops_yaml_resolves_scalars_as_sops_does(text, expected):
    value = load_sops_yaml(f"k: {text}\n")["k"]
    assert value == expected
    assert type(value) is type(expected)


def test_load_sops_yaml_special_floats():
    loaded = load_sops_yaml("a: .inf\nb: -.Inf\nc: .nan\n")
    assert loaded["a"] == math.inf
    assert loaded["b"] == -math.inf
    assert math.isnan(loaded["c"])


def test_load_sops_yaml_leaves_safe_loader_alone():
    assert yaml.safe_load("k: yes\n")["k"] is True
