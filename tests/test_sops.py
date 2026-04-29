"""Tests for the sops module — focused on the temp-dir hardening."""

import os
import stat

import pytest

from sops_mcp.sops import _make_secure_tempdir


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

    def fake_mkdtemp(prefix=None, dir=None):
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
    monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/dev/shm" else os.path.isdir(p))

    d = _make_secure_tempdir()
    try:
        assert not d.startswith("/dev/shm")
    finally:
        os.rmdir(d)
