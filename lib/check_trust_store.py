"""Fail the image build if a distrusted root CA is still in any trust store.

Run in the Dockerfile's final stage, so the build itself fails when the
image would still trust a revoked root. Each argument is a CA bundle file,
or a directory searched for `*.crt`, `*.pem` and certifi's `cacert.pem`,
which also finds the copy pip vendors under `pip/_vendor/certifi/`. The
search follows symlinked directories, each real directory visited once, so
a bundle reached only through a link (or a link loop) can't escape it.
Certificates are matched by SHA-256 fingerprint of the DER encoding, not by
file or subject name.

    python3 lib/check_trust_store.py /etc/ssl /opt/venv

Exits non-zero naming every file that still holds a distrusted root or
can't be read, and every directory it can't list, or if the arguments
yield no certificate at all (a moved path must not pass). OpenSSL CApath
entries (`<hash>.0`) are scanned too.
Standard library only: the runtime image is distroless.
"""

import binascii
import hashlib
import os
import re
import ssl
import sys

# Roots no image may trust, by SHA-256 fingerprint.
DISTRUSTED = {
    # emSign ECC Root CA - G3: eight eMudhra intermediates under it had
    # their private keys recovered (GHSA-6q48-6c7w-9gw2).
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": (
        "emSign ECC Root CA - G3"
    ),
}

PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
BUNDLE_SUFFIXES = (".crt", ".pem")
# OpenSSL CApath entries: <subject hash>.0, .1, ...
CAPATH_ENTRY = re.compile(r"^[0-9a-f]{8}\.\d+$")


def bundle_files(path: str, bad: list[str], seen: set[tuple[int, int]]) -> list[str]:
    """Return `path` itself, or the CA bundle files found under it.

    A directory the walk can't list is appended to `bad`: the build runs as
    a non-root user, and a store it can't read must fail, not be skipped.
    Symlinked directories are followed, since a bundle behind one is still
    trusted, and each real directory (by device and inode) is walked once,
    so a link loop or a venv's `lib64 -> lib` ends rather than recursing.
    `seen` is shared across arguments, so a directory two of them reach is
    walked once. A link os.walk can't classify because its target is
    permission-denied is listed among the files; it is reported too.
    """
    if not os.path.isdir(path):
        return [path]  # a missing file is reported when it is opened
    found = []

    def unlistable(exc: OSError) -> None:
        bad.append(f"{exc.filename}: unreadable directory ({exc.strerror})")

    for root, dirs, files in os.walk(path, onerror=unlistable, followlinks=True):
        try:
            st = os.stat(root)
        except OSError as exc:
            unlistable(exc)
            dirs[:] = []
            continue
        if (st.st_dev, st.st_ino) in seen:
            dirs[:] = []  # already walked through another path
            continue
        seen.add((st.st_dev, st.st_ino))
        for name in files:
            # os.walk puts a link whose target it can't stat among the
            # files, where it would be dropped unread: a permission-denied
            # target may be a directory, so it fails like an unlistable one.
            # Other errors (dangling, a loop, a path through a file) mean
            # nothing is behind the link. A bundle name is opened below,
            # which reports it already.
            if name.endswith(BUNDLE_SUFFIXES) or CAPATH_ENTRY.match(name):
                continue
            link = os.path.join(root, name)
            if os.path.islink(link):
                try:
                    os.stat(link)
                except PermissionError as exc:
                    bad.append(f"{link}: unreadable link target ({exc.strerror})")
                except OSError:
                    pass  # dangling, a loop, or through a file: nothing there
        found.extend(
            os.path.join(root, name)
            for name in files
            if name.endswith(BUNDLE_SUFFIXES) or CAPATH_ENTRY.match(name)
        )
    return sorted(found)


def main(paths: list[str]) -> int:
    scanned = 0
    bad: list[str] = []
    seen: set[tuple[int, int]] = set()
    for path in paths:
        for bundle in bundle_files(path, bad, seen):
            try:
                with open(bundle, encoding="ascii", errors="replace") as f:
                    certs = PEM.findall(f.read())
            except OSError as exc:
                # Missing, unreadable or a dangling symlink: a failure, but
                # keep scanning so the report names every problem at once.
                bad.append(f"{bundle}: unreadable ({exc.strerror})")
                continue
            scanned += len(certs)
            for cert in certs:
                try:
                    der = ssl.PEM_cert_to_DER_cert(cert)
                except (ValueError, binascii.Error):
                    # A deliberately broken test fixture, say. A real root
                    # always decodes, so skipping one can't hide it.
                    print(f"warning: undecodable certificate in {bundle}")
                    continue
                fp = hashlib.sha256(der).hexdigest()
                if fp in DISTRUSTED:
                    bad.append(f"{bundle}: {DISTRUSTED[fp]}")
    if bad:
        print(
            "Distrusted root CA still trusted, or a bundle, directory or link"
            " unreadable:",
            *bad,
            sep="\n  ",
        )
        return 1
    if scanned == 0:
        print(f"No certificates found under {paths}: nothing was checked")
        return 1
    print(f"Trust store OK: {scanned} certificates checked under {paths}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
