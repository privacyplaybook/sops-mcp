"""Fail the image build if a distrusted root CA is still in any trust store.

Run in the Dockerfile's final stage, so the build itself fails when the
image would still trust a revoked root. Each argument is a CA bundle file,
or a directory searched (without following directory symlinks) for
`*.crt`, `*.pem` and certifi's `cacert.pem`, which also finds the copy pip
vendors under `pip/_vendor/certifi/`. Certificates are matched by SHA-256
fingerprint of the DER encoding, not by file or subject name.

    python3 lib/check_trust_store.py /etc/ssl /opt/venv

Exits non-zero naming every file that still holds a distrusted root or
can't be read, or if the arguments yield no certificate at all (a moved
path must not pass). OpenSSL CApath entries (`<hash>.0`) are scanned too.
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


def bundle_files(path: str) -> list[str]:
    """Return `path` itself, or the CA bundle files found under it."""
    if not os.path.isdir(path):
        return [path]  # a missing file is reported when it is opened
    found = []
    for root, _dirs, files in os.walk(path):
        found.extend(
            os.path.join(root, name)
            for name in files
            if name.endswith(BUNDLE_SUFFIXES) or CAPATH_ENTRY.match(name)
        )
    return sorted(found)


def main(paths: list[str]) -> int:
    scanned = 0
    bad = []
    for path in paths:
        for bundle in bundle_files(path):
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
            "Distrusted root CA still trusted, or bundle unreadable:", *bad, sep="\n  "
        )
        return 1
    if scanned == 0:
        print(f"No certificates found under {paths}: nothing was checked")
        return 1
    print(f"Trust store OK: {scanned} certificates checked under {paths}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
