"""SOPS encryption/decryption via CLI with secure temp file handling."""

import os
import subprocess
import tempfile

import yaml


class SopsError(Exception):
    """Raised when a sops CLI operation fails."""


class SopsEncryptor:
    """Encrypt and decrypt YAML data using the sops CLI."""

    def __init__(self, age_public_key: str, sops_binary: str = "sops"):
        self.age_public_key = age_public_key
        self.sops_binary = sops_binary

    def encrypt(self, data: dict) -> str:
        """Encrypt a dict as SOPS YAML, returning the encrypted content.

        Keys ending with '_unencrypted' are left in plaintext by sops.

        Args:
            data: Dict of key-value pairs to encrypt. May include a
                  '_meta_unencrypted' key that will be stored in plaintext.

        Returns:
            SOPS-encrypted YAML string.
        """
        plaintext_yaml = yaml.dump(data, default_flow_style=False, sort_keys=False)
        tmpdir = tempfile.mkdtemp(prefix="sops-mcp-")
        os.chmod(tmpdir, 0o700)
        tmpfile = os.path.join(tmpdir, "secrets.yaml")

        try:
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(plaintext_yaml)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "encrypt",
                    "--age", self.age_public_key,
                    "--unencrypted-suffix", "_unencrypted",
                    "--input-type", "yaml",
                    "--output-type", "yaml",
                    tmpfile,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise SopsError(f"sops encrypt failed: {result.stderr.strip()}")

            return result.stdout

        finally:
            self._secure_cleanup(tmpfile, tmpdir)

    def decrypt(self, encrypted_content: str) -> dict:
        """Decrypt SOPS-encrypted YAML content, returning the plaintext dict.

        Requires SOPS_AGE_KEY environment variable to be set.

        Args:
            encrypted_content: SOPS-encrypted YAML string.

        Returns:
            Dict of decrypted key-value pairs.
        """
        if not os.environ.get("SOPS_AGE_KEY"):
            raise SopsError(
                "SOPS_AGE_KEY environment variable is required for decryption"
            )

        tmpdir = tempfile.mkdtemp(prefix="sops-mcp-")
        os.chmod(tmpdir, 0o700)
        tmpfile = os.path.join(tmpdir, "secrets.enc.yaml")

        try:
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(encrypted_content)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "decrypt",
                    "--input-type", "yaml",
                    "--output-type", "yaml",
                    tmpfile,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise SopsError(f"sops decrypt failed: {result.stderr.strip()}")

            return yaml.safe_load(result.stdout) or {}

        finally:
            self._secure_cleanup(tmpfile, tmpdir)

    def _secure_cleanup(self, filepath: str, dirpath: str) -> None:
        """Overwrite file with zeros, then delete file and directory."""
        try:
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                with open(filepath, "wb") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
                os.unlink(filepath)
            if os.path.isdir(dirpath):
                os.rmdir(dirpath)
        except OSError:
            pass
