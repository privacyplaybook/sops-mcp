"""SOPS encryption/decryption via CLI with secure temp file handling."""

import os
import shutil
import subprocess
import tempfile

import yaml

from .domains import DEFAULT_DOMAIN, Domain

# Every environment variable sops consults for an age private key. They are
# stripped from each child environment so that the only key material sops
# can see is the one belonging to the domain of the call in hand. Without
# this, a process holding several domains' keys would let any domain
# decrypt any file.
_AGE_KEY_ENV_VARS = (
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "SOPS_AGE_KEY_CMD",
    "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
    "SOPS_AGE_RECIPIENTS",
)


class SopsError(Exception):
    """Raised when a sops CLI operation fails."""


def _make_secure_tempdir() -> str:
    """Create a 0700 temp dir on tmpfs (/dev/shm) when available, falling
    back to the default temp dir.

    Using tmpfs means the plaintext temp file backing the sops invocation
    is never written to persistent storage — defends against later disk
    forensics and against block-level remnants on flash/COW filesystems
    that the zero-overwrite in `_secure_cleanup` can't reach.
    """
    parent: str | None = None
    if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        parent = "/dev/shm"
    try:
        tmpdir = tempfile.mkdtemp(prefix="sops-mcp-", dir=parent)
    except OSError:
        if parent is None:
            raise
        tmpdir = tempfile.mkdtemp(prefix="sops-mcp-")
    os.chmod(tmpdir, 0o700)
    return tmpdir


# sops master-key groups other than age. This server encrypts with --age
# only, so a file carrying any of these would lose them on re-encryption.
_NON_AGE_KEY_GROUPS = ("pgp", "kms", "gcp_kms", "azure_kv", "hc_vault")


def _envelope_of(encrypted_content: str) -> dict:
    """Return the `sops` metadata block, or raise if it isn't there."""
    try:
        parsed = yaml.safe_load(encrypted_content)
    except yaml.YAMLError as exc:
        raise SopsError(f"content is not valid YAML: {exc}") from exc

    if not isinstance(parsed, dict) or "sops" not in parsed:
        raise SopsError(
            "content has no 'sops' metadata block — it does not look like a "
            "SOPS-encrypted file."
        )

    envelope = parsed["sops"]
    if not isinstance(envelope, dict):
        raise SopsError("the 'sops' metadata block is malformed.")
    return envelope


def non_age_key_groups(encrypted_content: str) -> tuple[str, ...]:
    """Names of the non-age master-key groups a file actually carries.

    A normal age file lists these groups empty. A non-empty one means the
    file is also readable by a PGP or KMS key, which this server cannot
    reproduce: it always encrypts with --age alone, so re-encrypting would
    drop that key holder silently. Callers refuse rather than do that.
    """
    envelope = _envelope_of(encrypted_content)
    return tuple(
        group
        for group in _NON_AGE_KEY_GROUPS
        if isinstance(envelope.get(group), list) and envelope[group]
    )


def recipients_of(encrypted_content: str) -> tuple[str, ...]:
    """Return the age recipients a SOPS file is encrypted to.

    Reads the `sops` envelope only — no private key, no decryption. This is
    what a mutation compares against its domain before re-encrypting, so
    that re-encrypting can never quietly change who can read a file.

    The envelope is not authenticated, but it cannot be forged upward: an
    added recipient entry without a matching wrapped data key simply fails
    to decrypt, and a removed one only revokes its own access.
    """
    envelope = _envelope_of(encrypted_content)

    entries = envelope.get("age") or []
    if not isinstance(entries, list):
        raise SopsError("the 'sops.age' metadata block is malformed.")

    recipients = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("recipient"):
            recipients.append(str(entry["recipient"]).strip())
    return tuple(recipients)


class SopsEncryptor:
    """Encrypt and decrypt YAML data using the sops CLI.

    Key material is supplied per call via a :class:`~sops_mcp.domains.Domain`
    rather than inherited from the process environment, so one server can
    hold several domains' keys without any of them leaking into another
    domain's sops invocation.
    """

    def __init__(self, sops_binary: str = "sops"):
        self.sops_binary = sops_binary

    def _child_env(
        self, domain: Domain, scratch_home: str, *, with_keys: bool
    ) -> dict[str, str]:
        """Build the environment for one sops invocation.

        Three things happen here, all load-bearing:

        1. Every age key environment variable is dropped, then reinstated
           with only this domain's keys.
        2. HOME and XDG_CONFIG_HOME point at an empty scratch directory.
           sops falls back to ``~/.config/sops/age/keys.txt`` when no key
           env var is set, so without this a key on disk would silently be
           available to every domain.
        3. Private keys are passed only when the operation needs them.
           Encryption needs recipients on the command line and nothing
           else, so an encrypt subprocess never carries an identity in its
           environment where /proc would expose it.
        """
        env = dict(os.environ)
        for var in _AGE_KEY_ENV_VARS:
            env.pop(var, None)

        env["HOME"] = scratch_home
        env["XDG_CONFIG_HOME"] = scratch_home

        if with_keys and domain.keys:
            env["SOPS_AGE_KEY"] = "\n".join(domain.keys)
        return env

    def encrypt(self, data: dict, domain: Domain) -> str:
        """Encrypt a dict as SOPS YAML, returning the encrypted content.

        Keys ending with '_unencrypted' are left in plaintext by sops.

        Args:
            data: Dict of key-value pairs to encrypt. May include a
                  '_meta_unencrypted' key that will be stored in plaintext.
            domain: The domain whose recipients the content is encrypted to.

        Returns:
            SOPS-encrypted YAML string.
        """
        plaintext_yaml = yaml.dump(data, default_flow_style=False, sort_keys=False)
        tmpdir = _make_secure_tempdir()
        tmpfile = os.path.join(tmpdir, "secrets.yaml")
        scratch_home = os.path.join(tmpdir, "home")

        try:
            os.mkdir(scratch_home, 0o700)
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(plaintext_yaml)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "encrypt",
                    "--age", domain.age_argument,
                    "--unencrypted-suffix", "_unencrypted",
                    "--input-type", "yaml",
                    "--output-type", "yaml",
                    tmpfile,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=self._child_env(domain, scratch_home, with_keys=False),
                check=False,
            )

            if result.returncode != 0:
                raise SopsError(f"sops encrypt failed: {result.stderr.strip()}")

            return result.stdout

        finally:
            self._secure_cleanup(tmpfile, tmpdir)

    def decrypt(self, encrypted_content: str, domain: Domain) -> dict:
        """Decrypt SOPS-encrypted YAML content, returning the plaintext dict.

        Args:
            encrypted_content: SOPS-encrypted YAML string.
            domain: The domain whose private keys are offered to sops. Its
                    keys are the *only* ones the sops process can see.

        Returns:
            Dict of decrypted key-value pairs.
        """
        if domain.encrypt_only:
            # SOPS_AGE_KEY only ever feeds the implicit 'default' domain,
            # so pointing a named domain at it would be a dead end.
            remedy = (
                "Set SOPS_AGE_KEY."
                if domain.name == DEFAULT_DOMAIN
                else f"Give it a 'keys' or 'key_file' entry in the domains "
                f"file; SOPS_AGE_KEY only configures the "
                f"'{DEFAULT_DOMAIN}' domain."
            )
            raise SopsError(
                f"domain '{domain.name}' has no private key configured, so "
                f"it cannot decrypt. {remedy}"
            )

        tmpdir = _make_secure_tempdir()
        tmpfile = os.path.join(tmpdir, "secrets.enc.yaml")
        scratch_home = os.path.join(tmpdir, "home")

        try:
            os.mkdir(scratch_home, 0o700)
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
                env=self._child_env(domain, scratch_home, with_keys=True),
                check=False,
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
                # rmtree rather than rmdir: the scratch HOME handed to sops
                # is a subdirectory, and sops may leave a cache file in it.
                shutil.rmtree(dirpath, ignore_errors=True)
        except OSError:
            pass
