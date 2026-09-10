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


def _write_empty_config(tmpdir: str) -> str:
    """Create the empty config file every sops invocation is pinned to.

    sops looks for a `.sops.yaml` by walking up from its working directory,
    which is this server's — typically the user's project, where a sops
    user very likely keeps one. Its creation rules would then override what
    this server intends: a `path_regex` that misses the temp file fails the
    call outright, and an `encrypted_regex` collides with the
    `--unencrypted-suffix` this server relies on. Pinning `--config` at an
    empty file removes the whole class; recipients still come from `--age`.
    """
    path = os.path.join(tmpdir, "empty-sops-config.yaml")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    return path


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

# Envelope flags that change what this server can promise about a file.
#
# `key_groups` / `shamir_threshold`: recipients move into `sops.key_groups`
# and the top-level `age` list is absent, so the file reads as having no
# recipients at all. Re-encrypting would flatten an n-of-m threshold into a
# plain single-group file any one holder could open.
#
# `mac_only_encrypted`: sops then MACs only the encrypted values, which
# voids the guarantee the rest of this design leans on — that the plaintext
# `_meta_unencrypted` block cannot be edited without breaking decryption.
# With it set, a file's recorded domain and each secret's `source` are
# freely rewritable by anyone who can edit the file, and `source` is what
# decides whether a value may be overwritten in place.
_UNSUPPORTED_FLAGS = ("key_groups", "shamir_threshold", "mac_only_encrypted")


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


def unsupported_key_features(encrypted_content: str) -> tuple[str, ...]:
    """Envelope features this server cannot reproduce when re-encrypting.

    It always encrypts with ``--age <recipients>`` and nothing else, so any
    file whose access rules go beyond a flat age recipient list would come
    back weaker than it went in: a PGP or KMS holder dropped, or an n-of-m
    Shamir threshold flattened into a list any single holder can open. It
    also refuses files whose metadata is unauthenticated, since the
    recorded domain and each secret's source are only trustworthy while
    the MAC covers them.

    A normal age file lists the other master-key groups empty and carries
    none of these flags, so this returns an empty tuple for it.
    """
    envelope = _envelope_of(encrypted_content)
    # Truthiness throughout: sops writes lists for the master-key groups,
    # but a truthy value of any other shape should still be treated as
    # present rather than waved through on a type check.
    found = [group for group in _NON_AGE_KEY_GROUPS if envelope.get(group)]
    found.extend(flag for flag in _UNSUPPORTED_FLAGS if envelope.get(flag))
    return tuple(found)


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

    return tuple(
        str(entry["recipient"]).strip()
        for entry in entries
        if isinstance(entry, dict) and entry.get("recipient")
    )


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
            empty_config = _write_empty_config(tmpdir)
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(plaintext_yaml)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "--config", empty_config,
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
            empty_config = _write_empty_config(tmpdir)
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(encrypted_content)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "--config", empty_config,
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
