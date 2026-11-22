"""SOPS encryption/decryption via CLI with secure temp file handling."""

import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Collection
from typing import Any

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


# sops reads and writes YAML 1.2 (Go), and PyYAML speaks YAML 1.1. The two
# disagree about plain scalars: `0189`, `1e3`, `0o17` and `0123456789` are
# strings to PyYAML, so a plain yaml.dump leaves them unquoted, and numbers
# to sops, which then stores them as numbers; `=` and `!!merge <<`, which
# sops writes unquoted for the strings "=" and "<<", make PyYAML's safe_load
# fail. So plaintext goes to sops as YAML with every string double-quoted
# (_QuotedStrDumper: ints, floats, bools and nulls keep their YAML types,
# which JSON input would turn into float64), comes back as JSON (nothing
# to resolve, though an integral float such as 5.0 comes back as int 5),
# and the YAML sops writes (the encrypted file, whose `_meta_unencrypted`
# block is plaintext) is read with the YAML 1.2 core schema below (#77).
_INT_RE = re.compile(r"[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+")
_FLOAT_RE = re.compile(
    r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)"
)


class SopsYamlLoader(yaml.SafeLoader):
    """A safe loader with the YAML 1.2 core schema.

    Plain scalars resolve only to null, bool, int and float as the YAML 1.2
    core schema defines them, and to str otherwise: no YAML 1.1 `yes`/`on`
    booleans, sexagesimals, timestamps or `=`. sops' own resolver (Go
    yaml.v3) accepts a little more as numbers (`0b101`, `1_000`, and `0123`
    as octal), so it quotes those strings when it writes them; reading them
    as strings here is the safe side. A `<<` key is still a merge key.
    """

    # Emptied, not inherited: only the resolvers added below apply.
    yaml_implicit_resolvers: dict = {}  # noqa: RUF012 - BaseResolver declares it


def _construct_int(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> int:
    value = loader.construct_scalar(node)
    if value.startswith(("0o", "0x")):
        return int(value, 0)
    return int(value, 10)  # 1.2: a leading zero is decimal, not octal


def _construct_float(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> float:
    value = loader.construct_scalar(node).lower()
    if value.endswith(".inf"):
        return -math.inf if value.startswith("-") else math.inf
    if value == ".nan":
        return math.nan
    return float(value)


def _construct_str(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
    return loader.construct_scalar(node)


for _tag, _regexp, _first in (
    ("tag:yaml.org,2002:null", r"~|null|Null|NULL|", [*"~nN", ""]),
    ("tag:yaml.org,2002:bool", r"true|True|TRUE|false|False|FALSE", list("tTfF")),
    ("tag:yaml.org,2002:int", _INT_RE.pattern, list("-+0123456789")),
    ("tag:yaml.org,2002:float", _FLOAT_RE.pattern, list("-+.0123456789")),
):
    SopsYamlLoader.add_implicit_resolver(
        _tag, re.compile(rf"^(?:{_regexp})$"), _first
    )
SopsYamlLoader.add_constructor("tag:yaml.org,2002:int", _construct_int)
SopsYamlLoader.add_constructor("tag:yaml.org,2002:float", _construct_float)
# sops writes the string "<<" as `!!merge <<`. As a value it is that string;
# SafeLoader still treats a `<<` *key* as a merge.
SopsYamlLoader.add_constructor("tag:yaml.org,2002:merge", _construct_str)


class _QuotedStrDumper(yaml.SafeDumper):
    """A safe dumper that writes every string double-quoted, so neither
    YAML 1.1 nor 1.2 can read one as anything else."""


def _represent_quoted_str(dumper: yaml.SafeDumper, value: str) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style='"')


_QuotedStrDumper.add_representer(str, _represent_quoted_str)


_INT64 = range(-(2**63), 2**63)


def _check_numbers(value: Any) -> None:
    """Refuse numbers sops can't store and give back exactly.

    sops keeps ints as int64 (larger ones fail or turn into float64), and
    decrypting to JSON can't write an infinite or NaN float.
    """
    if isinstance(value, dict):
        for item in value.values():
            _check_numbers(item)
    elif isinstance(value, list):
        for item in value:
            _check_numbers(item)
    elif isinstance(value, bool):
        return
    elif isinstance(value, int) and value not in _INT64:
        raise SopsError(
            "an integer is outside the 64-bit range sops can store; "
            "store it as a string"
        )
    elif isinstance(value, float) and not math.isfinite(value):
        raise SopsError(
            "an infinite or NaN number can't be stored; store it as a string"
        )


def _dump_for_sops(data: Any) -> str:
    """Plaintext YAML for sops to encrypt, with no ambiguous scalars.

    Raises:
        SopsError: If a number is one sops can't store exactly.
    """
    _check_numbers(data)
    return yaml.dump(
        data,
        Dumper=_QuotedStrDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=math.inf,
    )


def load_sops_yaml(content: str) -> Any:
    """Parse YAML that sops wrote (or reads) with sops' own scalar rules.

    Raises:
        yaml.YAMLError: If the content is not valid YAML.
    """
    return yaml.load(content, Loader=SopsYamlLoader)  # noqa: S506 - a SafeLoader


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

# The suffix every flat file this server writes is encrypted with: keys
# ending in it (the `_meta_unencrypted` block) stay plaintext, and every
# other value is encrypted.
UNENCRYPTED_SUFFIX = "_unencrypted"

# A root key of a flat file: what server.py's _validate_key_name enforces
# on input. Here too so encrypt() can refuse what a caller failed to check.
# Always applied with fullmatch: `$` also matches before a trailing newline.
KEY_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

# The one root key a flat file holds besides its secrets.
META_KEY = "_meta_unencrypted"


def _check_flat_root_keys(data: Any, carried: Collection[Any]) -> None:
    """Refuse to encrypt a flat file with a root key no tool may write.

    The last guard before the YAML is written: every handler validates the
    key names it adds, so this fires only for a caller that skipped that.
    Keys in `carried` came out of the file being re-encrypted and pass as
    they are, so a legacy file made with the sops CLI, whose keys need not
    follow the pattern, can still be rekeyed, renamed or trimmed. The one
    exception is a key ending in the unencrypted suffix, which is always
    refused.
    """
    if not isinstance(data, dict):
        raise SopsError("refusing to encrypt: data is not a mapping")
    for key in data:
        if key == META_KEY:
            continue
        if isinstance(key, str) and key.endswith(UNENCRYPTED_SUFFIX):
            # sops would leave this value in the clear. Never excused by
            # `carried`: a handler may be writing a new value into it.
            raise SopsError(
                f"refusing to encrypt: key {_shown(key)} ends in "
                f"{UNENCRYPTED_SUFFIX!r}, so its value would be stored in "
                "plaintext. Manage this file with the sops CLI."
            )
        if key in carried:
            continue
        if not isinstance(key, str) or not KEY_NAME_PATTERN.fullmatch(key):
            raise SopsError(
                f"refusing to encrypt: invalid key name {_shown(key)}. Key "
                "names must match ^[A-Z][A-Z0-9_]*$."
            )


# How much of a refused key an error message quotes.
_SHOWN_KEY_MAX = 64


def _shown(key: Any) -> str:
    """A key for an error message: repr-escaped, and cut short.

    Key names are plaintext in an encrypted file, but a refused key never
    reached one, and a caller that skipped validation could have put
    anything there.
    """
    text = repr(key)
    if len(text) <= _SHOWN_KEY_MAX:
        return text
    return text[:_SHOWN_KEY_MAX] + "…"


# What `sops_create_k8s_secret` encrypts with: only the `data` and
# `stringData` subtrees, so `apiVersion`, `kind`, `metadata` and `type`
# stay readable to kubectl and to a reviewer.
K8S_ENCRYPTED_REGEX = "^(data|stringData)$"

# Envelope keys that choose *which* values sops encrypts. The flat-file
# mutation path always re-encrypts with `--unencrypted-suffix _unencrypted`,
# so a file written under any of these would come back with a different set
# of values in the clear: a Kubernetes manifest would get `kind:` and
# `metadata:` encrypted, and a file that kept some value plaintext on
# purpose would lose that. sops records each of them in the envelope, which
# is what lets a file be recognised without decrypting it.
_ENCRYPTION_MODE_KEYS = (
    "encrypted_regex",
    "unencrypted_regex",
    "encrypted_suffix",
    "encrypted_comment_regex",
    "unencrypted_comment_regex",
)


def _envelope_of(encrypted_content: str) -> dict:
    """Return the `sops` metadata block, or raise if it isn't there."""
    try:
        parsed = load_sops_yaml(encrypted_content)
    except yaml.YAMLError as exc:
        raise SopsError(f"content is not valid YAML: {exc}") from exc
    return envelope_from(parsed)


def envelope_from(parsed: object) -> dict:
    """The `sops` block of an already-parsed document, or raise."""
    if not isinstance(parsed, dict) or "sops" not in parsed:
        raise SopsError(
            "content has no 'sops' metadata block — it does not look like a "
            "SOPS-encrypted file."
        )

    envelope = parsed["sops"]
    if not isinstance(envelope, dict):
        raise SopsError("the 'sops' metadata block is malformed.")
    return envelope


def encryption_mode_features(encrypted_content: str) -> tuple[str, ...]:
    """Envelope settings that encrypt a different set of values than ours.

    Returns the names of every encryption-mode key the envelope sets,
    plus ``unencrypted_suffix`` when it is set to anything but
    ``_unencrypted``. A file this server wrote in flat form returns an
    empty tuple; one from ``sops_create_k8s_secret`` returns
    ``("encrypted_regex",)``.
    """
    return encryption_mode_features_of(_envelope_of(encrypted_content))


def encryption_mode_features_of(envelope: dict) -> tuple[str, ...]:
    """:func:`encryption_mode_features`, for an envelope already in hand."""
    found = [key for key in _ENCRYPTION_MODE_KEYS if envelope.get(key)]
    suffix = envelope.get("unencrypted_suffix")
    if suffix and suffix != UNENCRYPTED_SUFFIX:
        found.append("unencrypted_suffix")
    return tuple(found)


def unsupported_key_features(encrypted_content: str) -> tuple[str, ...]:
    """Envelope features this server cannot reproduce when re-encrypting.

    It always encrypts with ``--age <recipients>`` and nothing else, so any
    file whose access rules go beyond a flat age recipient list would come
    back weaker than it went in: a PGP or KMS holder dropped, or an n-of-m
    Shamir threshold flattened into a list any single holder can open. It
    also refuses files whose metadata is unauthenticated, since the
    recorded domain and each secret's source are only trustworthy while
    the MAC covers them, and files encrypted under a different encryption
    mode (:func:`encryption_mode_features`), since re-encrypting would
    change which values are in the clear.

    A normal age file lists the other master-key groups empty and carries
    none of these flags, so this returns an empty tuple for it.
    """
    envelope = _envelope_of(encrypted_content)
    return key_features_of(envelope) + encryption_mode_features_of(envelope)


def key_features_of(envelope: dict) -> tuple[str, ...]:
    """The access-rule features (master keys, Shamir, MAC scope) alone."""
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

    def encrypt(
        self,
        data: dict,
        domain: Domain,
        *,
        encrypted_regex: str | None = None,
        carried: Collection[Any] = (),
    ) -> str:
        """Encrypt a dict as SOPS YAML, returning the encrypted content.

        By default keys ending with '_unencrypted' are left in plaintext by
        sops and every other value is encrypted.

        Args:
            data: Dict of key-value pairs to encrypt. May include a
                  '_meta_unencrypted' key that will be stored in plaintext.
            domain: The domain whose recipients the content is encrypted to.
            encrypted_regex: Encrypt only the subtrees under keys matching
                  this regex, and leave everything else plaintext, instead
                  of the suffix rule. sops records it in the envelope.
            carried: Root keys taken from the file being re-encrypted.
                  Under the suffix rule every other root key must be a
                  valid key name or `_meta_unencrypted`, or SopsError is
                  raised before sops runs.

        Returns:
            SOPS-encrypted YAML string.
        """
        if encrypted_regex is None:
            # Under the suffix rule every root key is a secret or the
            # metadata block. A manifest (encrypted_regex) has its own root
            # keys, and its caller validates the keys under stringData.
            _check_flat_root_keys(data, carried)
        # Every string quoted: see SopsYamlLoader.
        plaintext = _dump_for_sops(data)
        # sops refuses more than one encryption-mode flag, so exactly one.
        mode = (
            ["--encrypted-regex", encrypted_regex]
            if encrypted_regex is not None
            else ["--unencrypted-suffix", UNENCRYPTED_SUFFIX]
        )
        tmpdir = _make_secure_tempdir()
        tmpfile = os.path.join(tmpdir, "secrets.yaml")
        scratch_home = os.path.join(tmpdir, "home")

        try:
            os.mkdir(scratch_home, 0o700)
            empty_config = _write_empty_config(tmpdir)
            fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(plaintext)

            result = subprocess.run(
                [
                    self.sops_binary,
                    "--config", empty_config,
                    "encrypt",
                    "--age", domain.age_argument,
                    *mode,
                    "--input-type", "yaml",
                    "--output-type", "yaml",
                    tmpfile,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
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
                    # JSON keeps the type sops stored: see SopsYamlLoader.
                    "--output-type", "json",
                    tmpfile,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                env=self._child_env(domain, scratch_home, with_keys=True),
                check=False,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if re.search(r"json: unsupported value: (?:[+-]Inf|NaN)", stderr):
                    # Go's JSON encoder has no infinity or NaN. Its message
                    # names only the value kind, never the plaintext.
                    raise SopsError(
                        "sops decrypt failed: the file holds an infinite or "
                        "NaN number, which sops-mcp can't read. Quote it "
                        "with the sops CLI (sops edit), then try again. "
                        f"({stderr})"
                    )
                raise SopsError(f"sops decrypt failed: {stderr}")

            try:
                return json.loads(result.stdout) or {}
            except json.JSONDecodeError:
                # Not chained or echoed: the text is decrypted plaintext.
                raise SopsError(
                    "sops decrypt returned output that is not JSON"
                ) from None

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
