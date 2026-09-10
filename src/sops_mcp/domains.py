"""Key domains: named bundles of age recipients and their private keys.

A domain is the unit this server encrypts to and decrypts with. Splitting
the key material into named domains lets one process serve several
independent recipient sets, and — more importantly — lets every mutation
check that the file it is about to re-encrypt already belongs to the
recipient set it is about to encrypt to. See ``docs/design/domains.md``.

Nothing in this module logs or reprs private key material. :class:`Domain`
overrides ``__repr__`` for that reason: a bare dataclass repr in a
traceback would print every identity the server holds.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

import yaml

from .age_keys import (
    AgeKeyError,
    is_plugin_identity,
    recipient_from_identity,
    recipient_is_derivable,
    validate_recipient,
)

__all__ = [
    "DEFAULT_DOMAIN",
    "Domain",
    "DomainConfigError",
    "load_domains",
]

logger = logging.getLogger(__name__)

DEFAULT_DOMAIN = "default"
DOMAIN_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

_RECIPIENT_ENV = ("SOPS_MCP_AGE_PUBLIC_KEY", "SOPS_AGE_RECIPIENTS")
_KEY_ENV = "SOPS_AGE_KEY"
_DOMAINS_FILE_ENV = "SOPS_MCP_DOMAINS_FILE"
_DOMAINS_ENV = "SOPS_MCP_DOMAINS"
_REQUIRE_DOMAIN_ENV = "SOPS_MCP_REQUIRE_DOMAIN"

_SCHEMA_VERSION = 1


class DomainConfigError(Exception):
    """Raised at startup when the domain configuration is unusable.

    Every instance is fatal: a half-valid key configuration is the kind of
    thing that silently encrypts to the wrong party.
    """


@dataclass(frozen=True)
class Domain:
    """One named recipient set, with the private keys the server holds."""

    name: str
    recipients: tuple[str, ...]
    keys: tuple[str, ...] = field(default=(), repr=False)

    @property
    def encrypt_only(self) -> bool:
        """True when this domain can encrypt but not decrypt."""
        return not self.keys

    @property
    def age_argument(self) -> str:
        """The value for ``sops encrypt --age``."""
        return ",".join(self.recipients)

    def public_summary(self) -> dict:
        """A description safe to return across the MCP boundary.

        Recipients are public keys and are included. Private keys are
        reduced to a count.
        """
        return {
            "name": self.name,
            "recipients": list(self.recipients),
            "recipient_count": len(self.recipients),
            "key_count": len(self.keys),
            "encrypt_only": self.encrypt_only,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Domain(name={self.name!r}, "
            f"recipients={len(self.recipients)}, keys={len(self.keys)})"
        )


def _split_keys(blob: str) -> list[str]:
    """Split an age keys blob into identities, dropping comments/blanks."""
    keys = []
    for raw in blob.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        keys.append(line)
    return keys


def _split_recipients(blob: str) -> list[str]:
    """Split a comma- or whitespace-separated recipient list."""
    parts = re.split(r"[,\s]+", blob.strip())
    return [p for p in parts if p]


def _dedupe(items: list[str]) -> tuple[str, ...]:
    """Drop duplicates, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


def _stat_or_fail(path: str, what: str) -> os.stat_result:
    try:
        return os.stat(path)
    except OSError as exc:
        raise DomainConfigError(
            f"cannot read {what} {path!r}: {exc.strerror}"
        ) from exc


def _require_trusted_writer(path: str, what: str) -> None:
    """Refuse a file that someone other than the server or root can rewrite.

    This is the integrity half, and it applies to the domains file whether
    or not it holds key material: that file decides which recipients every
    secret is encrypted to, so a group-writable one lets a local attacker
    add their own recipient and have the server encrypt to it on the next
    restart.
    """
    if os.name != "posix":
        return
    info = _stat_or_fail(path, what)

    if info.st_mode & 0o022:
        raise DomainConfigError(
            f"{what} {path!r} is mode {info.st_mode & 0o777:04o} and is "
            "writable by group or other. It controls which recipients "
            "secrets are encrypted to, so anyone who can rewrite it can "
            f"redirect them. Run: chmod go-w {path}"
        )
    if info.st_uid not in (os.geteuid(), 0):
        raise DomainConfigError(
            f"{what} {path!r} is owned by uid {info.st_uid}, which is "
            f"neither this server's uid ({os.geteuid()}) nor root. Its "
            "owner could rewrite it at any time."
        )


def _require_private_mode(path: str, what: str) -> None:
    """The rules for a file holding private keys.

    Integrity first, then confidentiality: world-readable is fatal, and
    group-readable earns a warning rather than a refusal. Container secret
    mounts routinely arrive root-owned and group-readable to the runtime
    user, and refusing those outright pushes operators back to putting the
    key in an environment variable, which is worse — /proc and
    `docker inspect` both expose it.
    """
    if os.name != "posix":
        return
    _require_trusted_writer(path, what)
    info = _stat_or_fail(path, what)

    if info.st_mode & 0o004:
        raise DomainConfigError(
            f"{what} {path!r} is mode {info.st_mode & 0o777:04o} and is "
            "readable by any user on the host. It holds private key "
            f"material. Run: chmod o-r {path}"
        )
    if info.st_mode & 0o040:
        logger.warning(
            "%s %r is group-readable (mode %04o); anyone in that group can "
            "read the private key.",
            what,
            path,
            info.st_mode & 0o777,
        )


def _validate_domain(
    name: str, recipients: tuple[str, ...], keys: tuple[str, ...]
) -> Domain:
    """Validate one domain's key material, returning the frozen Domain."""
    if not DOMAIN_NAME_RE.match(name):
        raise DomainConfigError(
            f"invalid domain name {name!r}: must start with a lowercase "
            "letter and contain only lowercase letters, digits and hyphens "
            "(max 63 characters)."
        )
    if not recipients:
        raise DomainConfigError(f"domain {name!r} has no recipients.")

    for recipient in recipients:
        try:
            validate_recipient(recipient)
        except AgeKeyError as exc:
            raise DomainConfigError(
                f"domain {name!r} has an invalid recipient: {exc}"
            ) from exc

    derivable = {r for r in recipients if recipient_is_derivable(r)}

    for index, identity in enumerate(keys):
        if is_plugin_identity(identity):
            # Backed by hardware: neither parseable nor derivable here. Only
            # the age plugin binary can say whether it belongs.
            continue
        try:
            derived = recipient_from_identity(identity)
        except AgeKeyError as exc:
            # Positional, never the key itself.
            raise DomainConfigError(
                f"domain {name!r} private key #{index + 1} is invalid: {exc}"
            ) from exc
        # A software identity always has a plain X25519 public half. One
        # that matches no current recipient is usually a key being rotated
        # out: it still opens files encrypted before the change, and
        # sops_rekey is how those get migrated. Refusing to start would
        # strand exactly the deployment that is mid-rotation, so warn and
        # keep it.
        if derived not in derivable:
            logger.warning(
                "domain %r holds a private key (#%d) that matches none of "
                "its %d recipient(s); its public half is %s. It can still "
                "decrypt files encrypted before a recipient change — use "
                "sops_rekey to migrate them — but it cannot read anything "
                "this domain encrypts from now on.",
                name,
                index + 1,
                len(recipients),
                derived,
            )

    return Domain(name=name, recipients=recipients, keys=keys)


def _parse_domains_doc(text: str, source: str) -> dict:
    """Validate the top-level shape of a domains document.

    Shared by the file and the inline environment variable so the two
    cannot drift. YAML is a superset of JSON, so a compact single-line
    JSON object parses here too -- which is what makes the inline form
    practical in an environment variable.
    """
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise DomainConfigError(f"{source} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise DomainConfigError(f"{source} must contain a YAML mapping.")

    version = raw.get("version", _SCHEMA_VERSION)
    if version != _SCHEMA_VERSION:
        raise DomainConfigError(
            f"{source} has version {version!r}; this server understands "
            f"version {_SCHEMA_VERSION}."
        )

    domains = raw.get("domains")
    if not isinstance(domains, dict) or not domains:
        raise DomainConfigError(
            f"{source} must define a non-empty 'domains' mapping."
        )
    return domains


def _load_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise DomainConfigError(
            f"cannot read {_DOMAINS_FILE_ENV} {path!r}: {exc.strerror}"
        ) from exc
    return _parse_domains_doc(text, repr(path))


def _build_domains(
    spec: dict, *, allow_keys: bool, source: str
) -> dict[str, Domain]:
    """Turn a validated ``domains`` mapping into :class:`Domain` objects.

    ``allow_keys`` is False for the inline environment variable. Private
    key material must come from a file so that it keeps the permission
    checks in :func:`_require_private_mode` and stays out of
    ``docker inspect`` and ``/proc/<pid>/environ``.
    """
    domains: dict[str, Domain] = {}
    for name, body in spec.items():
        if not isinstance(name, str):
            raise DomainConfigError(f"domain name {name!r} must be a string.")
        if not isinstance(body, dict):
            raise DomainConfigError(f"domain {name!r} must be a mapping.")

        permitted = {"recipients", "keys", "key_file"}
        unknown = set(body) - permitted
        if unknown:
            raise DomainConfigError(
                f"domain {name!r} has unknown field(s): "
                f"{', '.join(sorted(unknown))}. Expected: recipients, keys, "
                "key_file."
            )

        if not allow_keys:
            offending = sorted(k for k in ("keys", "key_file") if body.get(k))
            if offending:
                raise DomainConfigError(
                    f"domain {name!r} in {source} sets "
                    f"{' and '.join(offending)}. Private key material cannot "
                    f"be given inline in {_DOMAINS_ENV}: an environment "
                    "variable is visible to `docker inspect` and "
                    "/proc/<pid>/environ, and cannot carry the file "
                    f"permission checks. Move this domain into a "
                    f"{_DOMAINS_FILE_ENV} document; the two are merged, so "
                    "public-recipient domains can stay here."
                )

        recipients_raw = body.get("recipients") or []
        if isinstance(recipients_raw, str):
            recipients_raw = _split_recipients(recipients_raw)
        if not isinstance(recipients_raw, list):
            raise DomainConfigError(
                f"domain {name!r}: 'recipients' must be a list."
            )
        recipients = _dedupe([str(r).strip() for r in recipients_raw if str(r).strip()])

        keys_raw = body.get("keys") or []
        if isinstance(keys_raw, str):
            keys_raw = _split_keys(keys_raw)
        if not isinstance(keys_raw, list):
            raise DomainConfigError(f"domain {name!r}: 'keys' must be a list.")
        keys = [str(k).strip() for k in keys_raw if str(k).strip()]

        key_file = body.get("key_file")
        if key_file:
            key_file = str(key_file)
            _require_private_mode(key_file, "key_file")
            try:
                with open(key_file, encoding="utf-8") as handle:
                    keys.extend(_split_keys(handle.read()))
            except OSError as exc:
                raise DomainConfigError(
                    f"domain {name!r}: cannot read key_file {key_file!r}: "
                    f"{exc.strerror}"
                ) from exc

        domains[name] = _validate_domain(name, recipients, _dedupe(keys))
    return domains


def _domains_from_file(path: str) -> dict[str, Domain]:
    spec = _load_file(path)
    file_has_inline_keys = any(
        isinstance(body, dict) and body.get("keys") for body in spec.values()
    )
    if file_has_inline_keys:
        _require_private_mode(path, "domains file")
    else:
        # No key material in it, but it still decides the recipients.
        _require_trusted_writer(path, "domains file")

    return _build_domains(spec, allow_keys=True, source=repr(path))


def _domains_from_env_doc(text: str) -> dict[str, Domain]:
    """Build domains from an inline ``SOPS_MCP_DOMAINS`` document.

    Public recipient sets only -- see :func:`_build_domains`. There is no
    permission check to apply here: the variable is set by whoever
    controls the deployment, which is the same authority that would own
    the file.
    """
    spec = _parse_domains_doc(text, _DOMAINS_ENV)
    return _build_domains(spec, allow_keys=False, source=_DOMAINS_ENV)


def _default_from_env(env) -> Domain | None:
    """Build the implicit ``default`` domain from the v1 environment."""
    recipients_blob = ""
    for var in _RECIPIENT_ENV:
        if env.get(var):
            recipients_blob = env[var]
            break
    if not recipients_blob:
        return None

    recipients = _dedupe(_split_recipients(recipients_blob))
    keys = _dedupe(_split_keys(env.get(_KEY_ENV, "") or ""))
    return _validate_domain(DEFAULT_DOMAIN, recipients, keys)


def load_domains(env=None) -> dict[str, Domain]:
    """Build every configured domain, or raise :class:`DomainConfigError`.

    Three sources are merged, and a name defined by more than one is
    fatal rather than silently resolved:

    * ``SOPS_MCP_DOMAINS_FILE`` -- a domains document on disk. The only
      source that may carry private keys, because it is the only one that
      can be permission-checked.
    * ``SOPS_MCP_DOMAINS`` -- the same document inline, for public
      recipient sets. YAML or compact JSON.
    * The v1 environment variables, which become the ``default`` domain,
      so an existing single-recipient deployment needs no config change.
    """
    env = os.environ if env is None else env

    domains: dict[str, Domain] = {}
    origin: dict[str, str] = {}

    def _merge(new: dict[str, Domain], source: str) -> None:
        for name, domain in new.items():
            if name in domains:
                raise DomainConfigError(
                    f"domain {name!r} is defined both in {origin[name]} and "
                    f"{source}. Remove one \u2014 merging them would make the "
                    "recipient set ambiguous."
                )
            domains[name] = domain
            origin[name] = source

    path = (env.get(_DOMAINS_FILE_ENV) or "").strip()
    if path:
        _merge(_domains_from_file(path), f"{_DOMAINS_FILE_ENV} ({path!r})")

    inline = (env.get(_DOMAINS_ENV) or "").strip()
    if inline:
        _merge(_domains_from_env_doc(inline), _DOMAINS_ENV)

    env_default = _default_from_env(env)
    if env_default is not None:
        _merge({DEFAULT_DOMAIN: env_default}, " / ".join(_RECIPIENT_ENV))

    if not domains:
        raise DomainConfigError(
            "No age recipients configured. Set SOPS_MCP_AGE_PUBLIC_KEY (or "
            "SOPS_AGE_RECIPIENTS) for a single-domain setup, define domains "
            f"inline in {_DOMAINS_ENV}, or point {_DOMAINS_FILE_ENV} at a "
            "domains file."
        )
    return domains


def require_explicit_domain(env=None) -> bool:
    """True when tool calls must name a domain instead of falling back."""
    env = os.environ if env is None else env
    return (env.get(_REQUIRE_DOMAIN_ENV) or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
