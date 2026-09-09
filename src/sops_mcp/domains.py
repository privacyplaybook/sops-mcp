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

DEFAULT_DOMAIN = "default"
DOMAIN_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

_RECIPIENT_ENV = ("SOPS_MCP_AGE_PUBLIC_KEY", "SOPS_AGE_RECIPIENTS")
_KEY_ENV = "SOPS_AGE_KEY"
_DOMAINS_FILE_ENV = "SOPS_MCP_DOMAINS_FILE"
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
    for line in blob.splitlines():
        line = line.strip()
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


def _require_private_mode(path: str, what: str) -> None:
    """Refuse to read key material from a world- or group-readable file."""
    if os.name != "posix":
        return
    try:
        info = os.stat(path)
    except OSError as exc:
        raise DomainConfigError(f"cannot read {what} {path!r}: {exc.strerror}") from exc
    if info.st_mode & 0o077:
        raise DomainConfigError(
            f"{what} {path!r} is mode {info.st_mode & 0o777:04o}; it holds "
            "private key material and must not be readable by group or "
            "other. Run: chmod 600 " + path
        )
    if info.st_uid != os.geteuid():
        raise DomainConfigError(
            f"{what} {path!r} is owned by uid {info.st_uid}, not the uid "
            f"this server runs as ({os.geteuid()})."
        )


def _validate_domain(name: str, recipients: tuple[str, ...], keys: tuple[str, ...]) -> Domain:
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
        # A software identity always has a plain X25519 public half, so it
        # must match one of the derivable recipients even when the domain
        # also carries plugin recipients.
        if derived not in derivable:
            raise DomainConfigError(
                f"domain {name!r} private key #{index + 1} does not match any "
                f"of its {len(recipients)} recipient(s). Its public half is "
                f"{derived}. A key that cannot decrypt what the domain "
                "encrypts is a configuration mistake — add the matching "
                "recipient, or move the key to the right domain."
            )

    return Domain(name=name, recipients=recipients, keys=keys)


def _load_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise DomainConfigError(
            f"cannot read {_DOMAINS_FILE_ENV} {path!r}: {exc.strerror}"
        ) from exc
    except yaml.YAMLError as exc:
        raise DomainConfigError(f"{path!r} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise DomainConfigError(f"{path!r} must contain a YAML mapping.")

    version = raw.get("version", _SCHEMA_VERSION)
    if version != _SCHEMA_VERSION:
        raise DomainConfigError(
            f"{path!r} has version {version!r}; this server understands "
            f"version {_SCHEMA_VERSION}."
        )

    domains = raw.get("domains")
    if not isinstance(domains, dict) or not domains:
        raise DomainConfigError(
            f"{path!r} must define a non-empty 'domains' mapping."
        )
    return domains


def _domains_from_file(path: str) -> dict[str, Domain]:
    spec = _load_file(path)
    file_has_inline_keys = any(
        isinstance(body, dict) and body.get("keys") for body in spec.values()
    )
    if file_has_inline_keys:
        _require_private_mode(path, "domains file")

    domains: dict[str, Domain] = {}
    for name, body in spec.items():
        if not isinstance(name, str):
            raise DomainConfigError(f"domain name {name!r} must be a string.")
        if not isinstance(body, dict):
            raise DomainConfigError(f"domain {name!r} must be a mapping.")

        unknown = set(body) - {"recipients", "keys", "key_file"}
        if unknown:
            raise DomainConfigError(
                f"domain {name!r} has unknown field(s): "
                f"{', '.join(sorted(unknown))}. Expected: recipients, keys, "
                "key_file."
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

    The v1 environment variables become the ``default`` domain, so an
    existing single-recipient deployment needs no configuration change.
    """
    env = os.environ if env is None else env

    domains: dict[str, Domain] = {}
    path = (env.get(_DOMAINS_FILE_ENV) or "").strip()
    if path:
        domains = _domains_from_file(path)

    env_default = _default_from_env(env)
    if env_default is not None:
        if DEFAULT_DOMAIN in domains:
            raise DomainConfigError(
                f"domain {DEFAULT_DOMAIN!r} is defined both in {path!r} and "
                f"by {' / '.join(_RECIPIENT_ENV)}. Remove one — merging them "
                "would make the recipient set ambiguous."
            )
        domains[DEFAULT_DOMAIN] = env_default

    if not domains:
        raise DomainConfigError(
            "No age recipients configured. Set SOPS_MCP_AGE_PUBLIC_KEY (or "
            "SOPS_AGE_RECIPIENTS) for a single-domain setup, or point "
            f"{_DOMAINS_FILE_ENV} at a domains file."
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
