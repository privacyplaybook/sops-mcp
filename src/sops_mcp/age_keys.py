"""Parsing and validation of age keys.

age encodes both halves of an X25519 keypair with bech32 (BIP-173):

- a *recipient* (public) is ``age1`` + bech32 payload, lowercase;
- an *identity* (private) is ``AGE-SECRET-KEY-1`` + bech32 payload,
  uppercased in its canonical form.

This module parses both and derives a recipient from an identity, so the
server can reject a domain whose private key does not belong to it at
startup rather than at first decrypt. Nothing here writes key material to
disk, and no exception raised here embeds the key it was given.
"""

import re

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "AgeKeyError",
    "is_plugin_identity",
    "is_plugin_recipient",
    "parse_identity",
    "parse_recipient",
    "recipient_from_identity",
    "recipient_is_derivable",
    "validate_recipient",
]

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_RECIPIENT_HRP = "age"
_IDENTITY_HRP = "age-secret-key-"
_KEY_BYTES = 32

# age itself does not impose bech32's 90-character limit (plugin identities
# exceed it), but an unbounded input would make the checksum loop a cheap
# way to burn CPU. No real age key comes close to this.
_MAX_LEN = 2048

# ``age1<plugin-name>1<payload>``. The name is letters-only on purpose: a
# corrupted X25519 recipient almost always carries digits in that span, so
# it falls through to the strict parse instead of being taken for a plugin
# key. A plugin whose name carries a digit would be rejected here; none of
# the deployed ones (yubikey, tpm, se) do.
_PLUGIN_RE = re.compile(r"^age1[a-z]{2,30}1[" + _CHARSET + r"]{6,}$")


class AgeKeyError(ValueError):
    """Raised when an age key is malformed.

    Messages never quote the offending key: identities are secret, and a
    recipient that failed to parse is often a mistyped identity.
    """


def _polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i, g in enumerate(generator):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(text: str, expected_hrp: str) -> list[int]:
    """Return the 5-bit data payload of ``text``, checksum verified."""
    if len(text) > _MAX_LEN:
        raise AgeKeyError("key is implausibly long")
    # A bech32 string is all-lower or all-upper. age uppercases identities,
    # so fold before checking: the checksum is defined over the lower form.
    if text != text.lower() and text != text.upper():
        raise AgeKeyError("key mixes upper and lower case")
    text = text.lower()

    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise AgeKeyError("key is not valid bech32")
    hrp, payload = text[:pos], text[pos + 1 :]
    if hrp != expected_hrp:
        # The prefix is not echoed: on a corrupted key it is a slice of the
        # key itself, and the caller may have pasted an identity here.
        raise AgeKeyError(f"key does not carry the {expected_hrp!r} prefix")

    data: list[int] = []
    for char in payload:
        found = _CHARSET.find(char)
        if found == -1:
            raise AgeKeyError("key contains a character outside the bech32 alphabet")
        data.append(found)

    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise AgeKeyError("key checksum is invalid (truncated or mistyped?)")
    return data[:-6]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int]:
    """Regroup bit-packed values; rejects lossy padding (decode direction)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise AgeKeyError("key payload is malformed")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise AgeKeyError("key payload has invalid padding")
    return ret


def is_plugin_recipient(text: str) -> bool:
    """True for a plugin recipient such as ``age1yubikey1...``.

    Plugin recipients are opaque to this server: it cannot derive them from
    an identity, so a domain using one skips the key-belongs-to-domain
    check. They still round-trip through the sops CLI unchanged.

    The shape is ``age1<plugin-name>1<payload>``. Requiring a plausible
    plugin name keeps a corrupted X25519 recipient — one where a typo
    introduced a ``1`` — from being waved through as a plugin key.
    """
    return bool(_PLUGIN_RE.match(text))


def parse_recipient(text: str) -> bytes:
    """Return the 32-byte X25519 public key encoded by an age recipient."""
    data = _bech32_decode(text, _RECIPIENT_HRP)
    raw = bytes(_convertbits(data, 5, 8))
    if len(raw) != _KEY_BYTES:
        raise AgeKeyError(
            f"recipient decodes to {len(raw)} bytes, expected {_KEY_BYTES}"
        )
    return raw


def parse_identity(text: str) -> bytes:
    """Return the 32-byte X25519 scalar encoded by an age identity."""
    data = _bech32_decode(text, _IDENTITY_HRP)
    raw = bytes(_convertbits(data, 5, 8))
    if len(raw) != _KEY_BYTES:
        raise AgeKeyError(
            f"identity decodes to {len(raw)} bytes, expected {_KEY_BYTES}"
        )
    return raw


def recipient_from_identity(text: str) -> str:
    """Derive the canonical ``age1...`` recipient for an age identity."""
    scalar = parse_identity(text)
    public = (
        X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return _bech32_encode(_RECIPIENT_HRP, public)


def validate_recipient(text: str) -> None:
    """Raise :class:`AgeKeyError` unless ``text`` is a usable recipient.

    Plugin recipients pass on shape alone — only an age plugin binary can
    say more, and this server never needs their bytes.
    """
    if not text.startswith("age1"):
        raise AgeKeyError("recipient must start with 'age1'")
    if is_plugin_recipient(text):
        return
    parse_recipient(text)


def is_plugin_identity(text: str) -> bool:
    """True for a plugin identity such as ``AGE-PLUGIN-YUBIKEY-1...``.

    The private half lives in hardware, so this server can neither parse it
    nor derive its recipient; it is handed to sops untouched.
    """
    return text.upper().startswith("AGE-PLUGIN-")


def recipient_is_derivable(text: str) -> bool:
    """True when :func:`recipient_from_identity` can be checked against this.

    False for plugin recipients, whose private half lives in hardware.
    """
    return not is_plugin_recipient(text)


def _bech32_encode(hrp: str, payload: bytes) -> str:
    data = _convertbits_encode(list(payload), 8, 5)
    checksum = _create_checksum(hrp, data)
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def _convertbits_encode(data: list[int], frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod([*values, 0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
