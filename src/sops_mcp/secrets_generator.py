"""Random secret generation with charset support."""

import math
import secrets
import string

# Bounds on a generated secret's length. The upper bound is arbitrary but
# guards against a client asking for a value large enough to be a nuisance.
MIN_LENGTH = 1
MAX_LENGTH = 1024

# Below this many bits of effective entropy, a generated secret comes back
# with a warning. It is a warning only, never a refusal: short values have
# legitimate uses (PINs, test fixtures), and existing callers keep working.
MIN_RECOMMENDED_ENTROPY_BITS = 64

CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "alphanumeric_symbols": string.ascii_letters + string.digits + "!@#$%^&*()-_=+",
    "hex": string.hexdigits[:16],
    # A 64-character *alphabet* (letters, digits, '+' and '/'), drawn from
    # one character at a time. It is not base64 encoding: there is no '='
    # padding, any length is allowed, and the output does not decode to
    # anything. '+' and '/' need escaping in URLs, paths and form data, so
    # prefer 'urlsafe' there. Kept under this name for existing callers.
    "base64": string.ascii_letters + string.digits + "+/",
    # The RFC 4648 URL- and filename-safe alphabet: letters, digits, '-'
    # and '_'. Same size as 'base64', so the same entropy per character.
    "urlsafe": string.ascii_letters + string.digits + "-_",
    "numeric": string.digits,
}


def _alphabet(charset: str, exclude_chars: str = "") -> str:
    """The characters a secret is drawn from, after exclusions.

    Raises:
        ValueError: If charset is unknown or exclusions leave nothing.
    """
    if charset not in CHARSETS:
        raise ValueError(
            f"Unknown charset {charset!r}. "
            f"Valid options: {', '.join(sorted(CHARSETS))}"
        )
    chars = CHARSETS[charset]
    if exclude_chars:
        chars = "".join(c for c in chars if c not in exclude_chars)
    if not chars:
        raise ValueError("No characters remaining after exclusions")
    return chars


def entropy_bits(
    length: int,
    charset: str = "alphanumeric",
    exclude_chars: str = "",
) -> float:
    """Effective entropy of a generated secret: length x log2(alphabet size).

    The alphabet size is counted after `exclude_chars` are removed, since
    each character is drawn uniformly from what remains.
    """
    return length * math.log2(len(set(_alphabet(charset, exclude_chars))))


def entropy_warning(
    length: int,
    charset: str = "alphanumeric",
    exclude_chars: str = "",
) -> str | None:
    """A warning if a secret with these parameters is weak, else None.

    The text names only the parameters, never a value, so it is safe to
    return alongside the encrypted result.
    """
    bits = entropy_bits(length, charset, exclude_chars)
    if bits >= MIN_RECOMMENDED_ENTROPY_BITS:
        return None
    return (
        f"WARNING: about {bits:.0f} bits of entropy "
        f"({length} chars from a {len(set(_alphabet(charset, exclude_chars)))}"
        f"-character '{charset}' alphabet), below the recommended "
        f"{MIN_RECOMMENDED_ENTROPY_BITS}. Use a longer length or a larger "
        "charset unless this value is meant to be weak."
    )


def generate_secret(
    length: int = 32,
    charset: str = "alphanumeric",
    exclude_chars: str = "",
) -> str:
    """Generate a cryptographically random secret string.

    Args:
        length: Number of characters to generate.
        charset: One of the CHARSETS keys: 'alphanumeric',
                 'alphanumeric_symbols', 'hex', 'base64' (a 64-character
                 alphabet, not base64 encoding), 'urlsafe', 'numeric'.
        exclude_chars: Characters to omit from the charset.

    Returns:
        Random string of the given length. Weak parameters are allowed;
        see entropy_warning() to tell the caller about them.

    Raises:
        ValueError: If charset is unknown, length is invalid, or exclusions
                    leave an empty character set.
    """
    if charset not in CHARSETS:
        raise ValueError(
            f"Unknown charset {charset!r}. "
            f"Valid options: {', '.join(sorted(CHARSETS))}"
        )
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(
            f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}, "
            f"got {length}"
        )

    chars = _alphabet(charset, exclude_chars)
    return "".join(secrets.choice(chars) for _ in range(length))
