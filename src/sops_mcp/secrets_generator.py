"""Random secret generation with charset support."""

import secrets
import string

# Bounds on a generated secret's length. The upper bound is arbitrary but
# guards against a client asking for a value large enough to be a nuisance.
MIN_LENGTH = 1
MAX_LENGTH = 1024

CHARSETS = {
    "alphanumeric": string.ascii_letters + string.digits,
    "alphanumeric_symbols": string.ascii_letters + string.digits + "!@#$%^&*()-_=+",
    "hex": string.hexdigits[:16],
    "base64": string.ascii_letters + string.digits + "+/",
    "numeric": string.digits,
}


def generate_secret(
    length: int = 32,
    charset: str = "alphanumeric",
    exclude_chars: str = "",
) -> str:
    """Generate a cryptographically random secret string.

    Args:
        length: Number of characters to generate.
        charset: One of 'alphanumeric', 'alphanumeric_symbols', 'hex',
                 'base64', 'numeric'.
        exclude_chars: Characters to omit from the charset.

    Returns:
        Random string of the given length.

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

    chars = CHARSETS[charset]
    if exclude_chars:
        chars = "".join(c for c in chars if c not in exclude_chars)
    if not chars:
        raise ValueError("No characters remaining after exclusions")

    return "".join(secrets.choice(chars) for _ in range(length))
