"""Validate .grype.yaml, the image scan's allowlist (.github/actions/image-scan).

Run by the image-scan action before Grype, and unit-tested in
tests/test_verify_grype_config.py. Exits 1, with one GitHub `::error`
annotation per problem, if the file:

- holds any top-level key but `ignore:`. Any other Grype setting here
  (`exclude:` paths, `match:` toggles, `only-fixed`, `fail-on-severity`, ...)
  could narrow the scan with no reason recorded; the gate's settings belong in
  the action and its callers.
- has an `ignore:` rule that names no `vulnerability:` or carries no
  `reason:`. A rule with no vulnerability (say `package: {name: python-3.14}`,
  or `fix-state: fixed`) would silence a whole package, or the whole gate
  under --only-fixed, so it is refused even with a reason.
- has a rule key Grype doesn't know, or a known key of the wrong shape. Grype
  ignores unknown keys, so a typo such as `pacakge:` would leave a rule that
  matches the vulnerability in every package. Keys are compared exactly:
  Grype's config loader is case-insensitive, so `Package:` would take effect
  in Grype, but it is refused here as unknown, which fails closed.
- repeats a key in one mapping. YAML keeps only the last value, so a
  second `package:` would silently replace the first.

The allowed keys and values are those of Grype's IgnoreRule and
IgnoreRulePackage at the version the action pins (grype/match/ignore.go,
grype/match/type.go, grype/vulnerability/fix.go, grype/vex/status). When
bumping Grype, check those for new keys before adding them here.

Usage: python3 -I lib/verify_grype_config.py [path]   (default .grype.yaml)
Needs PyYAML (the runner's system Python has it).
"""

from __future__ import annotations

import difflib
import sys
from collections.abc import Callable

import yaml

DEFAULT_PATH = ".grype.yaml"

FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown")
MATCH_TYPES = ("exact-direct-match", "exact-indirect-match", "cpe-match")
VEX_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
VEX_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

# Each check returns a problem description, or None when the value is fine.
Check = Callable[[object], "str | None"]


def _string(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "must be a non-empty string"
    return None


def _boolean(value: object) -> str | None:
    if not isinstance(value, bool):
        return "must be true or false"
    return None


def _one_of(choices: tuple[str, ...]) -> Check:
    def check(value: object) -> str | None:
        if value not in choices:
            return f"must be one of {', '.join(choices)}"
        return None

    return check


PACKAGE_KEYS: dict[str, Check] = {
    "name": _string,
    "version": _string,
    "language": _string,
    "type": _string,
    "location": _string,
    "upstream-name": _string,
}


def _package(value: object) -> str | None:
    # An empty or null `package:` (often a mis-indented one, whose `name:`
    # landed at rule level) narrows nothing, so it is refused.
    if not isinstance(value, dict) or not value:
        return "must be a non-empty mapping of " + ", ".join(PACKAGE_KEYS)
    problems = _check_keys(value, PACKAGE_KEYS, "package.")
    return "; ".join(problems) if problems else None


RULE_KEYS: dict[str, Check] = {
    "vulnerability": _string,
    "reason": _string,
    "include-aliases": _boolean,
    "namespace": _string,
    "fix-state": _one_of(FIX_STATES),
    "package": _package,
    "vex-status": _one_of(VEX_STATUSES),
    "vex-justification": _one_of(VEX_JUSTIFICATIONS),
    "match-type": _one_of(MATCH_TYPES),
}

REQUIRED_RULE_KEYS = ("vulnerability", "reason")


def _check_keys(
    mapping: dict, allowed: dict[str, Check], prefix: str = ""
) -> list[str]:
    problems = []
    for key, value in mapping.items():
        check = allowed.get(key) if isinstance(key, str) else None
        if check is None:
            hint = ""
            if isinstance(key, str):
                close = difflib.get_close_matches(key, allowed, n=1)
                if close:
                    hint = f" (did you mean `{prefix}{close[0]}`?)"
            problems.append(f"unknown key `{prefix}{key}`{hint}")
            continue
        problem = check(value)
        if problem:
            problems.append(f"`{prefix}{key}` {problem}")
    return problems


def check_rule(rule: object) -> list[str]:
    """Return the problems with one `ignore:` rule (empty when it is valid)."""
    if not isinstance(rule, dict):
        return ["is not a mapping"]
    problems = []
    # Missing or empty required keys keep the wording CI has always printed.
    if _string(rule.get("vulnerability")):
        problems.append("names no vulnerability")
    if _string(rule.get("reason")):
        problems.append("has no reason")
    present = {k: v for k, v in rule.items() if k not in REQUIRED_RULE_KEYS}
    problems.extend(_check_keys(present, RULE_KEYS))
    return problems


def check_config(cfg: object) -> list[str]:
    """Return every problem in a parsed .grype.yaml (empty when it is valid)."""
    if cfg is None:
        return []
    if not isinstance(cfg, dict):
        return ["must be a mapping with only an `ignore:` key"]
    extra = sorted(map(str, set(cfg) - {"ignore"}))
    if extra:
        return [f"only `ignore:` is allowed here, found: {', '.join(extra)}"]
    rules = cfg.get("ignore") or []
    if not isinstance(rules, list):
        return ["`ignore:` must be a list of rules"]
    return [
        f"ignore rule {problem}: {rule}"
        for rule in rules
        for problem in check_rule(rule)
    ]


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses a key repeated in one mapping."""


def _construct_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key `{key}`", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load(text: str) -> object:
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else DEFAULT_PATH
    try:
        with open(path) as f:
            cfg = load(f.read())
    except (OSError, yaml.YAMLError) as e:
        print(f"::error file={path}::cannot read the Grype allowlist: {e}")
        return 1
    problems = check_config(cfg)
    for problem in problems:
        print(f"::error file={path}::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
