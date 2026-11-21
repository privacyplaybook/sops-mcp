"""lib/verify_grype_config.py: the image scan's .grype.yaml allowlist."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_grype_config", ROOT / "lib" / "verify_grype_config.py"
    )
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load_verifier()

CVE = "CVE-2026-00000"
REASON = "Only the minizip contrib code is affected; never linked. (#NN)"


def _run(tmp_path: Path, text: str, capsys) -> tuple[int, str]:
    path = tmp_path / ".grype.yaml"
    path.write_text(text)
    rc = verifier.main(["verify_grype_config.py", str(path)])
    return rc, capsys.readouterr().out


def _problems(rule: dict) -> list[str]:
    return verifier.check_config({"ignore": [rule]})


# --- files that pass ---------------------------------------------------------


def test_repo_allowlist_passes(capsys):
    rc = verifier.main(["verify_grype_config.py", str(ROOT / ".grype.yaml")])
    assert rc == 0, capsys.readouterr().out


@pytest.mark.parametrize(
    "text", ["", "ignore: []\n", "ignore:\n", "# only a comment\n"]
)
def test_empty_allowlists_pass(tmp_path, capsys, text):
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 0
    assert out == ""


def test_documented_example_passes(tmp_path, capsys):
    # The example in .grype.yaml's header comment.
    text = f"""
ignore:
  - vulnerability: {CVE}
    package:
      name: zlib
    reason: >-
      Only the minizip contrib code is affected; the image never links it.
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 0, out


def test_every_supported_key_passes():
    rule = {
        "vulnerability": CVE,
        "reason": REASON,
        "include-aliases": True,
        "namespace": "wolfi:distro:wolfi:rolling",
        "fix-state": "fixed",
        "match-type": "exact-direct-match",
        "vex-status": "not_affected",
        "vex-justification": "vulnerable_code_not_present",
        "package": {
            "name": "zlib",
            "version": "1.3.1-r0",
            "language": "python",
            "type": "apk",
            "location": "/usr/lib/**",
            "upstream-name": "zlib",
        },
    }
    assert _problems(rule) == []


# --- unknown keys (#60) ------------------------------------------------------


def test_misspelled_package_is_refused(tmp_path, capsys):
    # The #60 case: Grype ignores `pacakge:`, leaving a rule that silences
    # the CVE in every package.
    text = f"""
ignore:
  - vulnerability: {CVE}
    pacakge:
      name: zlib
    reason: {REASON}
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 1
    assert "::error file=" in out
    assert "unknown key `pacakge` (did you mean `package`?)" in out


def test_unknown_package_key_is_refused():
    rule = {"vulnerability": CVE, "reason": REASON, "package": {"nmae": "zlib"}}
    (problem,) = _problems(rule)
    assert "unknown key `package.nmae` (did you mean `package.name`?)" in problem


def test_mis_indented_package_is_refused():
    # `package:` left null and its `name:` landed at rule level.
    rule = {"vulnerability": CVE, "reason": REASON, "package": None, "name": "zlib"}
    problems = _problems(rule)
    assert any("`package` must be a non-empty mapping" in p for p in problems)
    assert any("unknown key `name`" in p for p in problems)


@pytest.mark.parametrize(
    "key", ["Package", "PACKAGE", "fix_state", "package-name", "cve"]
)
def test_other_unknown_keys_are_refused(key):
    rule = {"vulnerability": CVE, "reason": REASON, key: "x"}
    (problem,) = _problems(rule)
    assert f"unknown key `{key}`" in problem


def test_non_string_key_is_refused():
    rule = {"vulnerability": CVE, "reason": REASON, 1: "x"}
    (problem,) = _problems(rule)
    assert "unknown key `1`" in problem


# --- shapes ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("include-aliases", "yes please", "must be true or false"),
        ("include-aliases", 1, "must be true or false"),
        ("namespace", "", "must be a non-empty string"),
        ("namespace", ["a"], "must be a non-empty string"),
        ("fix-state", "not_fixed", "must be one of"),
        ("match-type", "fuzzy", "must be one of"),
        ("vex-status", "not-affected", "must be one of"),
        ("vex-justification", "because", "must be one of"),
        ("package", "zlib", "must be a non-empty mapping"),
        ("package", {}, "must be a non-empty mapping"),
        ("package", {"name": ""}, "`package.name` must be a non-empty string"),
        ("package", {"version": 1.3}, "`package.version` must be a non-empty string"),
    ],
)
def test_wrong_shapes_are_refused(key, value, expected):
    rule = {"vulnerability": CVE, "reason": REASON, key: value}
    (problem,) = _problems(rule)
    assert f"`{key}" in problem
    assert expected in problem


# --- the refusals that predate #60 -------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        {"reason": REASON, "package": {"name": "python-3.14"}},
        {"reason": REASON, "fix-state": "fixed"},
        {"vulnerability": "", "reason": REASON},
        {"vulnerability": "   ", "reason": REASON},
        {"vulnerability": None, "reason": REASON},
    ],
)
def test_rule_without_vulnerability_is_refused(rule):
    problems = _problems(rule)
    assert any("names no vulnerability" in p for p in problems)


@pytest.mark.parametrize("reason", [None, "", "  \n"])
def test_rule_without_reason_is_refused(reason):
    rule = {"vulnerability": CVE}
    if reason is not None:
        rule["reason"] = reason
    (problem,) = _problems(rule)
    assert "has no reason" in problem


def test_non_string_vulnerability_is_refused():
    (problem,) = _problems({"vulnerability": 2026, "reason": REASON})
    assert "names no vulnerability" in problem


def test_rule_that_is_not_a_mapping_is_refused():
    (problem,) = verifier.check_config({"ignore": [CVE]})
    assert "is not a mapping" in problem


@pytest.mark.parametrize(
    "key", ["exclude", "match", "only-fixed", "fail-on-severity", "Ignore"]
)
def test_other_top_level_settings_are_refused(key):
    (problem,) = verifier.check_config({"ignore": [], key: True})
    assert "only `ignore:` is allowed here" in problem
    assert key in problem


@pytest.mark.parametrize("cfg", [[], "ignore", 3])
def test_top_level_not_a_mapping_is_refused(cfg):
    (problem,) = verifier.check_config(cfg)
    assert "must be a mapping" in problem


def test_ignore_not_a_list_is_refused():
    (problem,) = verifier.check_config(
        {"ignore": {"vulnerability": CVE, "reason": REASON}}
    )
    assert "must be a list of rules" in problem


def test_every_bad_rule_is_reported(tmp_path, capsys):
    text = f"""
ignore:
  - vulnerability: {CVE}
  - reason: {REASON}
  - vulnerability: {CVE}
    reason: {REASON}
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 1
    assert out.count("::error") == 2


# --- YAML loading ------------------------------------------------------------


def test_duplicate_key_is_refused(tmp_path, capsys):
    # YAML keeps the last `package:`, silently dropping the first.
    text = f"""
ignore:
  - vulnerability: {CVE}
    package:
      name: zlib
    package:
      name: glibc
    reason: {REASON}
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 1
    assert "duplicate key `package`" in out


def test_invalid_yaml_is_refused(tmp_path, capsys):
    rc, out = _run(tmp_path, "ignore: [\n", capsys)
    assert rc == 1
    assert "cannot read the Grype allowlist" in out


def test_missing_file_is_refused(tmp_path, capsys):
    rc = verifier.main(["verify_grype_config.py", str(tmp_path / "absent.yaml")])
    assert rc == 1
    assert "cannot read the Grype allowlist" in capsys.readouterr().out


def test_unsafe_tags_are_refused(tmp_path, capsys):
    rc, out = _run(
        tmp_path, "ignore: !!python/object/apply:os.system ['true']\n", capsys
    )
    assert rc == 1
    assert "cannot read the Grype allowlist" in out


def test_unhashable_key_is_an_annotation_not_a_traceback(tmp_path, capsys):
    text = f"""
ignore:
  - vulnerability: {CVE}
    reason: {REASON}
    ? {{x: 1}}
    : 2
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 1
    assert "found an unhashable key" in out


def test_merge_key_override_is_not_a_duplicate(tmp_path, capsys):
    text = f"""
ignore:
  - &base
    vulnerability: {CVE}
    reason: {REASON}
  - <<: *base
    reason: Another reason, written once.
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 0, out


def test_annotations_are_escaped_and_located(tmp_path, capsys):
    text = f"""
ignore:
  - vulnerability: {CVE}
    package:
      name: zlib
    package:
      name: glibc
    reason: {REASON}
"""
    rc, out = _run(tmp_path, text, capsys)
    assert rc == 1
    (line,) = out.splitlines()  # one annotation, its newlines escaped
    assert ",line=6,col=5::" in line
    assert "%0A" in line


def test_percent_is_escaped(capsys):
    verifier._annotate("f", "100% sure\nnext")
    assert capsys.readouterr().out == "::error file=f::100%25 sure%0Anext\n"


def test_package_problems_name_the_key_once():
    rule = {"vulnerability": CVE, "reason": REASON, "package": {"nmae": "zlib"}}
    (problem,) = _problems(rule)
    assert problem.startswith("ignore rule unknown key `package.nmae`")
