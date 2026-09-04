"""Engine edge cases that protect Wazuh 4.x compatibility."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from wazuhregex import WazuhRegex


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_ENV = os.environ.copy()
CLI_ENV["PYTHONPATH"] = os.pathsep.join(
    filter(None, (str(PROJECT_ROOT / "src"), CLI_ENV.get("PYTHONPATH")))
)


# OS_Regex: documented Wazuh 4.x syntax and boundary behaviour.


def test_osregex_top_level_alternatives_keep_their_own_anchors() -> None:
    tool = WazuhRegex("^root$|^admin$")

    assert tool.os_regex("root")[0] is True
    assert tool.os_regex("ADMIN")[0] is True
    assert tool.os_regex("xroot")[0] is False
    assert tool.os_regex("adminx")[0] is False


def test_osregex_star_class_can_match_empty_input() -> None:
    assert WazuhRegex(r"^\d*$").os_regex("") == (True, [(0, 0)])


@pytest.mark.parametrize(
    "pattern,text",
    [
        (r"^\$$", "$"),
        (r"^\($", "("),
        (r"^\)$", ")"),
        (r"^\\$", "\\"),
        (r"^\|$", "|"),
        (r"^\<$", "<"),
    ],
)
def test_osregex_documented_literal_escapes(pattern: str, text: str) -> None:
    assert WazuhRegex(pattern).os_regex(text)[0] is True


def test_osregex_space_class_rejects_other_whitespace() -> None:
    tool = WazuhRegex(r"^\s$")

    assert tool.os_regex(" ")[0] is True
    assert tool.os_regex("\t")[0] is False
    assert tool.os_regex("\n")[0] is False
    assert tool.os_regex("\N{NO-BREAK SPACE}")[0] is False


@pytest.mark.parametrize("character", ["-", "@", "_"])
def test_osregex_word_class_includes_wazuh_extra_word_characters(character: str) -> None:
    assert WazuhRegex(r"^\w$").os_regex(character)[0] is True


@pytest.mark.parametrize("character", [".", "/", "+", " "])
def test_osregex_word_class_rejects_non_word_characters(character: str) -> None:
    assert WazuhRegex(r"^\w$").os_regex(character)[0] is False


def test_osregex_bare_dot_and_escaped_dot_have_opposite_meanings() -> None:
    assert WazuhRegex(".").os_regex(".")[0] is True
    assert WazuhRegex(".").os_regex("X")[0] is False
    assert WazuhRegex(r"\.").os_regex("X")[0] is True


def test_osregex_lone_start_anchor_matches_nonempty_input() -> None:
    assert WazuhRegex("^").os_regex("event") == (True, [(0, 0)])


def test_osregex_escaped_dot_matches_newline() -> None:
    assert WazuhRegex(r"^\.$").os_regex("\n")[0] is True


@pytest.mark.parametrize("pattern", [r"\b", r"\x41", r"\1", r"\q", r"\^"])
def test_osregex_rejects_undocumented_escape_sequences(pattern: str) -> None:
    tool = WazuhRegex(pattern)

    assert tool.os_regex(pattern)[0] is False
    assert "OS_Regex" in tool.validation_errors()


def test_osregex_punctuation_class_excludes_backslash() -> None:
    assert WazuhRegex(r"^\p$").os_regex("\\")[0] is False


@pytest.mark.parametrize("pattern", [r"^(outer(inner))$", "((a))", "(abc", "abc)"])
def test_osregex_rejects_nested_or_unbalanced_groups(pattern: str) -> None:
    tool = WazuhRegex(pattern)

    assert "OS_Regex" in tool.validation_errors()


# OS_Match: anchors, alternatives, negation, and literal treatment.


def test_osmatch_negation_applies_after_anchored_alternatives() -> None:
    tool = WazuhRegex("!^debug$|^trace$")

    assert tool.os_match("debug") == (False, [])
    assert tool.os_match("TRACE") == (False, [])
    assert tool.os_match("debug details") == (True, [])
    assert tool.os_match("informational") == (True, [])


def test_osmatch_lone_anchors_are_zero_width_boundaries() -> None:
    assert WazuhRegex("^").os_match("event") == (True, [(0, 0)])
    assert WazuhRegex("$").os_match("event") == (True, [(5, 5)])
    assert WazuhRegex("^$").os_match("event") == (False, [])
    assert WazuhRegex("^$").os_match("") == (True, [(0, 0)])


@pytest.mark.parametrize("pattern", ["a.b", "a+b", "a*b", "a\\db", "a(b)", "a[b]"])
def test_osmatch_regex_metacharacters_remain_literal(pattern: str) -> None:
    assert WazuhRegex(f"^{pattern}$").os_match(pattern)[0] is True


def test_osmatch_bang_is_special_only_at_the_start() -> None:
    assert WazuhRegex("^a!b$").os_match("A!B")[0] is True


# PCRE2: Wazuh 4.x invokes pcre2_compile() with option bits 0.


def test_pcre2_dot_does_not_match_newline_by_default() -> None:
    assert WazuhRegex("^.$").pcre2_regex("X")[0] is True
    assert WazuhRegex("^.$").pcre2_regex("\n")[0] is False


def test_pcre2_is_case_sensitive_unless_inline_modifier_is_used() -> None:
    assert WazuhRegex("^POST$").pcre2_regex("post")[0] is False
    assert WazuhRegex("(?i)^POST$").pcre2_regex("post")[0] is True


@pytest.mark.parametrize(
    "pattern,text",
    [
        (r"^\x41$", "A"),
        (r"^\x{41}$", "A"),
        (r"^\x1$", "\x01"),
        (r"^\t$", "\t"),
        (r"^\r$", "\r"),
        (r"^\n$", "\n"),
        (r"^\f$", "\f"),
    ],
)
def test_pcre2_documented_character_escapes(pattern: str, text: str) -> None:
    assert WazuhRegex(pattern).pcre2_regex(text)[0] is True


def test_pcre2_hex_escape_with_no_digits_uses_zero_value() -> None:
    assert WazuhRegex(r"^\xz$").pcre2_regex("\x00z")[0] is True


def test_pcre2_rejects_braced_hex_outside_wazuh_8bit_range() -> None:
    assert "PCRE2" in WazuhRegex(r"\x{100}").validation_errors()


@pytest.mark.parametrize("utf_verb", ["(*UTF)", "(*UTF8)"])
def test_pcre2_utf_accepts_braced_hex_above_8bit_range(utf_verb: str) -> None:
    pattern = rf"{utf_verb}^\x{{100}}$"

    assert WazuhRegex._normalize_wazuh_pcre2(pattern) == pattern
    assert WazuhRegex(pattern).pcre2_regex("\u0100")[0] is True


@pytest.mark.parametrize(
    "pattern,text",
    [
        (r"(*UTF)(?x)^\x{23}$", "#"),
        (r"(*UTF)^[\x{5d}]$", "]"),
        (r"(*UTF)^\\\x{100}$", "\\\u0100"),
    ],
)
def test_pcre2_utf_braced_hex_adaptation_preserves_regex_syntax(
    pattern: str, text: str,
) -> None:
    assert WazuhRegex(pattern).pcre2_regex(text)[0] is True


def test_pcre2_utf_rejects_surrogate_braced_hex_escape() -> None:
    assert "PCRE2" in WazuhRegex(r"(*UTF)^\x{D800}$").validation_errors()


def test_pcre2_utf_does_not_adapt_braced_hex_inside_quoted_literal() -> None:
    pattern = WazuhRegex(r"(*UTF)^\Q\x{100}\E$")

    assert pattern.pcre2_regex(r"\x{100}")[0] is True
    assert pattern.pcre2_regex("\u0100")[0] is False


@pytest.mark.parametrize(
    "pattern",
    [
        "(*UTF)(?x)# ignored \\Q quote marker\n^\\x{100}$",
        "(*UTF)(?# ignored \\Q quote marker)^\\x{100}$",
        "(*UTF)(?x: # ignored \\Q quote marker\n)^\\x{100}$",
    ],
)
def test_pcre2_utf_adaptation_ignores_quote_markers_in_comments(
    pattern: str,
) -> None:
    assert WazuhRegex(pattern).pcre2_regex("\u0100")[0] is True


def test_pcre2_utf_extended_hash_in_character_class_is_not_a_comment() -> None:
    pattern = "(*UTF)(?x)^[#]\\x{100}$"

    assert WazuhRegex(pattern).pcre2_regex("#\u0100")[0] is True


@pytest.mark.parametrize("literal", [r"\#", r"\["])
def test_pcre2_utf_adaptation_preserves_escaped_syntax_in_extended_mode(
    literal: str,
) -> None:
    pattern = rf"(*UTF)(?x)^{literal}\x{{100}}$"

    assert WazuhRegex(pattern).pcre2_regex(literal[1] + "\u0100")[0] is True


@pytest.mark.parametrize("pattern", [r"\u0041", r"\U"])
def test_pcre2_rejects_alt_bsux_only_escapes(pattern: str) -> None:
    assert "PCRE2" in WazuhRegex(pattern).validation_errors()


def test_pcre2_character_classes_use_default_ascii_semantics() -> None:
    assert WazuhRegex(r"^\d+$").pcre2_regex("٣")[0] is False
    assert WazuhRegex(r"^\w+$").pcre2_regex("é")[0] is False
    assert WazuhRegex(r"^\s+$").pcre2_regex("\N{NO-BREAK SPACE}")[0] is False


@pytest.mark.parametrize("character", ["\n", "\v", "\f", "\r", "\x85", "\u2028", "\u2029"])
def test_pcre2_vertical_whitespace_class(character: str) -> None:
    assert WazuhRegex(r"^\v$").pcre2_regex(character)[0] is True


def test_pcre2_explicit_ucp_can_enable_unicode_character_properties() -> None:
    assert WazuhRegex(r"(*UCP)^\d+$").pcre2_regex("٣")[0] is True


def test_pcre2_backslash_c_matches_one_code_unit_for_ascii_input() -> None:
    assert WazuhRegex(r"^\C$").pcre2_regex("\n")[0] is True


def test_pcre2_lazy_quantifier_changes_match_boundaries() -> None:
    assert WazuhRegex("a+").pcre2_regex("aaa")[1] == [(0, 3)]
    assert WazuhRegex("a+?").pcre2_regex("aaa")[1] == [(0, 1), (1, 2), (2, 3)]


# Cross-engine differences must remain explicit rather than being normalized away.


def test_same_dot_spelling_has_different_osregex_and_pcre2_meaning() -> None:
    tool = WazuhRegex(".")

    assert tool.os_regex("X")[0] is False
    assert tool.pcre2_regex("X")[0] is True


def test_same_space_escape_has_different_osregex_and_pcre2_meaning() -> None:
    tool = WazuhRegex(r"^\s$")

    assert tool.os_regex("\t")[0] is False
    assert tool.pcre2_regex("\t")[0] is True


# CLI record handling.


def test_cli_skips_blank_and_whitespace_only_records() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wazuhregex", "event"],
        input="\n   \n\t\n",
        text=True,
        capture_output=True,
        check=False,
        env=CLI_ENV,
    )

    assert result.returncode == 0
    assert "Testing:" not in result.stdout


def test_cli_still_evaluates_nonempty_record_with_surrounding_spaces() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wazuhregex", "^ event $"],
        input=" event \n",
        text=True,
        capture_output=True,
        check=False,
        env=CLI_ENV,
    )

    assert result.returncode == 0
    assert "Testing:  event " in result.stdout
    assert "Match" in result.stdout
