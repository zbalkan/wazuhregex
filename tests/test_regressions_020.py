"""Additional regression and edge-case coverage for the 0.2.x alpha series.

These tests intentionally separate documented Wazuh behaviour from known emulator
approximations. Known divergences are marked xfail so they stay visible without
pretending that the alpha emulator is already bit-for-bit compatible with Wazuh.
"""

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


# OS_Regex: documented syntax and boundary behaviour.


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
    # OS_Regex uses a bare dot literally and an escaped dot as its wildcard.
    assert WazuhRegex(".").os_regex(".")[0] is True
    assert WazuhRegex(".").os_regex("X")[0] is False
    assert WazuhRegex(r"\.").os_regex("X")[0] is True


@pytest.mark.xfail(
    reason="Known alpha divergence: the emulator currently special-cases lone ^ as empty-input only",
    strict=False,
)
def test_osregex_lone_start_anchor_matches_nonempty_input() -> None:
    assert WazuhRegex("^").os_regex("event") == (True, [(0, 0)])


@pytest.mark.xfail(
    reason="Known alpha divergence: translated \\. currently inherits PCRE2 newline behaviour",
    strict=False,
)
def test_osregex_escaped_dot_matches_newline() -> None:
    assert WazuhRegex(r"^\.$").os_regex("\n")[0] is True


@pytest.mark.xfail(
    reason="Known alpha divergence: unsupported OS_Regex escapes are currently treated as quoted literals",
    strict=False,
)
@pytest.mark.parametrize("pattern", [r"\b", r"\x41", r"\1", r"\q", r"\^"])
def test_osregex_rejects_undocumented_escape_sequences(pattern: str) -> None:
    assert "OS_Regex" in WazuhRegex(pattern).validation_errors()


@pytest.mark.xfail(
    reason="Known alpha divergence: current punctuation translation includes backslash",
    strict=False,
)
def test_osregex_punctuation_class_excludes_backslash() -> None:
    assert WazuhRegex(r"^\p$").os_regex("\\")[0] is False


@pytest.mark.xfail(
    reason="Known alpha divergence: the PCRE2 backend accepts nested groups that Wazuh OS_Regex rejects",
    strict=False,
)
def test_osregex_rejects_nested_groups_even_without_alternation() -> None:
    tool = WazuhRegex(r"^(outer(inner))$")

    assert "OS_Regex" in tool.validation_errors()
    assert tool.os_regex("outerinner")[0] is False


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


# PCRE2: documented semantics that differ from the legacy engines.


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
        pytest.param(
            r"^\x{41}$",
            "A",
            marks=pytest.mark.xfail(
                reason="Known alpha divergence: pcre2 0.6.0 does not accept Wazuh's documented braced hex form through this binding",
                strict=False,
            ),
        ),
        (r"^\t$", "\t"),
        (r"^\r$", "\r"),
        (r"^\n$", "\n"),
        (r"^\f$", "\f"),
    ],
)
def test_pcre2_documented_character_escapes(pattern: str, text: str) -> None:
    assert WazuhRegex(pattern).pcre2_regex(text)[0] is True


def test_pcre2_lazy_quantifier_changes_match_boundaries() -> None:
    assert WazuhRegex("a+").pcre2_regex("aaa")[1] == [(0, 3)]
    assert WazuhRegex("a+?").pcre2_regex("aaa")[1] == [(0, 1), (1, 2), (2, 3)]


@pytest.mark.xfail(
    reason="Known alpha divergence: the Python PCRE2 binding enables Unicode properties for str patterns",
    strict=False,
)
def test_pcre2_digit_class_is_ascii_as_documented_by_wazuh() -> None:
    assert WazuhRegex(r"^\d+$").pcre2_regex("٣")[0] is False


# Cross-engine differences should remain explicit rather than being normalised away.


def test_same_dot_spelling_has_different_osregex_and_pcre2_meaning() -> None:
    tool = WazuhRegex(".")

    assert tool.os_regex("X")[0] is False
    assert tool.pcre2_regex("X")[0] is True


def test_same_space_escape_has_different_osregex_and_pcre2_meaning() -> None:
    tool = WazuhRegex(r"^\s$")

    assert tool.os_regex("\t")[0] is False
    assert tool.pcre2_regex("\t")[0] is True


# CLI record handling: blank records are intentionally skipped, while content on
# non-empty records remains untouched.


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
