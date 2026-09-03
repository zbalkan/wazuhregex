"""Regression tests for algorithmic performance invariants.

These tests avoid wall-clock thresholds. They verify reuse and output properties
that keep repeated evaluation from regressing to avoidable per-line setup work.
"""

import pcre2

from wazuhregex.highlighter import Highlighter
from wazuhregex.wazuh_regex_lib import WazuhRegex


def test_compiled_regex_patterns_are_reused(monkeypatch) -> None:
    real_compile = pcre2.compile
    calls: list[str] = []

    def counting_compile(pattern, *args, **kwargs):
        calls.append(pattern)
        return real_compile(pattern, *args, **kwargs)

    monkeypatch.setattr(pcre2, "compile", counting_compile)

    tool = WazuhRegex(r"^event\d+$")
    assert tool.validation_errors() == {}
    assert tool.os_regex("EVENT42")[0] is True
    assert tool.pcre2_regex("event42")[0] is True
    assert tool.os_regex("EVENT43")[0] is True
    assert tool.pcre2_regex("event43")[0] is True
    assert tool.validation_errors() == {}

    # One compile for translated OS_Regex and one for PCRE2, regardless of
    # how many records are evaluated afterwards.
    assert len(calls) == 2


def test_compile_failures_are_cached(monkeypatch) -> None:
    real_compile = pcre2.compile
    calls = 0

    def counting_compile(pattern, *args, **kwargs):
        nonlocal calls
        calls += 1
        return real_compile(pattern, *args, **kwargs)

    monkeypatch.setattr(pcre2, "compile", counting_compile)

    tool = WazuhRegex("(")
    first = tool.validation_errors()
    second = tool.validation_errors()

    assert first == second
    # OS_Regex rejects the unbalanced group before reaching PCRE2 compilation;
    # only the PCRE2 engine calls the backend, and its failure is cached.
    assert calls == 1


def test_osmatch_compilation_is_reused() -> None:
    tool = WazuhRegex("^error$|warning|critical$")

    compiled = tool._os_match_compile()
    assert tool._os_match_compile() is compiled
    assert tool.os_match("WARNING event")[0] is True
    assert tool.os_match("fatal CRITICAL")[0] is True
    assert tool._os_match_compile() is compiled


def test_highlighter_handles_dense_ordered_matches_without_changing_text() -> None:
    text = "x" * 1024
    spans = [(index, index + 1) for index in range(len(text))]
    highlighter = Highlighter(highlight_color="<")

    highlighted = highlighter.apply(text, spans)

    assert highlighted.count("<") == len(text)
    assert highlighted.count(Highlighter.ENDC) == len(text)
    assert highlighted.replace("<", "").replace(Highlighter.ENDC, "") == text


def test_highlighter_keeps_unsorted_non_overlapping_span_behavior() -> None:
    highlighter = Highlighter(highlight_color="<")

    highlighted = highlighter.apply("one two", [(4, 7), (0, 3)])

    assert highlighted == f"<one{Highlighter.ENDC} <two{Highlighter.ENDC}"
