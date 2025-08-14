from types import TracebackType
from typing import Final, List, Optional, Tuple, Type

import pcre2


class WazuhRegex:
    """
    A Python class that emulates the logic of Wazuh's os_regex.h and
    os_match.h libraries.

    This class is designed to be a high-fidelity testing tool for Wazuh
    regex and sregex patterns. It replicates many of the specific behaviors
    and limitations of the native Wazuh engine.

    Usage:
        try:
            # 1. Instantiate the class with a Wazuh pattern.
            # This will compile the pattern and validate its syntax.
            regex_tool = WazuhRegex("your_wazuh_pattern")

            # 2. Execute the match against your text.
            is_match, spans = regex_tool.os_regex_execute("some log text")
            if is_match:
                print(f"Match found at spans: {spans}")
                substrings = regex_tool.get_substrings()
                print(f"Captured substrings: {substrings}")

        except ValueError as e:
            print(f"Pattern failed to compile: {e}")

    Known Emulation Differences:
        - The underlying Python `re` engine uses a backtracking algorithm, which
          is more powerful than the non-backtracking C engine. This means some
          complex patterns with multiple greedy quantifiers (e.g., `\\p*\\d*...`)
          may succeed here when they would fail in Wazuh.
    """

    _INVALID_GROUP_ALTERNATION = pcre2.compile(r'\([^)]*\|[^)]*\)', flags=pcre2.U, jit=True)
    _INVALID_MODIFIER_USE = pcre2.compile(r'(?<!\\[wdspWDSP\.])[*+]')

    # Centralized translation rules. The order is critical for correctness.
    _TRANSLATION_RULES: Final[List[Tuple[str, str]]] = [
        (r'\\', r'\\'),
        (r'\D', r'[^0-9]'),
        (r'\W', r'[^a-zA-Z0-9_@\-]'),
        (r'\S', r'[^ ]'),
        (r'\d', r'[0-9]'),
        (r'\w', r'[a-zA-Z0-9_@\-]'),
        (r'\s', r'[ ]'),
        (r'\t', r'\t'),
        (r'\p', r'[-\(\)\*\+,.\\:;<=>?\"\'#$%&\|{}]'),
        (r'\.', r'.'),
        (r'\*', r'\\*'),
        (r'[(', r'\[('),
        (r')]', r')\]'),
    ]

    def __init__(self, pattern: str) -> None:
        self._raw_pattern: str = pattern

    def __enter__(self) -> 'WazuhRegex':
        """
        Performs compilation and validation upon entering the 'with' block.
        Returns the instance of itself.
        """
        self._os_regex_compiled = None
        self._os_match_compiled = []
        self._last_os_regex_substrings = []
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]],
                 exc_value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> None:
        """
        Handles cleanup upon exiting the 'with' block.
        (No specific cleanup needed, but implemented for protocol correctness).
        """
        pass

    def _os_regex_compile(self, pattern: str) -> None:
        if self._INVALID_GROUP_ALTERNATION.search(pattern):
            raise ValueError(
                "Invalid pattern: Alternation '|' is not allowed inside groups '()'.")

        if self._INVALID_MODIFIER_USE.search(pattern):
            raise ValueError(
                "Invalid pattern: Modifiers '*' or '+' can only be applied to backslash expressions (e.g., \\d+), not bare characters (e.g., a+).")

        translation = pattern
        for old, new in self._TRANSLATION_RULES:
            translation = translation.replace(old, new)

        try:
            self._os_regex_compiled = pcre2.compile(translation, pcre2.IGNORECASE)
        except Exception as e:
            error_msg = (
                f"Pattern '{pattern}' failed to compile.\n"
                f"Translated Python pattern: '{translation}'\n"
                f"Error: {e}"
            )
            raise ValueError(error_msg)

    def os_regex(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """
        Emulates OSRegex_Execute.
        Returns a boolean and a list of (start, end) tuples for matches.
        """
        self._last_os_regex_substrings = []

        if self._raw_pattern in ('$', '^$', '^'):
            return (True, [(0, 0)]) if text == "" else (False, [])

        try:
            self._os_regex_compile(self._raw_pattern)
        except (ValueError, TypeError):
            return False, []

        if not self._os_regex_compiled:
            return False, []

        match: Optional[pcre2.Match] = self._os_regex_compiled.search(text)

        if not match:
            return False, []

        self._last_os_regex_substrings = list(match.groups())
        return True, [match.span()]

    def get_substrings(self) -> list[str]:
        """Returns the substrings captured by groups in the last os_regex_execute call."""
        return self._last_os_regex_substrings

    def _os_match_compile(self, pattern: str) -> None:
        self._os_match_compiled = []
        is_negated = pattern.startswith('!')
        if is_negated:
            pattern = pattern[1:]
        sub_patterns = pattern.split('|')
        for sub in sub_patterns:
            is_start_anchored = sub.startswith('^')
            is_end_anchored = sub.endswith('$')
            clean_sub = sub
            if is_start_anchored:
                clean_sub = clean_sub[1:]
            if is_end_anchored:
                clean_sub = clean_sub[:-1]
            if is_start_anchored and is_end_anchored:
                self._os_match_compiled.append(
                    ("_exact_match", clean_sub, is_negated))
            elif is_start_anchored:
                self._os_match_compiled.append(
                    ("_starts_with", clean_sub, is_negated))
            elif is_end_anchored:
                self._os_match_compiled.append(
                    ("_ends_with", clean_sub, is_negated))
            else:
                self._os_match_compiled.append(
                    ("_substring_search", clean_sub, is_negated))

    def os_match(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """
        Emulates OSMatch_Execute (sregex).
        Returns a boolean and a list of (start, end) tuples for matches.
        """
        text_lower = text.lower()
        match_found = False
        match_spans: list[tuple[int, int]] = []

        try:
            self._os_match_compile(self._raw_pattern)
        except (ValueError, TypeError):
            return False, []

        is_negated_rule = self._os_match_compiled[0][2] if self._os_match_compiled else False

        for strategy, pattern_arg, _ in self._os_match_compiled:
            pattern_lower = pattern_arg.lower()
            start, end = -1, -1

            if strategy == "_exact_match" and text_lower == pattern_lower:
                start, end = 0, len(text)
            elif strategy == "_starts_with" and text_lower.startswith(pattern_lower):
                start, end = 0, len(pattern_arg)
            elif strategy == "_ends_with" and text_lower.endswith(pattern_lower):
                start = len(text) - len(pattern_arg)
                end = len(text)
            elif strategy == "_substring_search":
                try:
                    start = text_lower.index(pattern_lower)
                    end = start + len(pattern_arg)
                except ValueError:
                    continue

            if start != -1:
                match_found = True
                match_spans.append((start, end))
                break

        final_match = not match_found if is_negated_rule else match_found
        return final_match, match_spans if final_match else []

    def pcre2_regex(self, text: str) -> tuple[bool, list[tuple[int, int]]]:

        pcre2_pattern: pcre2.Pattern

        try:
            pcre2_pattern = pcre2.compile(self._raw_pattern, flags=pcre2.U, jit=True)
            pcre2_pattern.jit_compile()
        except (ValueError, TypeError):
            return False, []

        match = pcre2_pattern.search(text)
        if not match:
            return False, []

        self._last_os_regex_substrings = list(match.groups())
        return True, [match.span()]
