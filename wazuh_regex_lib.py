# wazuh_regex_lib.py

import re


class WazuhRegex:
    """
    A Python class that emulates the logic of Wazuh's os_regex.h library.
    This library is responsible for matching logic ONLY and contains no
    display or coloring code.
    """

    def __init__(self, pattern: str) -> None:

        self._raw_pattern: str = pattern
        self._os_regex_compiled = None
        self._os_match_compiled: list[tuple[str, str, bool]] = []
        self._last_os_regex_substrings: list[str] = []

        self._os_regex_compile(self._raw_pattern)
        self._os_match_compile(self._raw_pattern)

    def _os_regex_compile(self, pattern: str) -> None:
        translation = pattern
        translation = translation.replace(r'\d', r'[0-9]')
        translation = translation.replace(r'\w', r'[a-zA-Z0-9_@\-]')
        translation = translation.replace(r'\s', r' ')
        translation = translation.replace(
            r'\p', r'[-()*+,.\\:;<=>?\[\]!"\'#$%&|{}]')
        translation = translation.replace(r'\.', r'.')
        try:
            self._os_regex_compiled = re.compile(translation, re.IGNORECASE)
        except re.error as e:
            raise ValueError(
                f"Pattern '{pattern}' does not compile with OSRegex emulation: {e}")

    def os_regex_execute(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """
        Emulates OSRegex_Execute.
        Returns a boolean and a list of (start, end) tuples for matches.
        """
        self._last_os_regex_substrings = []
        match = self._os_regex_compiled.search(text)  # type: ignore
        if not match:
            return False, []

        self._last_os_regex_substrings = list(match.groups())
        return True, [match.span()]  # Return the span of the full match

    def get_substrings(self) -> list[str]:
        return self._last_os_regex_substrings

    def _os_match_compile(self, pattern: str):
        self._os_match_compiled = []
        is_negated = False
        if pattern.startswith('!'):
            is_negated = True
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

    def os_match_execute(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """
        Emulates OSMatch_Execute.
        Returns a boolean and a list of (start, end) tuples for matches.
        """
        text_lower = text.lower()
        match_found = False
        match_spans: list[tuple[int, int]] = []

        for strategy, pattern_arg, is_negated in self._os_match_compiled:
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

        final_match: bool = match_found if not is_negated else not match_found  # type: ignore
        return final_match, match_spans if final_match else []

# --- One-Shot Wrapper Functions ---


def os_regex(pattern: str, text: str) -> tuple[bool, list[tuple[int, int]]]:
    try:
        regex_tool = WazuhRegex(pattern)
        return regex_tool.os_regex_execute(text)
    except (ValueError, TypeError):
        return False, []


def os_match2(pattern: str, text: str) -> tuple[bool, list[tuple[int, int]]]:
    try:
        regex_tool = WazuhRegex(pattern)
        return regex_tool.os_match_execute(text)
    except (ValueError, TypeError):
        return False, []
