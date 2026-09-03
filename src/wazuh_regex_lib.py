from typing import Final

import pcre2


class WazuhRegex:
    """
    A Python class that emulates the logic of Wazuh's os_regex.h,
    os_match.h, and PCRE2 libraries.

    This class provides three independent methods, each acting as a self-contained
    engine to test a pattern against a specific Wazuh regex flavor.
    """

    _INVALID_GROUP_ALTERNATION: Final[pcre2.Pattern] = pcre2.compile(r'\([^)]*\|[^)]*\)')
    _INVALID_MODIFIER_USE: Final[pcre2.Pattern] = pcre2.compile(r'(?<!\\[wdspWDSP\.])[*+]')

    _TRANSLATIONS: Final[dict[str, str]] = {
        r'\\': r'\\',
        r'\D': r'[^0-9]',
        r'\W': r'[^a-zA-Z0-9_@\-]',
        r'\S': r'[^ ]',
        r'\d': r'[0-9]',
        r'\w': r'[a-zA-Z0-9_@\-]',
        r'\s': r'[ ]',
        r'\t': r'\t',
        # Keep this character class self-contained. Running later string
        # replacements over it can corrupt its escaped characters.
        r'\p': r'''[\-()*+,.\\:;<=>?\[\]!"'#$%&|{}]''',
        # OS_Regex uses an escaped dot for its any-character operator.
        r'\.': r'.',
        r'[(': r'\[(',
        r')]': r')\]',
    }

    def __init__(self, pattern: str) -> None:
        self._raw_pattern: str = self._normalize_pattern(pattern)
        # This list is shared, so it must be cleared by each method.
        self._last_substrings: list[str] = []

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        if not pattern:
            return pattern

        if pattern[0] in ("'", '"'):
            if len(pattern) < 2 or pattern[-1] != pattern[0]:
                raise ValueError("Pattern quotes must start and end with the same quote character.")
            return pattern[1:-1]

        if pattern[-1] in ("'", '"'):
            raise ValueError("Pattern quotes must start and end with the same quote character.")

        return pattern

    def _os_regex_compile(self) -> pcre2.Pattern:
        if self._INVALID_GROUP_ALTERNATION.search(self._raw_pattern):
            raise ValueError("Invalid for OS_Regex: Alternation '|' in group.")
        if self._INVALID_MODIFIER_USE.search(self._raw_pattern):
            raise ValueError(
                "Invalid for OS_Regex: Modifier on bare character.")

        # Translate the original pattern in one pass. Sequential ``replace``
        # calls also rewrite text introduced by an earlier rule (notably the
        # escapes inside ``\p``), producing a subtly different expression.
        translation_parts: list[str] = []
        index = 0
        while index < len(self._raw_pattern):
            token = self._raw_pattern[index:index + 2]
            replacement = self._TRANSLATIONS.get(token)
            if replacement is None:
                translation_parts.append(self._raw_pattern[index])
                index += 1
            else:
                translation_parts.append(replacement)
                index += 2
        translation = ''.join(translation_parts)
        try:
            return pcre2.compile(translation, flags=pcre2.IGNORECASE, jit=True)
        except Exception as e:
            raise ValueError(f"Invalid for OS_Regex: {e}")

    def os_regex(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """Emulates the OSRegex_Execute engine."""
        self._last_substrings = []
        if self._raw_pattern in ('$', '^$', '^'):
            return (True, [(0, 0)]) if text == "" else (False, [])

        try:
            compiled = self._os_regex_compile()
            matches = list(compiled.finditer(text))
            if not matches:
                return False, []

            spans: list[tuple[int, int]] = []
            substrings: list[str] = []
            for match in matches:
                spans.append(match.span())
                groups = [group for group in match.groups() if group is not None]
                if groups:
                    substrings.extend(groups)
                else:
                    substrings.append(match.group(0))

            self._last_substrings = substrings
            return True, spans
        except ValueError:
            return False, []

    def get_substrings(self) -> list[str]:
        """Returns substrings captured by the last successful os_regex or pcre2_regex call."""
        return self._last_substrings

    def _os_match_compile(self) -> list[tuple[str, str, bool]]:
        os_match_compiled: list[tuple[str, str, bool]] = []
        pattern = self._raw_pattern
        is_negated = pattern.startswith('!')
        if is_negated:
            pattern = pattern[1:]

        for sub in pattern.split('|'):
            is_start, is_end = sub.startswith('^'), sub.endswith('$')
            clean_sub = sub.strip('^$')
            if is_start and is_end:
                os_match_compiled.append(("_exact", clean_sub, is_negated))
            elif is_start:
                os_match_compiled.append(
                    ("_startswith", clean_sub, is_negated))
            elif is_end:
                os_match_compiled.append(("_endswith", clean_sub, is_negated))
            else:
                os_match_compiled.append(("_substring", clean_sub, is_negated))
        return os_match_compiled

    def os_match(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """Emulates the OSMatch_Execute (sregex) engine."""
        self._last_substrings = []  # sregex does not capture substrings.
        text_lower = text.lower()
        match_found = False
        match_spans: list[tuple[int, int]] = []

        try:
            os_match_compiled = self._os_match_compile()
        except Exception:
            return False, []

        is_negated_rule = os_match_compiled[0][2] if os_match_compiled else False
        for strategy, pattern_arg, _ in os_match_compiled:
            pattern_lower = pattern_arg.lower()
            start, end = -1, -1
            if strategy == "_exact" and text_lower == pattern_lower:
                start, end = 0, len(text)
            elif strategy == "_startswith" and text_lower.startswith(pattern_lower):
                start, end = 0, len(pattern_arg)
            elif strategy == "_endswith" and text_lower.endswith(pattern_lower):
                start = len(text) - len(pattern_arg)
                end = len(text)
            elif strategy == "_substring":
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
        """Executes the pattern using the native PCRE2 engine."""
        self._last_substrings = []
        try:
            pcre2_pattern = pcre2.compile(self._raw_pattern, jit=True)
            matches = list(pcre2_pattern.finditer(text))
            if not matches:
                return False, []

            spans: list[tuple[int, int]] = []
            substrings: list[str] = []
            for match in matches:
                spans.append(match.span())
                groups = [group for group in match.groups() if group is not None]
                if groups:
                    substrings.extend(groups)
                else:
                    substrings.append(match.group(0))

            self._last_substrings = substrings
            return True, spans
        except Exception:
            return False, []
