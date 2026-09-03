from typing import Final

import pcre2


class WazuhRegex:
    """
    A Python class that emulates the logic of Wazuh's os_regex.h,
    os_match.h, and PCRE2 libraries.

    This class provides three independent methods, each acting as a self-contained
    engine to test a pattern against a specific Wazuh regex flavor.
    """

    _TRANSLATIONS: Final[dict[str, str]] = {
        r'\\': r'\\',
        r'\D': r'[^0-9]',
        r'\W': r'[^a-zA-Z0-9_@\-]',
        r'\S': r'[^ ]',
        r'\d': r'[0-9]',
        r'\w': r'[a-zA-Z0-9_@\-]',
        r'\s': r'[ ]',
        r'\t': r'\t',
        # Wazuh's punctuation class does not contain backslash.
        r'\p': r'''[\-()*+,.:;<=>?\[\]!"'#$%&|{}]''',
        # OS_Regex uses an escaped dot for its any-character operator. Wazuh's
        # character map accepts every byte, including newline, so use a scoped
        # DOTALL group instead of PCRE2's default dot behaviour.
        r'\.': r'(?s:.)',
    }
    _OSREGEX_LITERAL_ESCAPES: Final[frozenset[str]] = frozenset("()$|<")

    # These characters have no special meaning in OS_Regex, but do have one
    # in the PCRE2 backend used for the emulation. Escape them when they occur
    # unescaped so that the backend cannot accidentally accept PCRE syntax.
    _PCRE_ONLY_METACHARACTERS: Final[frozenset[str]] = frozenset('.?[]{}')
    _PCRE_METACHARACTERS: Final[frozenset[str]] = frozenset(r'\\.^$|?*+()[]{}')
    _ASCII_LOWERCASE_TRANSLATION: Final[dict[int, int]] = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
    )
    _HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")

    def __init__(self, pattern: str) -> None:
        if not isinstance(pattern, str):
            raise TypeError("pattern must be a string")
        self._raw_pattern: str = pattern
        self._last_substrings: list[str] = []

    def _os_regex_compile(self) -> pcre2.Pattern:
        if self._has_group_alternation(self._raw_pattern):
            raise ValueError("Invalid for OS_Regex: Alternation '|' in group.")
        if self._has_invalid_group_nesting(self._raw_pattern):
            raise ValueError("Invalid for OS_Regex: Nested or unbalanced parentheses.")

        translation_parts: list[str] = []
        index = 0
        while index < len(self._raw_pattern):
            token = self._raw_pattern[index:index + 2]
            replacement = self._TRANSLATIONS.get(token)
            if replacement is None:
                character = self._raw_pattern[index]
                if character in "*+":
                    raise ValueError(
                        "Invalid for OS_Regex: Modifier on bare character."
                    )
                if character == '\\':
                    if len(token) != 2:
                        raise ValueError("Invalid for OS_Regex: Trailing backslash.")
                    quoted = token[1]
                    if quoted not in self._OSREGEX_LITERAL_ESCAPES:
                        raise ValueError(
                            f"Invalid for OS_Regex: Unsupported escape \\{quoted}."
                        )
                    if quoted in self._PCRE_METACHARACTERS:
                        translation_parts.append('\\')
                    translation_parts.append(quoted)
                    index += 2
                    continue
                if character in self._PCRE_ONLY_METACHARACTERS:
                    translation_parts.append('\\')
                translation_parts.append(character)
                index += 1
            else:
                translation_parts.append(replacement)
                index += 2
                if index < len(self._raw_pattern) and self._raw_pattern[index] in "*+":
                    translation_parts.append(self._raw_pattern[index])
                    index += 1

        translation = ''.join(translation_parts).translate(
            self._ASCII_LOWERCASE_TRANSLATION
        )
        try:
            return pcre2.compile(translation, flags=pcre2.ASCII, jit=True)
        except pcre2.PatternError as error:
            raise ValueError(f"Invalid for OS_Regex: {error}") from error

    @staticmethod
    def _has_group_alternation(pattern: str) -> bool:
        """Return whether an unescaped alternation occurs inside a group."""
        group_depth = 0
        escaped = False
        for character in pattern:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == '(':
                group_depth += 1
            elif character == ')':
                group_depth = max(0, group_depth - 1)
            elif character == '|' and group_depth:
                return True
        return False

    @staticmethod
    def _has_invalid_group_nesting(pattern: str) -> bool:
        """Wazuh OS_Regex allows one parenthesis level and requires balance."""
        group_depth = 0
        escaped = False
        for character in pattern:
            if escaped:
                escaped = False
                continue
            if character == '\\':
                escaped = True
                continue
            if character == '(':
                group_depth += 1
                if group_depth > 1:
                    return True
            elif character == ')':
                group_depth -= 1
                if group_depth < 0:
                    return True
        return group_depth != 0

    @classmethod
    def _normalize_wazuh_pcre2(cls, pattern: str) -> str:
        r"""Normalize Python-wrapper differences from Wazuh 4.x PCRE2 defaults.

        Wazuh calls pcre2_compile() with option bits 0. pcre2.py forces
        PCRE2_ALT_BSUX, UTF, and UCP for Python strings. UCP is disabled at
        compile time separately; this function restores escape spellings that
        ALT_BSUX changes while retaining the string API.
        """
        parts: list[str] = []
        index = 0
        while index < len(pattern):
            if pattern[index] != '\\':
                parts.append(pattern[index])
                index += 1
                continue

            if index + 1 >= len(pattern):
                parts.append('\\')
                index += 1
                continue

            escaped = pattern[index + 1]
            if escaped == '\\':
                parts.append('\\\\')
                index += 2
                continue

            # PCRE2 without ALT_BSUX rejects \u and \U. The Python wrapper
            # enables them, so reject them before compilation.
            if escaped in {'u', 'U'}:
                raise ValueError(
                    f"Invalid for Wazuh PCRE2: unsupported escape \\{escaped}."
                )

            if escaped == 'x':
                if index + 2 < len(pattern) and pattern[index + 2] == '{':
                    end = pattern.find('}', index + 3)
                    if end < 0:
                        parts.append(pattern[index:])
                        break
                    digits = pattern[index + 3:end]
                    if not digits or any(ch not in cls._HEX_DIGITS for ch in digits):
                        parts.append(pattern[index:end + 1])
                        index = end + 1
                        continue
                    value = int(digits, 16)
                    if value > 0xFF:
                        raise ValueError(
                            "Invalid for Wazuh PCRE2: braced hex value exceeds 8-bit range."
                        )
                    parts.append(f"\\x{value:02x}")
                    index = end + 1
                    continue

                # With Wazuh's normal PCRE2 options, \x consumes zero, one, or
                # two hexadecimal digits. ALT_BSUX requires exactly two.
                first = pattern[index + 2] if index + 2 < len(pattern) else ''
                second = pattern[index + 3] if index + 3 < len(pattern) else ''
                if first in cls._HEX_DIGITS and second in cls._HEX_DIGITS:
                    parts.append(pattern[index:index + 4])
                    index += 4
                elif first in cls._HEX_DIGITS:
                    parts.append(f"\\x0{first}")
                    index += 3
                else:
                    parts.append(r"\x00")
                    index += 2
                continue

            # pcre2.py always sets PCRE2_NEVER_BACKSLASH_C. In Wazuh's
            # non-UTF 8-bit default, \C means one code unit; for the string API
            # the closest equivalent is one character including newline.
            if escaped == 'C':
                parts.append(r"(?s:.)")
                index += 2
                continue

            parts.append(pattern[index:index + 2])
            index += 2

        return ''.join(parts)

    def _pcre2_compile(self) -> pcre2.Pattern:
        pattern = self._normalize_wazuh_pcre2(self._raw_pattern)
        try:
            # Wazuh 4.x invokes pcre2_compile() with option bits 0. The Python
            # binding turns on UCP for str patterns; ASCII disables that wrapper
            # default so \d/\w/\s retain PCRE2's default ASCII semantics.
            return pcre2.compile(pattern, flags=pcre2.ASCII, jit=True)
        except pcre2.PatternError as error:
            raise ValueError(f"Invalid for PCRE2: {error}") from error

    @staticmethod
    def _validate_text(text: str) -> None:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

    def os_regex(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """Emulates the OSRegex_Execute engine."""
        self._last_substrings = []
        self._validate_text(text)
        if self._raw_pattern in ('$', '^$'):
            return (True, [(0, 0)]) if text == "" else (False, [])

        try:
            compiled = self._os_regex_compile()
            matches = list(compiled.finditer(
                text.translate(self._ASCII_LOWERCASE_TRANSLATION)
            ))
            if not matches:
                return False, []

            spans: list[tuple[int, int]] = []
            substrings: list[str] = []
            for match in matches:
                spans.append(match.span())
                groups: list[str] = [group for group in match.groups() if group is not None]
                if groups:
                    substrings.extend(groups)
                elif match.group(0):
                    substrings.append(str(match.group(0)))

            self._last_substrings = substrings
            return True, spans
        except ValueError:
            return False, []

    def get_substrings(self) -> list[str]:
        """Returns substrings captured by the last successful os_regex or pcre2_regex call."""
        return self._last_substrings.copy()

    def validation_errors(self) -> dict[str, str]:
        """Return compile errors for engines that compile regular expressions."""
        errors: dict[str, str] = {}
        try:
            self._os_regex_compile()
        except ValueError as error:
            errors["OS_Regex"] = str(error)

        try:
            self._pcre2_compile()
        except ValueError as error:
            errors["PCRE2"] = str(error)

        return errors

    def _os_match_compile(self) -> list[tuple[str, str, bool]]:
        os_match_compiled: list[tuple[str, str, bool]] = []
        pattern = self._raw_pattern
        is_negated = pattern.startswith('!')
        if is_negated:
            pattern = pattern[1:]

        for sub in pattern.split('|'):
            is_start, is_end = sub.startswith('^'), sub.endswith('$')
            start_index = 1 if is_start else 0
            end_index = -1 if is_end else None
            clean_sub = sub[start_index:end_index]
            if is_start and is_end:
                os_match_compiled.append(("_exact", clean_sub, is_negated))
            elif is_start:
                os_match_compiled.append(("_startswith", clean_sub, is_negated))
            elif is_end:
                os_match_compiled.append(("_endswith", clean_sub, is_negated))
            else:
                os_match_compiled.append(("_substring", clean_sub, is_negated))
        return os_match_compiled

    def os_match(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """Emulates the OSMatch_Execute (sregex) engine."""
        self._last_substrings = []
        self._validate_text(text)
        text_lower = text.translate(self._ASCII_LOWERCASE_TRANSLATION)
        match_found = False
        match_spans: list[tuple[int, int]] = []

        os_match_compiled = self._os_match_compile()
        is_negated_rule = os_match_compiled[0][2] if os_match_compiled else False
        for strategy, pattern_arg, _ in os_match_compiled:
            pattern_lower = pattern_arg.translate(
                self._ASCII_LOWERCASE_TRANSLATION
            )
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
        """Executes the pattern using Wazuh 4.x PCRE2 defaults."""
        self._last_substrings = []
        self._validate_text(text)
        try:
            pcre2_pattern = self._pcre2_compile()
        except ValueError:
            return False, []

        matches = list(pcre2_pattern.finditer(text))
        if not matches:
            return False, []

        spans: list[tuple[int, int]] = []
        substrings: list[str] = []
        for match in matches:
            spans.append(match.span())
            groups: list[str] = [group for group in match.groups() if group is not None]
            if groups:
                substrings.extend(groups)
            elif match.group(0):
                substrings.append(str(match.group(0)))

        self._last_substrings = substrings
        return True, spans
