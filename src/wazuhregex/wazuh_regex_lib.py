import re
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
        # Patterns are immutable for the lifetime of this object. Cache every
        # compiled representation (and compile failure) after its first use so
        # repeated line evaluation does not pay O(pattern_length) setup again.
        self._osregex_compiled: pcre2.Pattern | None = None
        self._osregex_compile_error: str | None = None
        self._pcre2_compiled: pcre2.Pattern | None = None
        self._pcre2_compile_error: str | None = None
        self._osmatch_compiled: tuple[tuple[str, str, bool], ...] | None = None

    @staticmethod
    def _validate_osregex_groups(pattern: str) -> None:
        """Validate OS_Regex grouping in one linear scan.

        Wazuh allows one parenthesis level, rejects alternation inside a group,
        and requires balanced parentheses. Alternation errors retain precedence
        over nesting errors to match the previous diagnostics.
        """
        group_depth = 0
        escaped = False
        has_group_alternation = False
        has_invalid_nesting = False

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
                    has_invalid_nesting = True
            elif character == ')':
                group_depth -= 1
                if group_depth < 0:
                    has_invalid_nesting = True
                    group_depth = 0
            elif character == '|' and group_depth:
                has_group_alternation = True

        if group_depth != 0:
            has_invalid_nesting = True
        if has_group_alternation:
            raise ValueError("Invalid for OS_Regex: Alternation '|' in group.")
        if has_invalid_nesting:
            raise ValueError("Invalid for OS_Regex: Nested or unbalanced parentheses.")

    def _os_regex_compile(self) -> pcre2.Pattern:
        if self._osregex_compiled is not None:
            return self._osregex_compiled
        if self._osregex_compile_error is not None:
            raise ValueError(self._osregex_compile_error)

        try:
            self._validate_osregex_groups(self._raw_pattern)

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
                compiled = pcre2.compile(translation, flags=pcre2.ASCII, jit=True)
            except pcre2.PatternError as error:
                raise ValueError(f"Invalid for OS_Regex: {error}") from error
        except ValueError as error:
            self._osregex_compile_error = str(error)
            raise

        self._osregex_compiled = compiled
        return compiled

    @classmethod
    def _normalize_wazuh_pcre2(cls, pattern: str) -> str:
        r"""Normalize Python-wrapper differences from Wazuh 4.x PCRE2 defaults.

        Wazuh calls pcre2_compile() with option bits 0. pcre2.py forces
        PCRE2_ALT_BSUX, UTF, and UCP for Python strings. UCP is disabled at
        compile time separately; this function restores escape spellings that
        ALT_BSUX changes while retaining the string API.
        """
        parts: list[str] = []
        utf_enabled = pattern.startswith(("(*UTF)", "(*UTF8)"))
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
                    if value > 0xFF and not utf_enabled:
                        raise ValueError(
                            "Invalid for Wazuh PCRE2: braced hex value exceeds 8-bit range."
                        )
                    if utf_enabled:
                        parts.append(pattern[index:end + 1])
                    else:
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
        if self._pcre2_compiled is not None:
            return self._pcre2_compiled
        if self._pcre2_compile_error is not None:
            raise ValueError(self._pcre2_compile_error)

        try:
            pattern = self._normalize_wazuh_pcre2(self._raw_pattern)
            # pcre2.py forces ALT_BSUX, under which its backend does not
            # recognize PCRE2's braced hex spelling. Keep that spelling in the
            # normalization contract, but pass the equivalent code point to
            # the wrapper when the pattern explicitly selected UTF mode.
            if pattern.startswith(("(*UTF)", "(*UTF8)")):
                parts: list[str] = []
                index = 0
                quoted = False
                braced_hex = re.compile(r"x\{([0-9a-fA-F]+)\}")
                while index < len(pattern):
                    if pattern[index] != "\\":
                        parts.append(pattern[index])
                        index += 1
                        continue

                    end = index
                    while end < len(pattern) and pattern[end] == "\\":
                        end += 1
                    slashes = pattern[index:end]
                    marker = pattern[end:end + 1]
                    parts.append(slashes)

                    if len(slashes) % 2 and marker == ("E" if quoted else "Q"):
                        parts.append(marker)
                        quoted = not quoted
                        index = end + 1
                        continue

                    match = (
                        None
                        if quoted or len(slashes) % 2 == 0
                        else braced_hex.match(pattern, end)
                    )
                    if match is None:
                        index = end
                        continue

                    value = int(match.group(1), 16)
                    if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                        raise ValueError(
                            "Invalid for Wazuh PCRE2: braced hex value is not a Unicode code point."
                        )
                    parts[-1] = slashes[:-1]
                    parts.append(
                        f"\\u{value:04x}" if value <= 0xFFFF else f"\\U{value:08x}"
                    )
                    index = match.end()
                pattern = "".join(parts)
            try:
                # Wazuh 4.x invokes pcre2_compile() with option bits 0. The Python
                # binding turns on UCP for str patterns; ASCII disables that wrapper
                # default so \d/\w/\s retain PCRE2's default ASCII semantics.
                compiled = pcre2.compile(pattern, flags=pcre2.ASCII, jit=True)
            except pcre2.PatternError as error:
                raise ValueError(f"Invalid for PCRE2: {error}") from error
        except ValueError as error:
            self._pcre2_compile_error = str(error)
            raise

        self._pcre2_compiled = compiled
        return compiled

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
        except ValueError:
            return False, []

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

    def _os_match_compile(self) -> tuple[tuple[str, str, bool], ...]:
        if self._osmatch_compiled is not None:
            return self._osmatch_compiled

        os_match_compiled: list[tuple[str, str, bool]] = []
        pattern = self._raw_pattern
        is_negated = pattern.startswith('!')
        if is_negated:
            pattern = pattern[1:]

        for sub in pattern.split('|'):
            is_start, is_end = sub.startswith('^'), sub.endswith('$')
            start_index = 1 if is_start else 0
            end_index = -1 if is_end else None
            clean_sub = sub[start_index:end_index].translate(
                self._ASCII_LOWERCASE_TRANSLATION
            )
            if is_start and is_end:
                os_match_compiled.append(("_exact", clean_sub, is_negated))
            elif is_start:
                os_match_compiled.append(("_startswith", clean_sub, is_negated))
            elif is_end:
                os_match_compiled.append(("_endswith", clean_sub, is_negated))
            else:
                os_match_compiled.append(("_substring", clean_sub, is_negated))

        self._osmatch_compiled = tuple(os_match_compiled)
        return self._osmatch_compiled

    def os_match(self, text: str) -> tuple[bool, list[tuple[int, int]]]:
        """Emulates the OSMatch_Execute (sregex) engine."""
        self._last_substrings = []
        self._validate_text(text)
        text_lower = text.translate(self._ASCII_LOWERCASE_TRANSLATION)

        os_match_compiled = self._os_match_compile()
        is_negated_rule = os_match_compiled[0][2] if os_match_compiled else False
        for strategy, pattern_lower, _ in os_match_compiled:
            start, end = -1, -1
            if strategy == "_exact" and text_lower == pattern_lower:
                start, end = 0, len(text)
            elif strategy == "_startswith" and text_lower.startswith(pattern_lower):
                start, end = 0, len(pattern_lower)
            elif strategy == "_endswith" and text_lower.endswith(pattern_lower):
                start = len(text) - len(pattern_lower)
                end = len(text)
            elif strategy == "_substring":
                start = text_lower.find(pattern_lower)
                if start != -1:
                    end = start + len(pattern_lower)

            if start != -1:
                final_match = not is_negated_rule
                return final_match, [(start, end)] if final_match else []

        return is_negated_rule, []

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
