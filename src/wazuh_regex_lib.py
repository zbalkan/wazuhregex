import re
import sys

class WazuhRegex:
    """
    A Python class that emulates the interfaces and logic of Wazuh's
    os_regex.h library, including both the OSRegex and OSMatch engines.
    """

    def __init__(self, pattern: str):
        """
        Initializes the class and immediately "compiles" the pattern for
        both engines, storing the result internally. This mimics the startup
        phase of the wazuh-regex tool.

        Args:
            pattern (str): The regex pattern to be used.
        """
        if not isinstance(pattern, str):
            raise TypeError("Pattern must be a string.")

        self._raw_pattern = pattern
        self._os_regex_compiled = None
        self._os_match_compiled = None
        self._last_os_regex_substrings = []

        # Immediately compile both patterns upon instantiation.
        self._os_regex_compile(self._raw_pattern)
        self._os_match_compile(self._raw_pattern)

    # --- OSRegex Engine Emulation ---

    def _os_regex_compile(self, pattern: str):
        """
        Internal method to emulate OSRegex_Compile.
        It transforms the Wazuh-specific regex syntax into standard Python regex.
        """
        # Wazuh's OSRegex is case-insensitive by default.
        translation = pattern
        # 1. Handle character classes
        translation = translation.replace(r'\d', r'[0-9]')
        translation = translation.replace(r'\w', r'[a-zA-Z0-9_@\-]')
        translation = translation.replace(r'\s', r' ')
        translation = translation.replace(r'\p', r'[-()*+,.\\:;<=>?\[\]!"\'#$%&|{}]')
        # Note: \. in OSRegex means "anything", but in Python '.' means "anything".
        # A literal dot in OSRegex is '.', which is the same in Python if not special.
        # We'll assume '\.' means 'any character' as per the docs.
        translation = translation.replace(r'\.', r'.')

        # 2. Handle special characters (anchors are the same in Python)
        # The '|' (OR) is also the same.

        # 3. Limitations: OSRegex doesn't support quantifiers on literals (e.g., 'a+').
        # Python's `re` is more powerful, so it will naturally support more than the
        # original, but we are aiming for functional equivalence on valid patterns.

        try:
            # Compile with the IGNORECASE flag to match OSRegex's default behavior.
            self._os_regex_compiled = re.compile(translation, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Pattern '{pattern}' does not compile with OSRegex emulation: {e}")

    def os_regex_execute(self, text: str) -> bool:
        """
        Emulates OSRegex_Execute using the pre-compiled pattern.
        If a match is found, it populates the internal substring list.

        Args:
            text (str): The input string to test.

        Returns:
            bool: True if a match is found, False otherwise.
        """
        self._last_os_regex_substrings = []
        # Use search() to find a match anywhere in the string, which is the
        # default behavior unless anchored with '^'.
        match = self._os_regex_compiled.search(text)
        if match:
            # OSRegex returns all captured groups.
            self._last_os_regex_substrings = list(match.groups())
            return True
        return False

    def get_substrings(self) -> list:
        """
        Returns the substrings captured by the last successful
        os_regex_execute call.
        """
        return self._last_os_regex_substrings

    # --- OSMatch (sregex) Engine Emulation ---

    def _os_match_compile(self, pattern: str):
        """
        Internal method to emulate OSMatch_Compile.
        It prepares a list of specialized functions based on the pattern's structure.
        """
        self._os_match_compiled = []
        
        # Handle negation at the pattern level
        is_negated = False
        if pattern.startswith('!'):
            is_negated = True
            pattern = pattern[1:]

        sub_patterns = pattern.split('|')

        for sub in sub_patterns:
            # This is the "strategy selection" from the C code
            is_start_anchored = sub.startswith('^')
            is_end_anchored = sub.endswith('$')
            
            clean_sub = sub
            if is_start_anchored:
                clean_sub = clean_sub[1:]
            if is_end_anchored:
                clean_sub = clean_sub[:-1]

            # Store a tuple: (function, pattern_argument, negation_flag)
            if is_start_anchored and is_end_anchored:
                self._os_match_compiled.append(("_exact_match", clean_sub, is_negated))
            elif is_start_anchored:
                self._os_match_compiled.append(("_starts_with", clean_sub, is_negated))
            elif is_end_anchored:
                self._os_match_compiled.append(("_ends_with", clean_sub, is_negated))
            else:
                self._os_match_compiled.append(("_substring_search", clean_sub, is_negated))

    def os_match_execute(self, text: str) -> bool:
        """
        Emulates OSMatch_Execute by dispatching to the specialized functions
        chosen during compilation.

        Args:
            text (str): The input string to test.

        Returns:
            bool: True if a match is found, False otherwise.
        """
        text_lower = text.lower()
        match_found = False
        # Loop through the "OR" strategies
        for strategy, pattern_arg, is_negated in self._os_match_compiled:
            pattern_lower = pattern_arg.lower()
            
            # Dispatch to the chosen internal function
            if strategy == "_exact_match" and text_lower == pattern_lower:
                match_found = True
                break
            elif strategy == "_starts_with" and text_lower.startswith(pattern_lower):
                match_found = True
                break
            elif strategy == "_ends_with" and text_lower.endswith(pattern_lower):
                match_found = True
                break
            elif strategy == "_substring_search" and pattern_lower in text_lower:
                match_found = True
                break
        
        # Final logic includes negation
        return match_found if not is_negated else not match_found

# --- One-Shot Wrapper Functions ---

def os_regex(pattern: str, text: str) -> bool:
    """
    A stateless, one-shot function emulating OS_Regex.
    It creates a temporary instance and executes the match.
    """
    try:
        regex_tool = WazuhRegex(pattern)
        return regex_tool.os_regex_execute(text)
    except (ValueError, TypeError):
        return False

def os_match2(pattern: str, text: str) -> bool:
    """
    A stateless, one-shot function emulating OS_Match2.
    """
    try:
        regex_tool = WazuhRegex(pattern)
        return regex_tool.os_match_execute(text)
    except (ValueError, TypeError):
        return False
