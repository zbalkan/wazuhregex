#!/usr/bin/env python3

import os
import sys

from highlighter import Highlighter
from wazuh_regex_lib import WazuhRegex


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        print(f"\nUsage: {sys.argv[0]} '<PATTERN>'")
        sys.exit(1)

    pattern = sys.argv[1]
    no_color: bool = (os.getenv("NO_COLOR") is not None)
    highlighter = Highlighter(
        highlight_color=Highlighter.RED, no_color=no_color)

    try:
        # The wazuh_tool object holds the compiled state for both engines.
        wazuh_tool = WazuhRegex(pattern)
        print("Pattern compiled successfully. Ready for input.", file=sys.stderr)
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    for line in sys.stdin:
        text = line.strip()
        print("-" * 40)  # Add a separator for clarity between inputs

        # --- Test 1: The OS_Regex Engine ---
        # This is the main, powerful regex engine that captures substrings.
        is_match, spans = wazuh_tool.os_regex(text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(f"\n\033[1m✅ OSRegex Match:\033[0m\n{highlighted_string}")
            substrings = wazuh_tool.get_substrings()
            if substrings:
                for sub in substrings:
                    print(f"  - Substring: {sub}")
        else:
            print("\n\033[1m❌ OSRegex No Match\033[0m")

        # --- Test 2: The OS_Match (sregex) Engine ---
        # This is the fast, simple string matching engine.
        is_match, spans = wazuh_tool.os_match(text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(
                f"\n\033[1m✅ OSMatch (sregex) Match:\033[0m\n{highlighted_string}")
        else:
            print("\n\033[1m❌ OSMatch (sregex) No Match\033[0m")


if __name__ == "__main__":
    main()
