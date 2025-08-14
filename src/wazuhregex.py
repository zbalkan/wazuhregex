#!/usr/bin/env python3

import sys

from highlighter import Highlighter
from wazuh_regex_lib import WazuhRegex, os_match2, os_regex


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        print(f"\nUsage: {sys.argv[0]} '<PATTERN>'")
        sys.exit(1)

    pattern = sys.argv[1]

    # --- Application Setup ---
    # The application decides which color to use.
    highlighter = Highlighter(highlight_color=Highlighter.RED)

    try:
        wazuh_tool = WazuhRegex(pattern)
        print("wazuhregex tool initialized. Ready for input.", file=sys.stderr)
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    for line in sys.stdin:
        text = line.strip()

        # 1. Test OSRegex_Execute
        is_match, spans = wazuh_tool.os_regex_execute(text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(
                f"\n\033[1m+OSRegex_Execute:\033[0m\n{highlighted_string}")
            substrings = wazuh_tool.get_substrings()
            for sub in substrings:
                print(f" -Substring:\n{sub}")

        # 2. Test OS_Regex (stateless wrapper)
        is_match, spans = os_regex(pattern, text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(f"\n\033[1m+OS_Regex       :\033[0m\n{highlighted_string}")

        # 3. Test OSMatch_Execute
        is_match, spans = wazuh_tool.os_match_execute(text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(f"\n\033[1m+OSMatch_Execute:\033[0m\n{highlighted_string}")

        # 4. Test OS_Match2 (stateless wrapper)
        is_match, spans = os_match2(pattern, text)
        if is_match:
            highlighted_string = highlighter.apply(text, spans)
            print(f"\n\033[1m+OS_Match2      :\033[0m\n{highlighted_string}")


if __name__ == "__main__":
    main()
