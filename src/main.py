#!/usr/bin/env python3

# Save the above class and functions in a file named `wazuh_regex_lib.py`
# and then run this script.
import sys
from wazuh_regex_lib import WazuhRegex, os_match2, os_regex


def main():
    """
    A Python implementation of the wazuh-regex CLI tool.
    """
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        print(f"\nUsage: {sys.argv[0]} '<PATTERN>'")
        sys.exit(1)

    pattern = sys.argv[1]

    try:
        # This single line emulates the entire compilation phase of the C tool.
        # It instantiates the class, which automatically calls the internal
        # _os_regex_compile and _os_match_compile methods.
        wazuh_tool = WazuhRegex(pattern)
        print("Python wazuh-regex tool initialized. Ready for input.", file=sys.stderr)
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # This loop emulates the main `while` loop of the C tool.
    for line in sys.stdin:
        text = line.strip()  # Remove newline, just like the C code

        # 1. Test OSRegex_Execute
        if wazuh_tool.os_regex_execute(text):
            print(f"+OSRegex_Execute: {text}")
            substrings = wazuh_tool.get_substrings()
            for sub in substrings:
                print(f" -Substring: {sub}")

        # 2. Test OS_Regex (stateless wrapper)
        if os_regex(pattern, text):
            print(f"+OS_Regex       : {text}")

        # 3. Test OSMatch_Execute
        if wazuh_tool.os_match_execute(text):
            print(f"+OSMatch_Execute: {text}")

        # 4. Test OS_Match2 (stateless wrapper)
        if os_match2(pattern, text):
            print(f"+OS_Match2      : {text}")


if __name__ == "__main__":
    main()
