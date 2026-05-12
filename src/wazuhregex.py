#!/usr/bin/env python3

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wazuh_regex_lib import WazuhRegex


def main() -> None:
    console = Console()

    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        console.print(f"\n[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        sys.exit(1)

    pattern = sys.argv[1]

    # Show pattern info
    console.print(Panel(f"[bold cyan]Pattern:[/bold cyan] {pattern}",
                        title="Wazuh Regex Tester"))

    wazuh_tool = WazuhRegex(pattern)
    console.print(
        "[green]✓[/green] Pattern compiled successfully\n", style="dim")

    for line in sys.stdin:
        text = line.strip().strip('\n')
        if not text:
            continue

        # Create results table
        table = Table(title=f"Testing: {text}",
                      show_header=True, header_style="bold")
        table.add_column("Engine", style="cyan", width=15)
        table.add_column("Result", justify="center", width=10)
        table.add_column("Match Span", style="yellow")
        table.add_column("Captured Groups", style="green")

        # Test OS_Regex
        is_match, spans = wazuh_tool.os_regex(text)
        if is_match:
            substrings = wazuh_tool.get_substrings()
            span_str = str(spans[0]) if spans else "—"
            groups_str = ", ".join(
                f'"{s}"' for s in substrings) if substrings else "—"
            table.add_row("OS_Regex", "✅ Match", span_str, groups_str)
        else:
            table.add_row("OS_Regex", "❌ No Match", "—", "—")

        # Test OS_Match
        is_match, spans = wazuh_tool.os_match(text)
        span_str = str(spans[0]) if spans else "—"
        if is_match:
            table.add_row("OS_Match", "✅ Match", span_str, "N/A")
        else:
            table.add_row("OS_Match", "❌ No Match", "—", "N/A")

        # Test PCRE2
        is_match, spans = wazuh_tool.pcre2_regex(text)
        if is_match:
            substrings = wazuh_tool.get_substrings()
            span_str = str(spans[0]) if spans else "—"
            groups_str = ", ".join(
                f'"{s}"' for s in substrings) if substrings else "—"
            table.add_row("PCRE2", "✅ Match", span_str, groups_str)
        else:
            table.add_row("PCRE2", "❌ No Match", "—", "—")

        console.print(table)
        console.print()  # Blank line between tests


if __name__ == "__main__":
    main()
