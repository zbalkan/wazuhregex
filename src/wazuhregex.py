#!/usr/bin/env python3

import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

if __package__:
    from .wazuh_regex_lib import WazuhRegex
else:
    from wazuh_regex_lib import WazuhRegex


def main() -> None:
    console = Console()

    if len(sys.argv) != 2:
        console.print(f"\n[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        sys.exit(1)
    if sys.argv[1] in ('-h', '--help'):
        console.print(f"\n[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        return

    pattern = sys.argv[1]

    # Show pattern info
    console.print(Panel(f"[bold cyan]Pattern:[/bold cyan] {escape(pattern)}",
                        title="Wazuh Regex Tester"))

    try:
        wazuh_tool = WazuhRegex(pattern)
    except ValueError as error:
        console.print(f"[red]Invalid pattern:[/red] {escape(str(error))}")
        sys.exit(2)
    console.print("[green]✓[/green] Pattern loaded\n", style="dim")
    validation_errors = wazuh_tool.validation_errors()
    for engine, error in validation_errors.items():
        console.print(
            f"[yellow]⚠ {engine}:[/yellow] {escape(error)}"
        )
    if validation_errors:
        console.print()

    for line in sys.stdin:
        # Remove only the stream delimiter. Leading/trailing spaces and empty
        # records are valid input to the Wazuh regex engines.
        text = line.rstrip('\r\n')

        # Create results table
        table = Table(title=f"Testing: {escape(text)}",
                      show_header=True, header_style="bold")
        table.add_column("Engine", style="cyan", width=15)
        table.add_column("Result", justify="center", width=10)
        table.add_column("Match Span", style="yellow")
        table.add_column("Captured Groups", style="green")

        # Test OS_Regex
        is_match, spans = wazuh_tool.os_regex(text)
        if "OS_Regex" in validation_errors:
            table.add_row("OS_Regex", "⚠ Invalid", "—", "—")
        elif is_match:
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
        if "PCRE2" in validation_errors:
            table.add_row("PCRE2", "⚠ Invalid", "—", "—")
        elif is_match:
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
    try:
        main()
    except KeyboardInterrupt:
        pass
