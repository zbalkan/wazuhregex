#!/usr/bin/env python3

import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

if __package__:
    from .compare import Engine, RegexComparer
    from .wazuh_regex_lib import WazuhRegex
else:
    from compare import Engine, RegexComparer
    from wazuh_regex_lib import WazuhRegex


def _remove_line_delimiter(line: str) -> str:
    """Remove one newline delimiter without discarding record content."""
    if line.endswith("\n"):
        line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
    return line


def _format_substrings(substrings: list[str]) -> str:
    """Format captured values as literal Rich markup-safe text."""
    return ", ".join(f'"{escape(value)}"' for value in substrings)


def _pattern_header(pattern: str) -> Table:
    """Build a header containing safe equivalents of the PCRE2 input."""
    comparer = RegexComparer()
    patterns = {Engine.PCRE2: pattern}
    try:
        source = comparer.parse(pattern, Engine.PCRE2)
        patterns.update(
            {alternative.engine: alternative.pattern
             for alternative in comparer.alternatives(source)}
        )
    except ValueError:
        # Compilation diagnostics below remain the authority for invalid input.
        pass

    table = Table(title="Wazuh Regex Tester", show_header=True,
                  header_style="bold")
    table.add_column("engine", style="cyan", width=15)
    table.add_column("Equivalent pattern")
    for engine, label in (
        (Engine.OSREGEX, "OS_Regex"),
        (Engine.SREGEX, "OS_Match"),
        (Engine.PCRE2, "PCRE2"),
    ):
        alternative = patterns.get(engine)
        table.add_row(
            label,
            escape(alternative) if alternative is not None else "[dim]Not safely convertible[/dim]",
        )
    return table


def main() -> None:
    console = Console()

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        console.print(f"[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        console.print("Test each stdin line against Wazuh regex engines.")
        return

    if len(sys.argv) != 2:
        console.print("[bold red]Error:[/bold red] expected one pattern argument")
        console.print(f"[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        sys.exit(2)

    pattern = sys.argv[1]

    # Treat the command-line expression as PCRE2 when deriving equivalent
    # spellings. Every conversion is round-trip checked by RegexComparer.
    console.print(Panel(f"[bold cyan]Input pattern:[/bold cyan] {escape(pattern)}"))
    console.print(_pattern_header(pattern))

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
        text = _remove_line_delimiter(line)

        # Create results table
        table = Table(title=f"Testing: {escape(text)}",
                      show_header=True, header_style="bold")
        table.add_column("Engine", style="cyan", width=15)
        table.add_column("Result", justify="center", width=15)
        table.add_column("Match Span", style="yellow")
        table.add_column("Captured Groups", style="green")

        # Test OS_Regex
        is_match, spans = wazuh_tool.os_regex(text)
        if "OS_Regex" in validation_errors:
            table.add_row("OS_Regex", "⚠ Invalid", "—", "—")
        elif is_match:
            substrings = wazuh_tool.get_substrings()
            span_str = str(spans[0]) if spans else "—"
            groups_str = _format_substrings(substrings) if substrings else "—"
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
            groups_str = _format_substrings(substrings) if substrings else "—"
            table.add_row("PCRE2", "✅ Match", span_str, groups_str)
        else:
            table.add_row("PCRE2", "❌ No Match", "—", "—")

        console.print(table)
        console.print()  # Blank line between tests


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('bye!👋')
        pass
