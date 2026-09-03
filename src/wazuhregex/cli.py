#!/usr/bin/env python3

import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .compare import Engine, RegexComparer
from .highlighter import Highlighter
from .wazuh_regex_lib import WazuhRegex


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


def _format_spans(spans: list[tuple[int, int]]) -> str:
    """Format every match span instead of silently dropping later matches."""
    return ", ".join(map(str, spans)) if spans else "-"


def _highlight_matches(text: str, spans: list[tuple[int, int]]) -> Text | str:
    """Return literal text with all non-empty match spans highlighted."""
    if not spans:
        return "-"
    return Text.from_ansi(Highlighter().apply(text, spans))


def _format_match(text: str, spans: list[tuple[int, int]]) -> Text | str:
    """Show highlighted matches and their exact offsets in one compact cell."""
    highlighted = _highlight_matches(text, spans)
    if isinstance(highlighted, str):
        return highlighted
    highlighted.append(f"\n{_format_spans(spans)}", style="yellow")
    return highlighted


def _pattern_header(pattern: str) -> Table:
    """Build a header containing safe equivalents of the detected input."""
    comparer = RegexComparer()
    original_engine = comparer.detect_engine(pattern)
    if original_engine is None:
        # Plain literals use the same spelling in every engine. Avoid parsing
        # and conversion work, and do not imply that one engine was original.
        patterns = dict.fromkeys(Engine, pattern)
    else:
        patterns = {original_engine: pattern}
        try:
            source = comparer.parse(pattern, original_engine)
            patterns.update(
                {alternative.engine: alternative.pattern
                 for alternative in comparer.alternatives(source)}
            )
        except ValueError:
            # Compilation diagnostics remain the authority for invalid input.
            pass

    table = Table(title="Wazuh Regex Tester", show_header=True,
                  header_style="bold")
    table.add_column("engine", style="cyan", width=20)
    table.add_column("Equivalent pattern")
    table.add_column("Remarks")
    for engine, label in (
        (Engine.OSREGEX, "OS_Regex"),
        (Engine.SREGEX, "OS_Match"),
        (Engine.PCRE2, "PCRE2"),
    ):
        alternative = patterns.get(engine)
        table.add_row(
            f"{label} (orig.)" if engine == original_engine else label,
            escape(alternative) if alternative is not None else "",
            ("[dim]Literal[/dim]" if original_engine is None else "")
            if alternative is not None
            else "[dim]Not safely convertible[/dim]",
        )
    return table


def _run() -> None:
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

    # Detect the command-line expression heuristically when deriving equivalent
    # spellings. Every conversion is round-trip checked by RegexComparer.
    console.print(Panel(f"[bold cyan]Input pattern:[/bold cyan] {escape(pattern)}"))
    console.print(_pattern_header(pattern))

    try:
        wazuh_tool = WazuhRegex(pattern)
    except ValueError as error:
        console.print(f"[red]Invalid pattern:[/red] {escape(str(error))}")
        sys.exit(2)
    console.print("[green]OK[/green] Pattern loaded\n", style="dim")
    validation_errors = wazuh_tool.validation_errors()
    for engine, error in validation_errors.items():
        console.print(
            f"[yellow]WARNING {engine}:[/yellow] {escape(error)}"
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
        table.add_column("Engine", style="cyan")
        table.add_column("Result", justify="center")
        table.add_column("Match / Span")
        table.add_column("Captured Groups", style="green")

        # Test OS_Regex
        is_match, spans = wazuh_tool.os_regex(text)
        if "OS_Regex" in validation_errors:
            table.add_row("OS_Regex", "Invalid", "-", "-")
        elif is_match:
            substrings = wazuh_tool.get_substrings()
            groups_str = _format_substrings(substrings) if substrings else "-"
            table.add_row("OS_Regex", "Match",
                          _format_match(text, spans), groups_str)
        else:
            table.add_row("OS_Regex", "No Match", "-", "-")

        # Test OS_Match
        is_match, spans = wazuh_tool.os_match(text)
        if is_match:
            table.add_row("OS_Match", "Match",
                          _format_match(text, spans), "N/A")
        else:
            table.add_row("OS_Match", "No Match", "-", "N/A")

        # Test PCRE2
        is_match, spans = wazuh_tool.pcre2_regex(text)
        if "PCRE2" in validation_errors:
            table.add_row("PCRE2", "Invalid", "-", "-")
        elif is_match:
            substrings = wazuh_tool.get_substrings()
            groups_str = _format_substrings(substrings) if substrings else "-"
            table.add_row("PCRE2", "Match",
                          _format_match(text, spans), groups_str)
        else:
            table.add_row("PCRE2", "No Match", "-", "-")

        console.print(table)
        console.print()  # Blank line between tests


def main() -> int:
    """Run the CLI, translating Ctrl+C into a clean process exit."""
    try:
        _run()
    except KeyboardInterrupt:
        # Catch this in the console entry point rather than installing a signal
        # handler. This is portable and also works in pip/pipx launchers, which
        # call ``main`` directly instead of executing this module's guard.
        print("bye!")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
