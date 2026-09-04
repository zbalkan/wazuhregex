#!/usr/bin/env python3

import multiprocessing
import signal
import sys
from multiprocessing.connection import Connection

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .compare import Engine, RegexComparer
from .highlighter import Highlighter
from .wazuh_regex_lib import WazuhRegex


LINE_TIMEOUT_SECONDS = 0.1
MAX_INPUT_LINES = 20


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


def _evaluate_line(
    tool: WazuhRegex,
    text: str,
    validation_errors: dict[str, str],
) -> tuple[
    tuple[bool, list[tuple[int, int]], list[str]],
    tuple[bool, list[tuple[int, int]]],
    tuple[bool, list[tuple[int, int]], list[str]],
]:
    """Evaluate one record against all three Wazuh engines."""
    osregex_match, osregex_spans = tool.os_regex(text)
    osregex_groups = (
        tool.get_substrings()
        if osregex_match and "OS_Regex" not in validation_errors
        else []
    )

    osmatch_match, osmatch_spans = tool.os_match(text)

    pcre2_match, pcre2_spans = tool.pcre2_regex(text)
    pcre2_groups = (
        tool.get_substrings()
        if pcre2_match and "PCRE2" not in validation_errors
        else []
    )

    return (
        (osregex_match, osregex_spans, osregex_groups),
        (osmatch_match, osmatch_spans),
        (pcre2_match, pcre2_spans, pcre2_groups),
    )


def _line_worker(pattern: str, connection: Connection) -> None:
    """Evaluate records in an isolated persistent process for hard timeouts."""
    # Ctrl+C is owned by the parent process.  On Windows, console control events
    # are delivered to every process sharing the console; leaving the default
    # handler installed here makes an idle spawn worker print its own traceback.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    tool = WazuhRegex(pattern)
    validation_errors = tool.validation_errors()
    connection.send(("ready", validation_errors))
    try:
        while True:
            text = connection.recv()
            if text is None:
                return
            try:
                connection.send(
                    ("result", _evaluate_line(tool, text, validation_errors))
                )
            except Exception as error:  # pragma: no cover - defensive worker boundary
                connection.send(
                    ("error", f"{type(error).__name__}: {error}")
                )
    except (EOFError, KeyboardInterrupt):
        # The explicit KeyboardInterrupt guard also keeps shutdown quiet if an
        # interrupt arrives before the platform has applied the ignored signal.
        return
    finally:
        connection.close()


def _start_worker(
    pattern: str,
) -> tuple[multiprocessing.Process, Connection, dict[str, str]]:
    """Start one reusable spawn worker and wait until pattern validation is ready."""
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(target=_line_worker, args=(pattern, child), daemon=True)
    process.start()
    child.close()

    try:
        kind, payload = parent.recv()
    except EOFError as error:
        process.join()
        parent.close()
        raise RuntimeError("regex worker failed to start") from error
    if kind != "ready":
        process.terminate()
        process.join()
        parent.close()
        raise RuntimeError("regex worker returned an invalid startup message")
    return process, parent, payload


def _stop_worker(process: multiprocessing.Process, connection: Connection) -> None:
    """Close a worker without leaving child processes behind."""
    if process.is_alive():
        try:
            connection.send(None)
        except (BrokenPipeError, EOFError, OSError):
            pass
        process.join(timeout=0.2)
    if process.is_alive():
        process.terminate()
        process.join()
    connection.close()


def _render_timeout(console: Console, text: str) -> None:
    table = Table(title=f"Testing: {escape(text)}",
                  show_header=True, header_style="bold")
    table.add_column("Engine", style="cyan")
    table.add_column("Result", justify="center")
    table.add_column("Match / Span")
    table.add_column("Captured Groups", style="green")
    for engine, groups in (("OS_Regex", "-"), ("OS_Match", "N/A"), ("PCRE2", "-")):
        table.add_row(engine, "Timeout", "-", groups)
    console.print(table)
    console.print()


def _render_results(
    console: Console,
    text: str,
    validation_errors: dict[str, str],
    results: tuple[
        tuple[bool, list[tuple[int, int]], list[str]],
        tuple[bool, list[tuple[int, int]]],
        tuple[bool, list[tuple[int, int]], list[str]],
    ],
) -> None:
    table = Table(title=f"Testing: {escape(text)}",
                  show_header=True, header_style="bold")
    table.add_column("Engine", style="cyan")
    table.add_column("Result", justify="center")
    table.add_column("Match / Span")
    table.add_column("Captured Groups", style="green")

    (is_match, spans, substrings), osmatch, pcre2 = results
    if "OS_Regex" in validation_errors:
        table.add_row("OS_Regex", "Invalid", "-", "-")
    elif is_match:
        groups_str = _format_substrings(substrings) if substrings else "-"
        table.add_row("OS_Regex", "Match", _format_match(text, spans), groups_str)
    else:
        table.add_row("OS_Regex", "No Match", "-", "-")

    is_match, spans = osmatch
    if is_match:
        table.add_row("OS_Match", "Match", _format_match(text, spans), "N/A")
    else:
        table.add_row("OS_Match", "No Match", "-", "N/A")

    is_match, spans, substrings = pcre2
    if "PCRE2" in validation_errors:
        table.add_row("PCRE2", "Invalid", "-", "-")
    elif is_match:
        groups_str = _format_substrings(substrings) if substrings else "-"
        table.add_row("PCRE2", "Match", _format_match(text, spans), groups_str)
    else:
        table.add_row("PCRE2", "No Match", "-", "-")

    console.print(table)
    console.print()


def _run() -> None:
    console = Console()

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        console.print(f"[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        console.print("Test each stdin line against Wazuh regex engines.")
        console.print(
            f"Limits: {MAX_INPUT_LINES} input lines per run; "
            f"{int(LINE_TIMEOUT_SECONDS * 1000)} ms evaluation time per line."
        )
        return

    if len(sys.argv) != 2:
        console.print("[bold red]Error:[/bold red] expected one pattern argument")
        console.print(f"[bold]Usage:[/bold] {sys.argv[0]} '<PATTERN>'")
        sys.exit(2)

    pattern = sys.argv[1]
    console.print(Panel(f"[bold cyan]Input pattern:[/bold cyan] {escape(pattern)}"))
    console.print(_pattern_header(pattern))

    process, connection, validation_errors = _start_worker(pattern)
    console.print("[green]OK[/green] Pattern loaded\n", style="dim")
    for engine, error in validation_errors.items():
        console.print(f"[yellow]WARNING {engine}:[/yellow] {escape(error)}")
    if validation_errors:
        console.print()

    try:
        for line_number, line in enumerate(sys.stdin, start=1):
            if line_number > MAX_INPUT_LINES:
                console.print(
                    f"[bold red]Error:[/bold red] input is limited to "
                    f"{MAX_INPUT_LINES} lines per run"
                )
                sys.exit(2)

            text = _remove_line_delimiter(line)
            if not text or text.isspace():
                continue

            try:
                connection.send(text)
            except (BrokenPipeError, EOFError, OSError):
                _stop_worker(process, connection)
                process, connection, validation_errors = _start_worker(pattern)
                connection.send(text)

            if not connection.poll(LINE_TIMEOUT_SECONDS):
                _render_timeout(console, text)
                _stop_worker(process, connection)
                process, connection, validation_errors = _start_worker(pattern)
                continue

            kind, payload = connection.recv()
            if kind == "result":
                _render_results(console, text, validation_errors, payload)
            else:
                console.print(
                    f"[bold red]Runtime error:[/bold red] {escape(str(payload))}"
                )
    finally:
        _stop_worker(process, connection)


def main() -> int:
    """Run the CLI, translating Ctrl+C into a clean process exit."""
    try:
        _run()
    except KeyboardInterrupt:
        print("bye!")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
