import subprocess
import sys

import pytest
from rich.console import Console

from src.compare import Engine, RegexComparer
from src.highlighter import Highlighter
from src.wazuh_regex_lib import WazuhRegex
from src.wazuhregex import _pattern_header, _remove_line_delimiter

# --- Data from C unit tests ---

# Data for: test_success_match (uses OS_Match2)
SUCCESS_MATCH_DATA = [
    ("abc", "abcd"),
    ("abcd", "abcd"),
    ("a", "a"),
    ("a", "aa"),
    ("^a", "ab"),
    ("test", "testa"),
    ("test", "testest"),
    ("lalaila", "lalalalaila"),
    ("abc|cde", "cde"),
    ("^aa|ee|ii|oo|uu", "dfgdsii"),
    ("Abc", "abc"),
    ("ZBE", "zbe"),
    ("ABC", "ABc"),
    ("^A", "a"),
    ("a|E", "abcdef"),
    ("daniel", "daniel"),
    ("DANIeL", "daNIel"),
    ("^abc ", "abc "),
    ("ddd|eee|fff|ggg|ggg|hhh|iii", "iii"),
    ("kwo|fe|fw|wfW|edW|dwDF|WdW|dw|d|^la", "la"),
    ("^a", "a"),
    ("^ab$", "ab"),
    ("c$", "c"),
    ("c$", "lalalalac"),
    ("^bin$|^shell$", "bin"),
    ("^bin$|^shell$", "shell"),
    ("^bin$|^shell$|^ftp$", "shell"),
    ("^bin$|^shell$|^ftp$", "ftp"),
    ("!test1", "test2"),
]

# Data for: test_fail_match (uses OS_Match2)
FAIL_MATCH_DATA = [
    ("abc", "abb"),
    ("^ab", " ab"),
    ("test", "tes"),
    ("abcd", "abc"),
    ("abbb", "abb"),
    ("abbbbbbbb", "abbbbbbb"),
    ("a|b|c| ", "def"),
    ("lala$", "lalalalalal"),
    ("^ab$", "abc"),
    ("zzzz$", "zzzzzzzzzzzz "),
    ("zzzz$", "zzz"),
    ("^bin$|^shell$", "bina"),
    ("^bin$|^shell$", "shella"),
    ("^bin$|^shell$", "ashell"),
    ("!test1", "test1"),
]

# Data for: test_success_regex (uses OS_Regex)
SUCCESS_REGEX_DATA: list[tuple[str, str]] = [
    ("", ""),
    ("", "a"),
    ("abc", "abcd"),
    ("abcd", "abcd"),
    ("a", "a"),
    ("a", "aa"),
    ("^a", "ab"),
    ("^$", ""),
    ("^", ""),
    ("$", ""),
    (r"\.*", ""),
    (r"(\.*)", ""),
    ("test", "testa"),
    ("test", "testest"),
    ("lalaila", "lalalalaila"),
    ("abc|cde", "cde"),
    ("^aa|ee|ii|oo|uu", "dfgdsii"),
    ("Abc", "abc"),
    ("ZBE", "zbe"),
    ("ABC", "ABc"),
    ("^A", "a"),
    ("a|E", "abcdef"),
    ("daniel", "daniel"),
    ("DANIeL", "daNIel"),
    ("^abc ", "abc "),
    ("ddd|eee|fff|ggg|ggg|hhh|iii", "iii"),
    ("kwo|fe|fw|wfW|edW|dwDF|WdW|dw|d|^la", "la"),
    ("^a", "a"),
    ("^ab$", "ab"),
    ("c$", "c"),
    ("c$", "lalalalac"),
    ("^bin$|^shell$", "bin"),
    ("^bin$|^shell$", "shell"),
    ("^bin$|^shell$|^ftp$", "shell"),
    ("^bin$|^shell$|^ftp$", "ftp"),
    (r"\s+123", "  123"),
    (r"\s*123", "123"),
    (r"\s123", " 123"),
    (r"\w+\s+\w+", "a 1"),
    (r"\w+\d+\w+\s+", "ab12fb12fd12 "),
    (r"^\s*\w\s*\w+", "a   l a  a"),
    (r"\w+\s+\w+\d+\s$", "a aa11 "),
    (r"^su\S*: BAD su", "su: BAD SU dcid to root on /dev/ttyp0"),
    (r"^su\s*: BAD su", "su: BAD SU dcid to root on /dev/ttyp0"),
    (r"^abc\sabc", "abc abcd"),
    (r"^abc\s\s*abc", "abc abcd"),
    (r"^\s+\sl", "     lala"),
    (r"^\s*\sl", "     lala"),
    (r"^\s\s+l", "     lala"),
    (r"^\s+\s l", "     lala"),
    (r"^\s*\s lal\w$", "  lala"),
    (r"test123test\d+$", "test123test123"),
    (r"^kernel: \S+ \.+ SRC=\S+ DST=\S+ \.+ PROTO=\w+ SPT=\d+ DPT=\d+ ",
     "kernel: IPTABLE IN=eth0 OUT= MAC=ff:ff:ff:ff:ff:ff:00:03:93:db:2e:b4:08:00 SRC=10.4.11.40 DST=255.255.255.255 LEN=180 TOS=0x00 PREC=0x00 TTL=64 ID=4753 PROTO=UDP SPT=49320 DPT=2222 LEN=160"),
    (r"test (\w+)la", "test abclala"),
    (r"(\w+) (\w+)", "wofl wofl"),
    (r"^\S+ [(\d+:\d+:\d+)] \.+ (\d+.\d+.\d+.\d+)\p*\d* -> (\d+.\d+.\d+.\d+)\p*",
     "snort: [1:469:3] ICMP PING NMAP [Classification: Attempted Information Leak] [Priority: 2]: {ICMP} 10.4.12.26 -> 10.4.10.231"),
    (r"^\t 1234", "\t 1234"),
    (r"^abc\$d", "abc$d"),
    (r"^abc\|d", "abc|d"),
    (r"^abc\<d", "abc<d"),
    (r"^\\ \w$", r"\ a"),
    (r"^\D+123", "test123"),
    (r"^\W+abc", " \t abc"),
]

# Data for: test_fail_regex (uses OS_Regex)
FAIL_REGEX_DATA: list[tuple[str, str]] = [
    ("abc", "abb"),
    ("^ab", " ab"),
    ("^$", "a"),
    ("$", "a"),
    ("test", "tes"),
    ("abcd", "abc"),
    ("abbb", "abb"),
    ("abbbbbbbb", "abbbbbbb"),
    ("a|b|c| ", "def"),
    ("lala$", "lalalalalal"),
    ("^ab$", "abc"),
    ("zzzz$", "zzzzzzzzzzzz "),
    ("^bin$|^shell$", "bina"),
    ("^bin$|^shell$", "shella"),
    ("^bin$|^shell$", "ashell"),
    (r"\w+\s+\w+\d+\s$", "a aa11  "),
    (r"^\s+\s     l", "     lala"),
    (r"test123test\d+", "test123test"),
    (r"test123test\d+$", "test123test"),
    ("(lalala", "lalala"),
    (r"test123(\d)", "test123a"),
    (r"\(test)", "test"),
    (r"(\w+)(\d+)", "1 1"),
    (r"^abc\*d", "abc*d"),
    (r"^\D+123", "te5st123"),
    (r"^\W+abc", " \t 1 abc"),
    (r"(\w|(\w)", ""),
]

# Data for: test_regex_extraction
EXTRACTION_DATA: list[tuple[str, str, list[str]]] = [
    (r"123(\w+\s+)abc", "123sdf    abc", ["sdf    "]),
    (r"123(\w+\s+)abc", "abc123sdf    abc", ["sdf    "]),
    (r"123 (\d+.\d.\d.\d\d*\d*)", "123 45.6.5.567", ["45.6.5.567"]),
    (r"from (\S*\d+.\d+.\d+.\d\d*\d*)",
     "sshd[21576]: Illegal user web14 from ::ffff:212.227.60.55", ["::ffff:212.227.60.55"]),
    (r"^sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+) port ",
     "sshd[21405]: Accepted password for root from 192.1.1.1 port 6023", ["root", "192.1.1.1"]),
    (r": \((\S+)@(\S+)\) \[", "pure-ftpd: (?@enigma.lab.ossec.net) [INFO] New connection from enigma.lab.ossec.net",
     ["?", "enigma.lab.ossec.net"]),
]


@pytest.mark.parametrize("pattern, text", SUCCESS_MATCH_DATA)
def test_osmatch_success(pattern: str, text: str) -> None:
    """Replicates test_success_match from the C tests."""
    is_match, _ = WazuhRegex(pattern).os_match(text)
    assert is_match is True


@pytest.mark.parametrize("pattern, text", FAIL_MATCH_DATA)
def test_osmatch_fail(pattern: str, text: str) -> None:
    """Replicates test_fail_match from the C tests."""
    is_match, _ = WazuhRegex(pattern).os_match(text)
    assert is_match is False


@pytest.mark.parametrize("pattern, text", SUCCESS_REGEX_DATA)
def test_osregex_success(pattern: str, text: str) -> None:
    """Replicates test_success_regex from the C tests."""
    is_match, _ = WazuhRegex(pattern).os_regex(text)
    assert is_match is True


@pytest.mark.parametrize("pattern, text", FAIL_REGEX_DATA)
def test_osregex_fail(pattern: str, text: str) -> None:
    """Replicates test_fail_regex from the C tests."""
    is_match, _ = WazuhRegex(pattern).os_regex(text)
    assert is_match is False


@pytest.mark.parametrize("pattern, text, expected_substrings", EXTRACTION_DATA)
def test_osregex_extraction(pattern: str, text: str, expected_substrings: list[str]) -> None:
    """Replicates test_regex_extraction from the C tests."""
    tool = WazuhRegex(pattern)
    is_match, _ = tool.os_regex(text)
    assert is_match is True
    assert tool.get_substrings() == expected_substrings


def test_osregex_multiple_group_matches() -> None:
    tool = WazuhRegex(r"(\d+)")
    is_match, spans = tool.os_regex("30 Agustos 2020")

    assert is_match is True
    assert spans == [(0, 2), (11, 15)]
    assert tool.get_substrings() == ["30", "2020"]


@pytest.mark.parametrize(
    "token, matching_text, non_matching_text",
    [
        (r"\d", "7", "a"),
        (r"\D", "a", "7"),
        (r"\w", "@", "."),
        (r"\w", "-", "+"),
        (r"\W", "+", "_"),
        (r"\s", " ", "\t"),
        (r"\S", "\t", " "),
        (r"\t", "\t", " "),
        (r"\p", "#", "a"),
    ],
)
def test_osregex_documented_character_classes(
    token: str, matching_text: str, non_matching_text: str
) -> None:
    """Exercise the character classes supported by Wazuh OS_Regex."""
    assert WazuhRegex(f"^{token}$").os_regex(matching_text)[0] is True
    assert WazuhRegex(f"^{token}$").os_regex(non_matching_text)[0] is False


@pytest.mark.parametrize(
    "pattern, matching_text, non_matching_text",
    [
        (r"^\d+$", "012345", "012a45"),
        (r"^\w*$", "user-name_1@example", "user.name"),
        (r"^\s+$", "   ", " \t "),
        (r"^\S+$", "host\tname", "host name"),
        (r"^file\.log$", "fileXlog", "filelog"),
        (r"^file.log$", "file.log", "fileXlog"),
    ],
)
def test_osregex_documented_operators(
    pattern: str, matching_text: str, non_matching_text: str
) -> None:
    """Cover Wazuh repetition and its unusual escaped-dot wildcard."""
    assert WazuhRegex(pattern).os_regex(matching_text)[0] is True
    assert WazuhRegex(pattern).os_regex(non_matching_text)[0] is False


@pytest.mark.parametrize("pattern", [r"a+", r"a*", r"(foo|bar)"])
def test_osregex_rejects_unsupported_operator_placement(pattern: str) -> None:
    tool = WazuhRegex(pattern)

    assert tool.os_regex(pattern)[0] is False
    assert "OS_Regex" in tool.validation_errors()


def test_osregex_allows_repetition_of_tab_class() -> None:
    assert WazuhRegex(r"^\t+$").os_regex("\t\t") == (True, [(0, 2)])


@pytest.mark.parametrize(
    "pattern, pcre_text, literal_text",
    [
        (r"\bcat\b", "cat", "bcatb"),
        (r"\x41", "A", "x41"),
        (r"(a)\1", "aa", "a1"),
    ],
)
def test_osregex_does_not_enable_unknown_pcre_escapes(
    pattern: str, pcre_text: str, literal_text: str
) -> None:
    tool = WazuhRegex(f"^{pattern}$")

    assert tool.os_regex(pcre_text)[0] is False
    assert tool.os_regex(literal_text)[0] is True


def test_osregex_allows_escaped_alternation_inside_group() -> None:
    tool = WazuhRegex(r"^(left\|right)$")

    assert "OS_Regex" not in tool.validation_errors()
    assert tool.os_regex("left|right") == (True, [(0, 10)])


def test_osregex_rejects_nested_group_alternation() -> None:
    tool = WazuhRegex(r"(outer(inner|other))")

    assert tool.os_regex("outerinner")[0] is False
    assert "Alternation '|' in group" in tool.validation_errors()["OS_Regex"]


def test_osregex_is_case_insensitive_but_pcre2_is_case_sensitive() -> None:
    tool = WazuhRegex("^error$")

    assert tool.os_regex("ERROR")[0] is True
    assert tool.pcre2_regex("ERROR")[0] is False


def test_osregex_captures_empty_and_unmatched_groups_distinctly() -> None:
    tool = WazuhRegex(r"^(\d*)(\s)(\w+)$")

    assert tool.os_regex(" user")[0] is True
    assert tool.get_substrings() == ["", " ", "user"]


def test_pcre2_multiple_group_matches() -> None:
    tool = WazuhRegex(r"(\d+)")
    is_match, spans = tool.pcre2_regex("30 Agustos 2020")

    assert is_match is True
    assert spans == [(0, 2), (11, 15)]
    assert tool.get_substrings() == ["30", "2020"]


@pytest.mark.parametrize(
    "pattern, text, expected_spans",
    [
        (r"(?<=user=)\w+", "user=alice", [(5, 10)]),
        (r"\b(?:cat|dog)s?\b", "cats and dog", [(0, 4), (9, 12)]),
        (r"^line\Rnext$", "line\r\nnext", [(0, 10)]),
        (r"\p{L}+", "123 café 456", [(4, 8)]),
    ],
)
def test_pcre2_extended_syntax(
    pattern: str, text: str, expected_spans: list[tuple[int, int]]
) -> None:
    """Cover PCRE2 constructs that are intentionally not OS_Regex syntax."""
    assert WazuhRegex(pattern).pcre2_regex(text) == (True, expected_spans)


def test_pcre2_preserves_named_and_optional_capture_values() -> None:
    tool = WazuhRegex(r"(?<scheme>https?)(://)(www\.)?")

    assert tool.pcre2_regex("http://example.com")[0] is True
    assert tool.get_substrings() == ["http", "://"]


def test_failed_match_clears_captures_from_previous_match() -> None:
    tool = WazuhRegex(r"(\d+)")
    assert tool.pcre2_regex("id=42")[0] is True
    assert tool.get_substrings() == ["42"]

    assert tool.pcre2_regex("no digits")[0] is False
    assert tool.get_substrings() == []


def test_get_substrings_returns_a_copy() -> None:
    tool = WazuhRegex(r"(\d+)")
    assert tool.pcre2_regex("42")[0] is True

    returned_substrings = tool.get_substrings()
    returned_substrings.append("caller mutation")

    assert tool.get_substrings() == ["42"]


@pytest.mark.parametrize("method_name", ["os_regex", "os_match", "pcre2_regex"])
def test_match_methods_reject_non_string_text_consistently(method_name: str) -> None:
    method = getattr(WazuhRegex("event"), method_name)

    with pytest.raises(TypeError, match="text must be a string"):
        method(None)


def test_pattern_preserves_single_quotes_as_literals() -> None:
    tool = WazuhRegex(r"'(\d+)'")
    is_match, spans = tool.os_regex("value '30'")

    assert is_match is True
    assert spans == [(6, 10)]
    assert tool.get_substrings() == ["30"]


def test_pattern_preserves_double_quotes_as_literals() -> None:
    tool = WazuhRegex(r'"(\d+)"')
    is_match, spans = tool.pcre2_regex('value "30"')

    assert is_match is True
    assert spans == [(6, 10)]
    assert tool.get_substrings() == ["30"]


@pytest.mark.parametrize("metacharacter", list(".?[]{}"))
def test_osregex_treats_pcre_only_metacharacters_as_literals(metacharacter: str) -> None:
    assert WazuhRegex(metacharacter).os_regex(metacharacter)[0] is True
    assert WazuhRegex(metacharacter).os_regex("unrelated")[0] is False


def test_osmatch_removes_only_one_anchor_at_each_end() -> None:
    assert WazuhRegex("^^event").os_match("^event log")[1] == [(0, 6)]


@pytest.mark.parametrize(
    "pattern, text, expected_span",
    [
        ("needle", "a NEEDLE here", (2, 8)),
        ("^start", "START here", (0, 5)),
        ("finish$", "the FINISH", (4, 10)),
        ("^whole$", "WHOLE", (0, 5)),
        ("first|second", "use SECOND", (4, 10)),
    ],
)
def test_osmatch_documented_matching_modes(
    pattern: str, text: str, expected_span: tuple[int, int]
) -> None:
    """Cover sregex substring, anchors, alternatives, and case folding."""
    assert WazuhRegex(pattern).os_match(text) == (True, [expected_span])


@pytest.mark.parametrize("pattern", ["a.b", "a+b", "a*b", "a\\db", "a(b)"])
def test_osmatch_treats_regular_expression_syntax_literally(pattern: str) -> None:
    assert WazuhRegex(f"^{pattern}$").os_match(pattern)[0] is True


def test_osmatch_negation_applies_to_all_alternatives() -> None:
    tool = WazuhRegex("!debug|trace")

    assert tool.os_match("an informational event") == (True, [])
    assert tool.os_match("DEBUG event") == (False, [])
    assert tool.os_match("trace event") == (False, [])


def test_osmatch_uses_first_matching_alternative() -> None:
    assert WazuhRegex("cat|catalog").os_match("catalog") == (True, [(0, 3)])


def test_osmatch_clears_captures_created_by_another_engine() -> None:
    tool = WazuhRegex(r"(\d+)")
    assert tool.os_regex("42")[0] is True
    assert tool.get_substrings() == ["42"]

    tool.os_match("literal text")
    assert tool.get_substrings() == []


def test_osmatch_unicode_input_keeps_original_span_offsets() -> None:
    """Unicode case mappings must not move offsets in the original input."""
    assert WazuhRegex("event").os_match("\u0130EVENT") == (True, [(1, 6)])


@pytest.mark.parametrize("character", list(r'''-()*+,.\:;<=>?[]!"'#$%&|{}'''))
def test_osregex_punctuation_class(character: str) -> None:
    assert WazuhRegex(r"\p").os_regex(character)[0] is True


def test_highlighter_applies_every_span() -> None:
    highlighter = Highlighter(highlight_color="<")

    assert highlighter.apply("one two", [(0, 3), (4, 7)]) == (
        "<one\033[0m <two\033[0m"
    )


def test_highlighter_rejects_invalid_span() -> None:
    with pytest.raises(ValueError, match="Invalid highlight span"):
        Highlighter().apply("text", [(0, 5)])


def test_cli_module_preserves_empty_input() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex", "^$"],
        input="\n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "OS_Regex" in result.stdout
    assert "Match" in result.stdout


def test_regex_comparer_converts_literal_to_all_engines() -> None:
    comparer = RegexComparer()
    source = comparer.parse("^event$", Engine.PCRE2)

    assert {
        alternative.engine: alternative.pattern
        for alternative in comparer.alternatives(source)
    } == {
        Engine.OSREGEX: "^event$",
        Engine.SREGEX: "^event$",
    }


def test_pattern_header_shows_all_safe_alternatives() -> None:
    console = Console(record=True)
    console.print(_pattern_header("^event$"))
    rendered = console.export_text()

    assert "OS_Regex" in rendered
    assert "OS_Match" in rendered
    assert "PCRE2" in rendered


def test_cli_preserves_input_whitespace() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex", "^ record $"],
        input=" record \n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "OS_Match" in result.stdout
    assert "✅ Match" in result.stdout


@pytest.mark.parametrize(
    "line, expected",
    [
        ("record\n", "record"),
        ("record\r\n", "record"),
        ("record\r", "record\r"),
        ("record\r\r\n", "record\r"),
        ("record", "record"),
    ],
)
def test_remove_line_delimiter_preserves_record_content(
    line: str, expected: str
) -> None:
    assert _remove_line_delimiter(line) == expected


def test_cli_renders_captured_rich_markup_as_literal_text() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex", r"(\S+)"],
        input="[bold]event[/bold]\n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert '"[bold]event[/bold]"' in result.stdout


@pytest.mark.parametrize("help_option", ["-h", "--help"])
def test_cli_help_does_not_treat_option_as_a_pattern(help_option: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex", help_option],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "Pattern:" not in result.stdout


def test_cli_requires_exactly_one_pattern() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "expected one pattern argument" in result.stdout


def test_validation_errors_are_reported_per_engine() -> None:
    errors = WazuhRegex("a+").validation_errors()

    assert "OS_Regex" in errors
    assert "Modifier on bare character" in errors["OS_Regex"]
    assert "PCRE2" not in errors


def test_validation_errors_reports_invalid_pcre2() -> None:
    errors = WazuhRegex("(").validation_errors()

    assert "OS_Regex" in errors
    assert "PCRE2" in errors


def test_cli_distinguishes_invalid_pattern_from_non_match() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "src.wazuhregex", "a+"],
        input="bbb\n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "OS_Regex" in result.stdout
    assert "Modifier on bare character" in result.stdout
    assert "Invalid" in result.stdout
