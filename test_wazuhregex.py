# test_wazuh_regex.py

import pytest

from wazuh_regex_lib import WazuhRegex, os_match2, os_regex

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
SUCCESS_REGEX_DATA = [
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
FAIL_REGEX_DATA = [
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
EXTRACTION_DATA = [
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

# --- Pytest Test Functions ---


@pytest.mark.parametrize("pattern, text", SUCCESS_MATCH_DATA)
def test_osmatch_success(pattern: str, text: str) -> None:
    """Replicates test_success_match from the C tests."""
    is_match, _ = os_match2(pattern, text)
    assert is_match is True


@pytest.mark.parametrize("pattern, text", FAIL_MATCH_DATA)
def test_osmatch_fail(pattern: str, text: str) -> None:
    """Replicates test_fail_match from the C tests."""
    is_match, _ = os_match2(pattern, text)
    assert is_match is False


@pytest.mark.parametrize("pattern, text", SUCCESS_REGEX_DATA)
def test_osregex_success(pattern: str, text: str) -> None:
    """Replicates test_success_regex from the C tests."""
    is_match, _ = os_regex(pattern, text)
    assert is_match is True


@pytest.mark.parametrize("pattern, text", FAIL_REGEX_DATA)
def test_osregex_fail(pattern: str, text: str) -> None:
    """Replicates test_fail_regex from the C tests."""
    is_match, _ = os_regex(pattern, text)
    assert is_match is False


@pytest.mark.parametrize("pattern, text, expected_substrings", EXTRACTION_DATA)
def test_osregex_extraction(pattern: str, text: str, expected_substrings: list[str]) -> None:
    """Replicates test_regex_extraction from the C tests."""
    tool = WazuhRegex(pattern)
    is_match, _ = tool.os_regex_execute(text)
    assert is_match is True
    assert tool.get_substrings() == expected_substrings
