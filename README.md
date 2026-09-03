# wazuhregex

[![CI](https://github.com/zbalkan/wazuhregex/actions/workflows/ci.yml/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/dependabot-updates)
[![Dependency Graph](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/update-graph)
[![Publish to PyPI](https://github.com/zbalkan/wazuhregex/actions/workflows/publish.yml/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/publish.yml)

`wazuhregex` is a Python package and command-line tool that implements Wazuh regex behavior for local testing and development. It lets you validate one pattern against [all three Wazuh regex engines](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html) in one run:

- `OS_Regex`
- `OS_Match` ([sregex](https://github.com/openresty/sregex))
- `PCRE2`

The project includes:

- `src/wazuhregex/`: importable Python package and command-line implementation.
- `wazuhregex`: CLI tester with side-by-side engine results.
- `tests/test_wazuhregex.py`: pytest suite that mirrors Wazuh C test coverage.
- `tests/test_engine_edge_cases.py`: additional engine boundary and edge-case coverage, including explicit expected failures for known alpha compatibility gaps.

## Why this exists

Wazuh rules can use regex engines that differ from common online testers. A pattern that works in PCRE-focused tools may fail in `OS_Regex` or `OS_Match`. On the other hand, you can use [the original `wazuh-regex` tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-regex.html), which is deployed on Wazuh manager servers under `/var/ossec/bin/` directory. But that requires you to SSH to the servers for simple checks.

This project gives you a local, repeatable way to check behavior before shipping rules.

## Features

- Test all 3 engines from one command.
- Heuristically detect whether the supplied pattern uses OS_Regex, OS_Match, or PCRE2 syntax, mark that engine with `(orig.)`, and show round-trip-validated alternatives whenever the input can be represented safely. Plain, non-empty literals have no detected original engine because they are valid in all three, and are identified as literals in the `Remarks` column. Ambiguous regex syntax continues to default to PCRE2. Conversion warnings also appear in `Remarks` so unavailable equivalent-pattern cells remain empty.
- Case-insensitive emulation for `OS_Regex` and `OS_Match` behavior.
- Highlighted matches and every match span for each engine.
- Captured groups/substring extraction for `OS_Regex` and `PCRE2`.
- Literal handling for OS_Regex characters that are metacharacters only in PCRE2.
- Preserve leading and trailing whitespace on non-empty stdin records. Blank and whitespace-only input records are skipped by the CLI.
- Per-engine validation that distinguishes invalid syntax from a valid non-match.

## Installation

The application requires Python 3.11 or newer, with Python 3.13 recommended. For command-line use -the recommended installation for most users- use [pipx](https://pipx.pypa.io/). It installs the application and its dependencies in an isolated environment while exposing the `wazuhregex` command on your `PATH`:

```bash
pipx install wazuhregex
```

When multiple Python interpreters are installed, select the recommended version explicitly with `pipx install --python python3.13 wazuhregex`.

Upgrade or remove the application without affecting other Python tools:

```bash
pipx upgrade wazuhregex
pipx uninstall wazuhregex
```

pipx can also install the application directly from a local checkout:

```bash
pipx install --editable .
```

Contributors should use a virtual environment and install the test dependencies with `python -m pip install -e ".[test]"`.

To import `wazuhregex` in another Python project, install it into that project's environment with pip. This provides both the library and CLI:

```bash
python -m pip install wazuhregex
```

## CLI usage

After installation, use either the console command or module entry point:

```bash
wazuhregex '<PATTERN>'
python -m wazuhregex '<PATTERN>'
```

Then provide input lines via stdin (interactive typing or piping).

### Help/usage output

```bash
wazuhregex --help
```

The command exits with status 2 when the pattern argument is missing or when more than one positional argument is supplied.

### Example: interactive input

<img class="fit-picture" src="assets/screenshot.png" alt="An example of the CLI tool capturing ssh logs" />

### Example: piped input

```bash
printf '%s\n' 'sshd: error found in log' 'info: all good' | wazuhregex 'error'
```

## Python API

The primary classes are available directly from the package:

```python
from wazuhregex import Engine, RegexComparer, WazuhRegex

tool = WazuhRegex(r"(\d+)")

is_match, spans = tool.os_regex("30 Agustos 2020")
if is_match:
    print(spans)                  # [(0, 2), (11, 15)]
    print(tool.get_substrings())  # ["30", "2020"]

is_match, spans = tool.os_match("Error: disk full")
is_match, spans = tool.pcre2_regex("30 Agustos 2020")

comparer = RegexComparer()
parsed = comparer.parse(r"\d+", Engine.PCRE2)
```

## Running tests

Run all tests:

```bash
python -m pytest
```

Run only the main compatibility suite:

```bash
python -m pytest tests/test_wazuhregex.py
```

The additional `tests/test_engine_edge_cases.py` suite exercises boundary cases that are easy to change accidentally. Known emulator differences are represented as non-strict `xfail` tests. This keeps a compatibility gap visible without making an alpha release claim bit-for-bit equivalence that it does not yet provide.

## Notes on behavior differences

`wazuhregex` is an emulator, not a binding to Wazuh's C implementations. The normal cases are covered heavily by tests adapted from Wazuh's own test suite, but some edge cases can differ and should be treated as compatibility caveats while the project remains alpha.

- `OS_Regex` syntax is translated to PCRE2 before execution. Wazuh's OS_Regex engine deliberately has limited backtracking, whereas the PCRE2 backend can reconsider earlier matches. Expressions that combine several `*` or `+` classes can therefore produce a different result. Wazuh documents `\p*\d*\s*\w*:` as an example where its engine does not backtrack after `\p*` consumes the colon.
- Wazuh's legacy OS_Regex and OS_Match implementations operate on byte strings. The Python API operates on Unicode strings. ASCII case folding and the documented ASCII character classes are emulated, but offsets and captured substrings involving non-ASCII input are Python character offsets and may not correspond to byte offsets returned by native Wazuh code.
- A bare `.` in OS_Regex is a literal dot, while `\.` is the OS_Regex wildcard. PCRE2 uses the opposite convention for the bare dot. The tool preserves that engine difference instead of normalizing the pattern silently. The OS_Regex wildcard translation is forced into scoped DOTALL mode so it also matches newline, as Wazuh's character map does.
- Some OS_Regex validation edge cases are not yet identical to Wazuh. In the current alpha implementation, some unsupported backslash escapes can be treated as quoted literals, nested groups can reach the PCRE2 backend, and the punctuation-class translation has edge cases. Edge-case tests keep these known gaps visible until the emulation is tightened.
- PCRE2 in Wazuh is compiled as an 8-bit expression without Unicode-property options by default. The Python `pcre2` binding operates on Python `str` values and enables Unicode processing internally. Shorthand classes such as `\d`, `\w`, or `\s` can therefore differ for non-ASCII input even when ordinary ASCII cases agree.
- The current `pcre2==0.6.0` Python binding also differs on at least one documented PCRE2 spelling: Wazuh documents both `\xhh` and `\x{hh..}`, but the binding accepts `\x41` while the braced `\x{41}` form is currently retained as an expected compatibility failure in the edge-case suite.
- `OS_Match` is implemented as substring/anchor matching and does not return capture groups. Match spans are a convenience provided by this project, not part of Wazuh's OS_Match API. A successful negated expression has no positive matching substring and therefore returns an empty span list.
- Equivalent-pattern suggestions are intentionally conservative. A missing conversion or an `unknown` comparison means that the tool could not prove a safe equivalence; it does not prove that two expressions behave differently for every possible input.
- The CLI skips blank and whitespace-only stdin records. Leading and trailing whitespace on non-empty records is preserved.

For complex expressions, non-ASCII data, rules that depend on unusual backtracking, or other security-sensitive use, validate the final pattern against the exact Wazuh manager version used in production. A divergence found in practice should become a regression test before the emulator is changed.

## Project status and maintainer policy

This is an independent compatibility tool, not an official Wazuh product. Its results should be checked against the Wazuh version used in production before they are relied upon for security-sensitive rules.

The project is open-source, but upstream development is owner-maintained. You may use, modify, and fork it under the license, but unsolicited pull requests are not accepted. Bug reports and suggestions may be submitted through the issue tracker and will be considered at the maintainer's discretion. There is no commitment to provide support, response times, fixes, or continued maintenance.

## License and third-party material

This project is licensed under the GNU General Public License, version 2 only. See [`LICENSE`](LICENSE) for the full terms and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the origin and licensing of test material and dependencies.

## Building and publishing

Build both the source distribution and wheel, then validate their metadata:

```bash
python -m pip install -e ".[build]"
python -m build
python -m twine check dist/*
```

Releases are published by `.github/workflows/publish.yml` using PyPI trusted publishing (OpenID Connect), so no long-lived API token is stored in GitHub. Before the first release, create a PyPI project or pending trusted publisher for this repository and select `.github/workflows/publish.yml` as its workflow. Publishing is triggered by a published GitHub release and can also be started manually.
