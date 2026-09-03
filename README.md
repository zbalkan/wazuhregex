# wazuhregex

[![CI](https://github.com/zbalkan/wazuhregex/actions/workflows/ci.yml/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/dependabot-updates)
[![Dependency Graph](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/dependabot/update-graph)
[![Publish to PyPI](https://github.com/zbalkan/wazuhregex/actions/workflows/publish.yml/badge.svg)](https://github.com/zbalkan/wazuhregex/actions/workflows/publish.yml)

`wazuhregex` is a Python package and command-line tool for testing expressions against the regex behavior used by **Wazuh 4.x**. It lets you validate one pattern against [all three regex engines supported by Wazuh rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html) in one run:

- `OS_Regex`
- `OS_Match` ([sregex](https://github.com/openresty/sregex))
- `PCRE2`

The project includes:

- `src/wazuhregex/`: importable Python package and command-line implementation.
- `wazuhregex`: CLI tester with side-by-side engine results.
- `tests/test_wazuhregex.py`: pytest suite containing behavior adapted from Wazuh's C tests.
- `tests/test_engine_edge_cases.py`: additional Wazuh 4.x engine boundary and edge-case coverage.

## Why this exists

Wazuh rules can use regex engines that differ from common online testers. A pattern that works in a general PCRE-focused tool may fail in `OS_Regex` or `OS_Match`, and generic Python regex behavior is not the compatibility target. You can use [the original `wazuh-regex` tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-regex.html), which is deployed on Wazuh manager servers under `/var/ossec/bin/`, but that requires access to a manager for simple checks.

This project gives you a local, repeatable way to check Wazuh 4.x behavior before shipping rules.

## Features

- Test all 3 Wazuh regex engines from one command.
- Heuristically detect whether the supplied pattern uses OS_Regex, OS_Match, or PCRE2 syntax, mark that engine with `(orig.)`, and show round-trip-validated alternatives whenever the expression can be represented safely. Plain, non-empty literals have no detected original engine because they are valid in all three. Ambiguous regex syntax defaults to PCRE2.
- Case-insensitive emulation for `OS_Regex` and `OS_Match` behavior.
- Highlighted matches and every match span for each engine.
- Captured groups/substring extraction for `OS_Regex` and `PCRE2`.
- Wazuh-specific OS_Regex validation and character classes rather than generic PCRE substitutions.
- Wazuh 4.x PCRE2 defaults, including ASCII shorthand-class behavior unless the pattern explicitly opts into Unicode properties.
- Preserve leading and trailing whitespace on non-empty stdin records. Blank and whitespace-only records are skipped by the CLI.
- Fixed CLI safety limits: at most 20 input lines per run and 100 ms evaluation time per non-empty line.
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

Then provide input lines via stdin (interactive typing or piping). The CLI accepts at most 20 physical input lines per invocation. Each non-empty line is evaluated in an isolated worker with a 100 ms wall-clock limit; if that limit is exceeded, the worker is terminated and recreated before the next line.

### Help/usage output

```bash
wazuhregex --help
```

The help text prints the fixed 20-line and 100 ms limits. The command exits with status 2 for invalid invocation or when input exceeds the 20-line limit.

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

The 100 ms and 20-line limits belong to the CLI. The direct Python methods remain ordinary library calls.

## Running tests

Run all tests:

```bash
python -m pytest
```

Run the main compatibility suite:

```bash
python -m pytest tests/test_wazuhregex.py
```

The `tests/test_engine_edge_cases.py` suite protects additional boundary behavior that is easy to change accidentally. Tests use Wazuh 4.x behavior as the oracle where it is documented or represented in the Wazuh source/tests; Python-wrapper behavior is not accepted merely because the backend happens to provide it.

## Compatibility caveats

The target is Wazuh 4.x, but `wazuhregex` is an emulator rather than a Python binding to Wazuh's C implementations. Known limitations should therefore be treated narrowly rather than as alternate semantics:

- `OS_Regex` is translated to PCRE2 for execution. Wazuh's native OS_Regex engine deliberately has limited backtracking, whereas PCRE2 can reconsider earlier matches. Complex expressions combining several `*` or `+` classes can therefore diverge. Wazuh itself documents this class of difference, including the `\p*\d*\s*\w*:` example where the native engine does not backtrack after `\p*` consumes the colon.
- Wazuh's legacy OS_Regex and OS_Match implementations operate on byte strings. The Python API uses Unicode strings. The documented ASCII character classes and ASCII case folding are emulated, but spans and captured substrings involving non-ASCII data are Python character offsets rather than native Wazuh byte offsets.
- Wazuh's PCRE2 rule path uses the 8-bit library with default compile options. The Python `pcre2` binding forces UTF processing for Python `str`. The tool compensates for known observable differences such as UCP defaults, `\x` forms, and `\C`, but unusual non-ASCII code-unit behavior can still differ from native Wazuh PCRE2.
- `OS_Match` match spans are a convenience provided by this project, not part of Wazuh's OS_Match API. A successful negated expression has no positive matching substring and therefore returns an empty span list.
- Equivalent-pattern suggestions are intentionally conservative. A missing conversion or an `unknown` comparison means the tool could not prove a safe equivalence; it does not prove the expressions differ for every possible input.

For complex expressions, non-ASCII data, rules that depend on unusual backtracking, or other security-sensitive use, validate the final pattern against the exact Wazuh 4.x manager version used in production. A confirmed divergence should become a regression test before the emulator is changed.

## Project status and maintainer policy

This is an independent compatibility tool, not an official Wazuh product. Version 0.2.0 remains alpha while compatibility coverage is expanded and tested against real Wazuh usage.

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

Publishing is manual. Start `.github/workflows/publish.yml` with `workflow_dispatch` from `main`. The workflow reads the version from `pyproject.toml`, creates `v<version>` on the dispatched commit (or verifies that the existing tag already points there), builds and smoke-tests the package, and publishes it through PyPI trusted publishing. No long-lived PyPI token or manually created release tag is required.
