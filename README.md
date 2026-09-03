# wazuhregex

`wazuhregex` is a Python implementation of Wazuh regex behavior for local testing and development.
It lets you validate one pattern against all three Wazuh-relevant engines in one run:

- `OS_Regex`
- `OS_Match` (sregex)
- `PCRE2`

The project includes:

- `src/wazuh_regex_lib.py`: reusable `WazuhRegex` library class.
- `src/wazuhregex.py`: CLI tester with side-by-side engine results.
- `tests/test_wazuhregex.py`: pytest suite that mirrors Wazuh C test coverage.

## Why this exists

Wazuh rules can use regex dialects that differ from common online testers. A pattern that works in PCRE-focused tools may fail in `OS_Regex` or `OS_Match`.

This project gives you a local, repeatable way to check behavior before shipping rules.

## Features

- Test all 3 engines from one command.
- Case-insensitive emulation for `OS_Regex` and `OS_Match` behavior.
- Match spans for each engine.
- Captured groups/substring extraction for `OS_Regex` and `PCRE2`.
- Pattern normalization that accepts fully quoted patterns and rejects unbalanced quotes.
- Lossless stdin handling, including blank records and leading or trailing whitespace.
- Per-engine validation that distinguishes invalid syntax from a valid non-match.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt` (notably `pcre2` and `rich`)

Install dependencies:

```bash
pip install -r requirements.txt
```

## CLI usage

Run either from repository root or from `src/`:

```bash
# from repository root
python src/wazuhregex.py '<PATTERN>'

# or from src/
./wazuhregex.py '<PATTERN>'

# or as a Python module
python -m src.wazuhregex '<PATTERN>'
```

Then provide input lines via stdin (interactive typing or piping).

### Help/usage output

```bash
python src/wazuhregex.py --help
```

### Example: interactive input

Command:

```bash
./wazuhregex.py '^(\S+): error'
```

Input line:

```text
sshd: error found in log
```

Example output (captured from the current CLI):

```text
╭─────────────────────────────────────────────────────── Wazuh Regex Tester ────────────────────────────────────────────────────────╮
│ Pattern: ^(\S+): error                                                                                                            │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ Pattern compiled successfully

sshd: error found in log
               Testing: sshd: error found in log
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Engine          ┃   Result   ┃ Match Span ┃ Captured Groups ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ OS_Regex        │  ✅ Match  │ (0, 11)    │ "sshd"          │
│ OS_Match        │   ❌ No    │ —          │ N/A             │
│                 │   Match    │            │                 │
│ PCRE2           │  ✅ Match  │ (0, 11)    │ "sshd"          │
└─────────────────┴────────────┴────────────┴─────────────────┘
```

### Example: piped input

```bash
printf '%s\n' 'sshd: error found in log' 'info: all good' | python src/wazuhregex.py 'error'
```

## Library usage

```python
from src.wazuh_regex_lib import WazuhRegex

tool = WazuhRegex(r"(\d+)")

# OS_Regex emulation
is_match, spans = tool.os_regex("30 Agustos 2020")
if is_match:
    print(spans)                 # [(0, 2), (11, 15)]
    print(tool.get_substrings()) # ['30', '2020']

# OS_Match emulation
is_match, spans = tool.os_match("Error: disk full")

# Native PCRE2
is_match, spans = tool.pcre2_regex("30 Agustos 2020")
```

## Running tests

Run all tests:

```bash
pytest
```

Run only this package tests:

```bash
pytest tests/test_wazuhregex.py
```

## Notes on behavior differences

- `OS_Regex` emulation translates Wazuh-style tokens before compiling with `pcre2`.
- Because the backend engine supports richer backtracking, edge cases may differ from the original C runtime in some complex patterns.
- `OS_Match` is substring/anchor strategy based and does not return capture groups.
