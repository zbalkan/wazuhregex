# wazuhregex

This project provides a high-fidelity Python emulation of Wazuh's `wazuh-regex` tool written in C, that allows checking against three distinct regular expression engines: `OS_Regex`, `sregex` (`OS_Match`), and `PCRE2`. It is designed for developers and security engineers who need to write, test, and validate Wazuh rules with confidence before deploying them.

The project consists of three main components:

1. **`wazuh_regex_lib.py`**: A powerful Python library providing access to emulators for each of Wazuh's regex engines.
2. **`wazuhregex.py` (Wazuh Regex Tester)**: A command-line tool that precisely mimics the output of the original `wazuh-regex` C program, testing a single pattern against all three engines simultaneously.
3. **`test_wazuhregex.py`**: A comprehensive unit test suite, derived from the original Wazuh C tests, to ensure the emulation is accurate and reliable.

## The Problem

Wazuh uses three different regex flavors, two of which (`OS_Regex` and `sregex`) have unique, non-standard syntax and a specific set of limitations. Standard online regex testers (like Regex101) use common engines like PCRE or JavaScript, which do not accurately reflect how a pattern will behave inside a Wazuh ruleset.

A pattern that seems correct in a standard tester might fail silently or behave unexpectedly in Wazuh. This tool suite bridges that gap by providing an environment that faithfully replicates the behavior of all three Wazuh engines.

## Features

* **Three Engines, One Tool**: Test patterns against `OS_Regex`, `sregex`, and `PCRE2` to cover all Wazuh rule types from legacy to modern.
* **High-Fidelity Emulation**: Accurately implements the behavior of the legacy `OS_Regex` and `sregex` engines, including their specific quirks and limitations.
* **Native PCRE2 Power**: Uses the `pcre2` library, the same engine used by Wazuh, for 100% accurate PCRE2 testing.
* **C-Tool Replica (`wazuhregex.py`)**: The command-line tool is designed to behave exactly like the internal `wazuh-regex` C tool, showing which of the three engines successfully match a given pattern.
* **Interactive CLI**: Pipe log files or type log lines directly into the tool for instant feedback.
* **Match Highlighting**: Visually highlights the exact part of the string that matched the pattern.
* **Substring Capture Display**: Clearly lists all substrings captured by `()` groups.

## Installation

1. **Prerequisites**:

  - Python 3.7+
  - PCRE2 library

2. **Clone the repository**:

```bash
git clone <your-repo-url>
cd wazuhregex
```

3. **Dependencies**:

The project requires the `pcre2` C and Python library, as mentioned above. Install it and other development dependencies (like `pytest` for testing) using:

```bash
pip install -r requirements.txt
```

## Usage: The `wazuhregex` Tool

The primary way to use this project is through the `wazuhregex.py` command-line tool. It takes a single pattern as an argument and tests it against all three engines for every line of input it receives.

### Basic Syntax

```bash
./wazuhregex.py '<WAZUH_PATTERN>'
```

**Note**: It is highly recommended to wrap your pattern in single quotes (`'`) to prevent your shell from interpreting special characters like `*`, `|`, or `$`.

### Examples

#### 1. Interactive Testing

Run the tool with a pattern and type or paste log lines directly into the terminal. Press `Ctrl+D` to exit.

**Command:**

```bash
./wazuhregex.py '^(\S+): error'
```

Now, paste this line and press Enter:
`sshd: error found in log`

**Output:**

```plaintext
Pattern compiled successfully. Ready for input.
----------------------------------------

✅ OSRegex Match:
sshd: error found in log
  - Substring: sshd

❌ OSMatch (sregex) No Match

✅ PCRE2 Match:
sshd: error found in log
  - Substring: sshd
```

This output clearly shows that the pattern is valid for the `OS_Regex` and `PCRE2` engines but not for `sregex` (which doesn't understand the `\S` token).

#### 2. Testing a Log File

Pipe a log file into the tool to test the pattern against every line.

```bash
cat /var/log/auth.log | ./wazuhregex.py 'Failed password for (\S+)'
```

#### 3. Testing an Invalid `OS_Regex` Pattern

If you provide a pattern that is invalid for `OS_Regex` (like using alternation in a group), it will correctly show "No Match" for that engine while still succeeding for PCRE2.

**Command:**

```bash
./wazuhregex.py 'invalid(a|b)pattern'
```

**Input:**

`this is an invalid(a|b)pattern`

**Output:**

```plantext
----------------------------------------

❌ OSRegex No Match

❌ OSMatch (sregex) No Match

✅ PCRE2 Match:
this is an invalid(a|b)pattern
  - Substring: a
```

## Library Usage (`wazuh_regex_lib.py`)

For more advanced use cases, you can import the `WazuhRegex` class directly into your own Python projects. It provides a stateless "toolbox" of methods to test patterns against specific engines.

```python
from wazuh_regex_lib import WazuhRegex

pattern = "^(\\d+)"
text = "123-abc"

tester = WazuhRegex(pattern)

# Test against the OS_Regex engine
is_match, spans = tester.os_regex(text)
if is_match:
    print(f"OS_Regex matched! Substrings: {tester.get_substrings()}")

# Test against the PCRE2 engine
is_pcre2_match, _ = tester.pcre2_regex(text)
if is_pcre2_match:
    print("PCRE2 matched!")
```

## Development and Testing

The unit test file `test_wazuhregex.py` contains a comprehensive suite of tests derived directly from the original Wazuh C source code. This ensures that the emulation logic remains accurate.

To run the tests, use `pytest`:

```bash
pytest
```

## Known Emulation Differences

**Backtracking**: The underlying `pcre2` engine used for the `OS_Regex` emulation has a powerful backtracking mechanism. The native Wazuh C engine is a simpler, non-backtracking engine. This means some complex patterns with multiple consecutive greedy quantifiers (e.g., `\p*\d*...`) may succeed in this tool when they would fail in Wazuh. This is a fundamental difference in execution strategy.
