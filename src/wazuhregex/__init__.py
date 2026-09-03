"""Public API for testing expressions with Wazuh-compatible regex engines."""

from .compare import (
    Alternative,
    ComparisonResult,
    ConversionResult,
    DuplicateGroup,
    Engine,
    Pattern,
    RegexComparer,
    Relation,
)
from .wazuh_regex_lib import WazuhRegex

__all__ = [
    "Alternative",
    "ComparisonResult",
    "ConversionResult",
    "DuplicateGroup",
    "Engine",
    "Pattern",
    "RegexComparer",
    "Relation",
    "WazuhRegex",
]
