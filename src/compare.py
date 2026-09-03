"""Conservative semantic comparison and conversion for Wazuh regex engines."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Iterator, TypeAlias


class Engine(StrEnum):
    PCRE2 = "pcre2"
    OSREGEX = "osregex"
    SREGEX = "sregex"

    @classmethod
    def coerce(cls, value: "Engine | str") -> "Engine":
        if isinstance(value, cls):
            return value
        aliases = {"regex": cls.OSREGEX, "os_regex": cls.OSREGEX,
                   "osregex": cls.OSREGEX, "osmatch": cls.SREGEX,
                   "os_match": cls.SREGEX, "sregex": cls.SREGEX,
                   "pcre": cls.PCRE2, "pcre2": cls.PCRE2}
        try:
            return aliases[value.lower()]
        except KeyError:
            raise ValueError(f"unsupported regex engine: {value!r}") from None


class Relation(StrEnum):
    EQUIVALENT = "equivalent"
    SUBSET = "subset"
    SUPERSET = "superset"
    OVERLAPPING = "overlapping"
    DISJOINT = "disjoint"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Literal:
    value: str


@dataclass(frozen=True, slots=True)
class CharSet:
    chars: frozenset[str]
    negated: bool = False


@dataclass(frozen=True, slots=True)
class AnyChar:
    except_newline: bool = True


@dataclass(frozen=True, slots=True)
class Sequence:
    items: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Choice:
    items: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Repeat:
    item: "Node"
    minimum: int
    maximum: int | None


@dataclass(frozen=True, slots=True)
class Anchor:
    kind: str


@dataclass(frozen=True, slots=True)
class Unsupported:
    feature: str
    source: str


Node: TypeAlias = Literal | CharSet | AnyChar | Sequence | Choice | Repeat | Anchor | Unsupported


@dataclass(frozen=True, slots=True)
class Pattern:
    source: str
    engine: Engine
    ast: Node


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    relation: Relation
    left: Pattern
    right: Pattern
    reason: str


@dataclass(frozen=True, slots=True)
class ConversionResult:
    target: Engine
    supported: bool
    pattern: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Alternative:
    engine: Engine
    pattern: str


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    fingerprint: str
    members: tuple[Pattern, ...]


_WORD_OS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-@_")
_DIGITS = frozenset("0123456789")
_SPACE = frozenset(" ")
_TAB = frozenset("\t")
_PUNCT_OS = frozenset("()*+, -.:;<=>?[]!\"'#$%&|{}")
_PCRE_SPACE = frozenset("\t\r\n\f ")
_ASCII_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


class RegexSyntaxError(ValueError):
    pass


def _split(source: str) -> list[str]:
    parts, start, depth, in_class, escaped = [], 0, 0, False, False
    for i, ch in enumerate(source):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_class:
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "|" and depth == 0:
            parts.append(source[start:i])
            start = i + 1
    parts.append(source[start:])
    return parts


def _seq(items: list[Node] | tuple[Node, ...]) -> Node:
    values = tuple(items)
    return Sequence(()) if not values else values[0] if len(values) == 1 else Sequence(values)


def _matching(source: str, start: int, opening="(", closing=")") -> int | None:
    depth, escaped = 0, False
    for i in range(start, len(source)):
        ch = source[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return i
    return None


def _parse_sregex(source: str) -> Node:
    if source.startswith("!"):
        return Unsupported("sregex-negation", source)
    branches: list[str] = _split(source)
    if len(branches) > 1:
        return Choice(tuple(_parse_sregex(x) for x in branches))
    items: list[Node] = []
    if source.startswith("^"):
        items.append(Anchor("start"))
        source = source[1:]
    if source.endswith("$"):
        source = source[:-1]
        end = True
    else:
        end = False
    if source:
        items.append(Literal(source))
    if end:
        items.append(Anchor("end"))
    return _seq(items)


def _parse_osregex(source: str) -> Node:
    branches: list[str] = _split(source)
    if len(branches) > 1:
        return Choice(tuple(_parse_osregex(x) for x in branches))
    mapping = {"w": CharSet(_WORD_OS), "d": CharSet(_DIGITS), "s": CharSet(_SPACE),
               "t": CharSet(_TAB), "p": CharSet(_PUNCT_OS), "W": CharSet(_WORD_OS, True),
               "D": CharSet(_DIGITS, True), "S": CharSet(_SPACE, True), ".": AnyChar(False)}
    items: list[Node] = []
    literal: list[str] = []
    i = 0

    def flush() -> None:
        if literal:
            items.append(Literal("".join(literal)))
            literal.clear()
    while i < len(source):
        ch = source[i]
        if ch == "^" and i == 0:
            flush()
            items.append(Anchor("start"))
            i += 1
        elif ch == "$" and i == len(source)-1:
            flush()
            items.append(Anchor("end"))
            i += 1
        elif ch == "\\":
            flush()
            if i+1 >= len(source):
                raise RegexSyntaxError("trailing backslash")
            node = mapping.get(source[i+1], Literal(source[i+1]))
            i += 2
            if i < len(source) and source[i] in "*+":
                node = Repeat(node, 0 if source[i] == "*" else 1, None)
                i += 1
            items.append(node)
        elif ch in "*+":
            return Unsupported("osregex-bare-quantifier", source)
        elif ch == "(":
            flush()
            end = _matching(source, i)
            if end is None:
                raise RegexSyntaxError("unbalanced parenthesis")
            inner = source[i+1:end]
            if len(_split(inner)) > 1:
                return Unsupported("osregex-grouped-alternation", source)
            items.append(_parse_osregex(inner))
            i = end + 1
        else:
            literal.append(ch)
            i += 1
    flush()
    return _seq(items)


def _quant(node: Node, source: str, i: int) -> tuple[Node, int]:
    if i >= len(source) or source[i] not in "*+?{":
        return node, i
    if source[i] == "*":
        return Repeat(node, 0, None), i+1
    if source[i] == "+":
        return Repeat(node, 1, None), i+1
    if source[i] == "?":
        return Repeat(node, 0, 1), i+1
    end = source.find("}", i+1)
    if end < 0:
        raise RegexSyntaxError("unterminated bounded quantifier")
    spec = source[i+1:end]
    try:
        if ", " not in spec:
            minimum = maximum = int(spec)
        else:
            left, right = spec.split(", ", 1)
            minimum = int(left)
            maximum: int | None = int(right) if right else None
    except ValueError:
        return Unsupported("pcre2-invalid-quantifier", source), end+1
    return Repeat(node, minimum, maximum), end+1


def _parse_class(body: str) -> Node:
    negated = body.startswith("^")
    body = body[1:] if negated else body
    chars: set[str] = set()
    i = 0
    classes = {"d": _DIGITS, "s": _PCRE_SPACE, "w": _ASCII_WORD}
    while i < len(body):
        if i+2 < len(body) and body[i+1] == "-":
            if ord(body[i+2]) < ord(body[i]):
                return Unsupported("pcre2-descending-range", body)
            chars.update(map(chr, range(ord(body[i]), ord(body[i+2])+1)))
            i += 3
        elif body[i] == "\\" and i+1 < len(body):
            chars.update(classes.get(body[i+1], frozenset(body[i+1])))
            i += 2
        else:
            chars.add(body[i])
            i += 1
    return CharSet(frozenset(chars), negated)


def _parse_pcre2(source: str) -> Node:
    advanced = [(r"\\[1-9]", "backreference"), (r"\(\?<([=!])", "lookbehind"),
                (r"\(\?[=!]", "lookahead"), (r"\(\?>", "atomic-group")]
    for expression, name in advanced:
        if re.search(expression, source):
            return Unsupported("pcre2-"+name, source)
    branches = _split(source)
    if len(branches) > 1:
        return Choice(tuple(_parse_pcre2(x) for x in branches))
    mapping = {"d": CharSet(_DIGITS), "D": CharSet(_DIGITS, True), "s": CharSet(_PCRE_SPACE),
               "S": CharSet(_PCRE_SPACE, True), "w": CharSet(_ASCII_WORD), "W": CharSet(_ASCII_WORD, True),
               "t": Literal("\t"), "r": Literal("\r"), "n": Literal("\n"), "f": Literal("\f")}
    items: list[Node] = []
    literal: list[str] = []
    i = 0

    def flush() -> None:
        if literal:
            items.append(Literal("".join(literal)))
            literal.clear()
    while i < len(source):
        ch = source[i]
        if ch == "^" and i == 0:
            flush()
            items.append(Anchor("start"))
            i += 1
        elif ch == "$" and i == len(source)-1:
            flush()
            items.append(Anchor("end"))
            i += 1
        elif ch == "\\":
            flush()
            if i+1 >= len(source):
                raise RegexSyntaxError("trailing backslash")
            node = mapping.get(source[i+1], Literal(source[i+1]))
            i += 2
            node, i = _quant(node, source, i)
            items.append(node)
        elif ch == ".":
            flush()
            node, i = _quant(AnyChar(), source, i+1)
            items.append(node)
        elif ch == "[":
            flush()
            end = _matching(source, i, "[", "]")
            if end is None:
                raise RegexSyntaxError("unterminated character class")
            node, i = _quant(_parse_class(source[i+1:end]), source, end+1)
            items.append(node)
        elif ch == "(":
            flush()
            end = _matching(source, i)
            if end is None:
                raise RegexSyntaxError("unbalanced parenthesis")
            start = i+3 if source.startswith("(?:", i) else i+1
            if source.startswith("(?", i) and start == i+1:
                return Unsupported("pcre2-special-group", source)
            node, i = _quant(_parse_pcre2(source[start:end]), source, end+1)
            items.append(node)
        elif ch in "*+?{":
            return Unsupported("pcre2-orphan-quantifier", source)
        else:
            literal.append(ch)
            i += 1
            if i < len(source) and source[i] in "*+?{":
                last = literal.pop()
                flush()
                node, i = _quant(Literal(last), source, i)
                items.append(node)
    flush()
    return _seq(items)


_PARSERS = {Engine.PCRE2: _parse_pcre2, Engine.OSREGEX: _parse_osregex, Engine.SREGEX: _parse_sregex}


def detect_engine(source: str) -> Engine:
    """Guess the engine whose spelling the user supplied.

    There is deliberately no attempt to claim certainty here: most literal
    expressions, anchors, and several character classes are valid in more
    than one Wazuh engine. Prefer the literal-oriented SRegex engine for a
    non-empty literal and PCRE2 for remaining ambiguous regex syntax.
    """
    if not isinstance(source, str):
        raise TypeError("pattern must be a string")

    # A leading bang is the OS_Match negation operator. In the other engines
    # it is merely a literal, making this the only strong SRegex signal.
    if source.startswith("!"):
        return Engine.SREGEX

    # OS_Regex's punctuation class and escaped-dot wildcard are characteristic
    # Wazuh spellings. PCRE2 gives ``\.`` the opposite (literal-dot) meaning,
    # so recognizing it is particularly important when producing alternatives.
    escaped = False
    for character in source:
        if escaped:
            if character in ("p", "."):
                return Engine.OSREGEX
            escaped = False
        elif character == "\\":
            escaped = True

    # A pattern with no regex operators is most naturally an OS_Match literal.
    # Keep the empty pattern on the PCRE2 fallback because it provides no
    # positive evidence for any engine.
    regex_syntax = frozenset(r"\.^$*+?{}[]()|")
    if source and not any(character in regex_syntax for character in source):
        return Engine.SREGEX

    return Engine.PCRE2


def parse(source: str, engine: Engine | str) -> Pattern:
    d = Engine.coerce(engine)
    return Pattern(source, d, _PARSERS[d](source))


def walk(node: Node) -> Iterator[Node]:
    yield node
    if isinstance(node, (Sequence, Choice)):
        for item in node.items:
            yield from walk(item)
    elif isinstance(node, Repeat):
        yield from walk(node.item)


def canonicalize(node: Node) -> Node:
    if isinstance(node, Sequence):
        flat: list[Node] = []
        for value in map(canonicalize, node.items):
            flat.extend(value.items if isinstance(value, Sequence) else (value, ))
        merged: list[Node] = []
        for value in flat:
            if isinstance(value, Literal) and merged and isinstance(merged[-1], Literal):
                merged[-1] = Literal(merged[-1].value + value.value)
            else:
                merged.append(value)
        return _seq(merged)
    if isinstance(node, Choice):
        values: list[Node] = []
        for value in map(canonicalize, node.items):
            values.extend(value.items if isinstance(value, Choice) else (value, ))
        unique = {semantic_key(x): x for x in values}
        ordered = tuple(unique[k] for k in sorted(unique))
        return ordered[0] if len(ordered) == 1 else Choice(ordered)
    if isinstance(node, Repeat):
        item = canonicalize(node.item)
        if node.minimum == node.maximum == 1:
            return item
        if node.minimum == node.maximum == 0:
            return Sequence(())
        if node.minimum == node.maximum and node.minimum <= 32:
            return canonicalize(Sequence((item, ) * node.minimum))
        return Repeat(item, node.minimum, node.maximum)
    return node


def _jsonable(node: Node):
    if isinstance(node, Literal):
        return ["lit", node.value]
    if isinstance(node, CharSet):
        return ["set", node.negated, sorted(map(ord, node.chars))]
    if isinstance(node, AnyChar):
        return ["any", node.except_newline]
    if isinstance(node, Sequence):
        return ["seq", list(map(_jsonable, node.items))]
    if isinstance(node, Choice):
        return ["choice", list(map(_jsonable, node.items))]
    if isinstance(node, Repeat):
        return ["repeat", node.minimum, node.maximum, _jsonable(node.item)]
    if isinstance(node, Anchor):
        return ["anchor", node.kind]
    if isinstance(node, Unsupported):
        return ["unsupported", node.feature, node.source]
    raise TypeError(node)


def semantic_key(node: Node) -> str:
    return json.dumps(_jsonable(node), separators=(", ", ":"), ensure_ascii=False)


def _coerce(pattern: Pattern | str, engine: Engine | str | None) -> Pattern:
    if isinstance(pattern, Pattern):
        return pattern
    if engine is None:
        raise TypeError("engine is required for raw pattern strings")
    return parse(pattern, engine)


def fingerprint(pattern: Pattern | str, engine: Engine | str | None = None) -> str:
    return hashlib.sha256(semantic_key(canonicalize(_coerce(pattern, engine).ast)).encode()).hexdigest()


def _unsupported(node: Node) -> bool: return any(isinstance(x, Unsupported) for x in walk(node))


def compare(left, left_engine=None, right=None, right_engine=None) -> ComparisonResult:
    if isinstance(left, Pattern) and isinstance(left_engine, Pattern) and right is None:
        lp, rp = left, left_engine
    else:
        if right is None:
            raise TypeError("right pattern is required")
        lp, rp = _coerce(left, left_engine), _coerce(right, right_engine)
    a, b = canonicalize(lp.ast), canonicalize(rp.ast)
    relation = Relation.UNKNOWN if _unsupported(a) or _unsupported(b) else Relation.EQUIVALENT if a == b else Relation.UNKNOWN
    return ComparisonResult(relation, lp, rp, "canonical ASTs are identical" if relation == Relation.EQUIVALENT else "no safe proof")


def equivalent(*args, **kwargs) -> bool: return compare(*args, **kwargs).relation == Relation.EQUIVALENT


def _escape_pcre(value: str) -> str: return re.sub(r'([\\.^$|?*+(){}\[\]])', r'\\\1', value)


def _class_char(ch: str) -> str: return {"\t": r"\t", "\r": r"\r", "\n": r"\n", "\f": r"\f"}.get(ch, "\\"+ch if ch in r"\]-^" else ch)


def _emit_pcre(node: Node) -> str:
    if isinstance(node, Literal):
        return _escape_pcre(node.value)
    if isinstance(node, CharSet):
        shortcuts = {(_DIGITS, False): r"\d", (_ASCII_WORD, False): r"\w", (_PCRE_SPACE, False): r"\s"}
        return shortcuts.get((node.chars, node.negated), "["+("^" if node.negated else "")+"".join(map(_class_char, sorted(node.chars)))+"]")
    if isinstance(node, AnyChar):
        return "." if node.except_newline else r"(?s:.)"
    if isinstance(node, Anchor):
        return "^" if node.kind == "start" else "$"
    if isinstance(node, Sequence):
        return "".join(map(_emit_pcre, node.items))
    if isinstance(node, Choice):
        return "|".join(map(_emit_pcre, node.items))
    if isinstance(node, Repeat):
        base = _emit_pcre(node.item)
        base = base if isinstance(node.item, (CharSet, AnyChar)) or isinstance(node.item, Literal) and len(node.item.value) == 1 else f"(?:{base})"
        q = "*" if (node.minimum, node.maximum) == (0, None) else "+" if (node.minimum, node.maximum) == (1, None) else "?" if (node.minimum, node.maximum) == (0, 1) else "{"+str(node.minimum)+("" if node.maximum == node.minimum else ", "+("" if node.maximum is None else str(node.maximum)))+"}"
        return base+q
    raise ValueError("unsupported AST cannot be emitted exactly")


def _emit_os(node: Node) -> str:
    if isinstance(node, Literal):
        if any(x in node.value for x in "^*+"):
            raise ValueError("OS_Regex cannot represent literal ^, * or + exactly")
        return "".join(("\\" if x in "$()\\|<" else "")+x for x in node.value)
    classes: dict[tuple[frozenset[str], bool], str] = {(_WORD_OS, False): r"\w", (_DIGITS, False): r"\d", (_SPACE, False): r"\s", (_TAB, False): r"\t", (_PUNCT_OS, False): r"\p", (_WORD_OS, True): r"\W", (_DIGITS, True): r"\D", (_SPACE, True): r"\S"}
    if isinstance(node, CharSet) and (node.chars, node.negated) in classes:
        return classes[(node.chars, node.negated)]
    if isinstance(node, AnyChar) and not node.except_newline:
        return r"\."
    if isinstance(node, Anchor):
        return "^" if node.kind == "start" else "$"
    if isinstance(node, Sequence):
        return "".join(map(_emit_os, node.items))
    if isinstance(node, Choice):
        return "|".join(map(_emit_os, node.items))
    if isinstance(node, Repeat):
        base = _emit_os(node.item)
        if len(base) == 2 and base.startswith("\\") and (node.minimum, node.maximum) in ((0, None), (1, None)):
            return base+("*" if node.minimum == 0 else "+")
        if node.minimum == node.maximum and node.minimum <= 32:
            return base*node.minimum
        raise ValueError("OS_Regex cannot represent this repetition exactly")
    raise ValueError(f"OS_Regex cannot represent node exactly: {node!r}")


def _emit_s(node: Node) -> str:
    if isinstance(node, Literal):
        if "|" in node.value:
            raise ValueError("SRegex literal pipe is not representable safely")
        return node.value
    if isinstance(node, Anchor):
        return "^" if node.kind == "start" else "$"
    if isinstance(node, Sequence):
        return "".join(map(_emit_s, node.items))
    if isinstance(node, Choice):
        return "|".join(map(_emit_s, node.items))
    raise ValueError(f"SRegex cannot represent node exactly: {node!r}")


_EMITTERS = {Engine.PCRE2: _emit_pcre, Engine.OSREGEX: _emit_os, Engine.SREGEX: _emit_s}


def convert(pattern, source=None, target=None) -> ConversionResult:
    if target is None:
        raise TypeError("target engine is required")
    p, d = _coerce(pattern, source), Engine.coerce(target)
    node = canonicalize(p.ast)
    if _unsupported(node):
        return ConversionResult(d, False, reason="source contains unsupported construct")
    try:
        text = _EMITTERS[d](node)
    except ValueError as error:
        return ConversionResult(d, False, reason=str(error))
    if canonicalize(parse(text, d).ast) != node:
        return ConversionResult(d, False, reason="round-trip semantic validation failed")
    return ConversionResult(d, True, text)


def alternatives(pattern, engine=None) -> tuple[Alternative, ...]:
    p = _coerce(pattern, engine)
    output = []
    for target in Engine:
        if target != p.engine:
            result = convert(p, target=target)
            if result.supported and result.pattern is not None:
                output.append(Alternative(target, result.pattern))
    return tuple(output)


def find_duplicates(patterns: Iterable[Pattern | tuple[str, Engine | str]]) -> tuple[DuplicateGroup, ...]:
    buckets = defaultdict(list)
    for value in patterns:
        p = value if isinstance(value, Pattern) else parse(*value)
        if not _unsupported(p.ast):
            buckets[fingerprint(p)].append(p)
    return tuple(DuplicateGroup(k, tuple(v)) for k, v in sorted(buckets.items()) if len(v) > 1)


class RegexComparer:
    """State-free facade over regex parsing, comparison, and conversion."""
    parse = staticmethod(parse)
    detect_engine = staticmethod(detect_engine)
    compare = staticmethod(compare)
    equivalent = staticmethod(equivalent)
    fingerprint = staticmethod(fingerprint)
    convert = staticmethod(convert)
    alternatives = staticmethod(alternatives)
    find_duplicates = staticmethod(find_duplicates)

    def canonicalize(self, pattern, engine=None):
        return canonicalize(_coerce(pattern, engine).ast)
