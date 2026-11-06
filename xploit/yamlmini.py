"""Minimal YAML subset parser (stdlib-only).

PyYAML is not a declared dependency, so YAML OpenAPI specs are parsed
with this small line-based parser instead of a full YAML implementation.
It covers the subset real ``openapi.yaml`` / ``swagger.yaml`` files use:

- block mappings and sequences, keyed by indentation (``- key: value``
  inline map starts included);
- plain, single-quoted and double-quoted scalars, typed like YAML
  (``null`` / ``true`` / ``false`` / ints / floats, else strings);
- flow mappings / sequences (``{url: /api}``, ``[v1, v2]``);
- block scalars (``|`` / ``>`` with ``-`` / ``+`` chomping and an
  optional explicit indent digit);
- full-line and trailing (`` # ...``) comments, blank lines, a leading
  ``---`` marker and multi-line plain-scalar folding.

Anything outside that subset — anchors (``&``), aliases (``*``), tags
(``!``), explicit ``?`` keys, tabs in indentation, multi-document
files, unterminated quotes or flow collections — makes
:func:`parse_yaml_subset` return ``None`` instead of guessing. A spec
the parser cannot prove it understands yields no seeds rather than
wrong seeds, and the caller treats ``None`` exactly like a missing or
broken spec: the crawl continues without it.
"""

from __future__ import annotations

import re

__all__ = ["parse_yaml_subset"]


class _YamlError(ValueError):
    """Raised for any construct outside the supported subset."""


_INT_RE = re.compile(r"^[+-]?[0-9]+$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_OCT_RE = re.compile(r"^0o[0-7]+$")
_FLOAT_RE = re.compile(r"^[+-]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][+-]?[0-9]+)?$")
_BLOCK_SCALAR_RE = re.compile(r"^([|>])(?:([1-9])([-+])?|([-+])([1-9])?)?$")

_DOUBLE_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n",
    "v": "\v", "f": "\f", "r": "\r", "e": "\x1b",
    '"': '"', "/": "/", "\\": "\\", " ": " ",
}


def _typed_scalar(text: str) -> object:
    """YAML core-schema typing for a plain scalar, else the raw string."""
    if text in ("", "~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(text):
        try:
            return int(text)
        except ValueError:
            pass
    if _HEX_RE.match(text):
        try:
            return int(text, 16)
        except ValueError:
            pass
    if _OCT_RE.match(text):
        try:
            return int(text, 8)
        except ValueError:
            pass
    if text in (".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF"):
        return float("inf")
    if text in ("-.inf", "-.Inf", "-.INF"):
        return float("-inf")
    if text in (".nan", ".NaN", ".NAN"):
        return float("nan")
    if _FLOAT_RE.match(text) and any(c in text for c in ".eE"):
        try:
            return float(text)
        except ValueError:
            pass
    return text


def _parse_double_quoted(text: str, pos: int) -> tuple[str, int]:
    """Parse a ``"..."`` scalar starting at ``pos``; return (value, end)."""
    out: list[str] = []
    i = pos + 1
    while i < len(text):
        ch = text[i]
        if ch == '"':
            return "".join(out), i + 1
        if ch == "\\":
            if i + 1 >= len(text):
                raise _YamlError("dangling backslash in double-quoted scalar")
            nxt = text[i + 1]
            if nxt in _DOUBLE_ESCAPES:
                out.append(_DOUBLE_ESCAPES[nxt])
                i += 2
            elif nxt in ("x", "u", "U"):
                width = {"x": 2, "u": 4, "U": 8}[nxt]
                digits = text[i + 2:i + 2 + width]
                if len(digits) != width or not re.match(r"^[0-9a-fA-F]+$", digits):
                    raise _YamlError("bad unicode escape in double-quoted scalar")
                out.append(chr(int(digits, 16)))
                i += 2 + width
            else:
                raise _YamlError(f"unsupported escape \\{nxt}")
        else:
            out.append(ch)
            i += 1
    raise _YamlError("unterminated double-quoted scalar")


def _parse_single_quoted(text: str, pos: int) -> tuple[str, int]:
    """Parse a ``'...'`` scalar starting at ``pos``; return (value, end)."""
    out: list[str] = []
    i = pos + 1
    while i < len(text):
        ch = text[i]
        if ch == "'":
            if i + 1 < len(text) and text[i + 1] == "'":
                out.append("'")
                i += 2
            else:
                return "".join(out), i + 1
        else:
            out.append(ch)
            i += 1
    raise _YamlError("unterminated single-quoted scalar")


def _parse_quoted(text: str, pos: int) -> tuple[str, int]:
    if text[pos] == '"':
        return _parse_double_quoted(text, pos)
    return _parse_single_quoted(text, pos)


def _strip_comment(text: str) -> str:
    """Drop a trailing `` # ...`` comment (outside quotes/flow)."""
    in_single = False
    in_double = False
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth = max(0, depth - 1)
            elif ch == "#" and depth == 0 and i > 0 and text[i - 1] in " \t":
                return text[:i].rstrip()
        i += 1
    return text


def _split_key(text: str) -> tuple[str, str] | None:
    """Split ``key: value`` on the first ``:`` followed by space/EOL.

    The colon is only a separator outside quotes and flow collections,
    so ``/users/{id}:`` splits on its trailing colon while
    ``url: https://api.example.com`` splits after ``url``.
    """
    in_single = False
    in_double = False
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if in_double:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth = max(0, depth - 1)
            elif ch == ":" and depth == 0 and (
                i + 1 == len(text) or text[i + 1] in " \t"
            ):
                return text[:i].strip(), text[i + 1:].strip()
        i += 1
    return None


class _FlowParser:
    """Recursive-descent parser for single-line ``{...}`` / ``[...]``."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def parse(self) -> object:
        value = self._value()
        self._skip_ws()
        if self.i != len(self.text):
            raise _YamlError("trailing characters in flow value")
        return value

    def _skip_ws(self) -> None:
        while self.i < len(self.text) and self.text[self.i] in " \t":
            self.i += 1

    def _value(self) -> object:
        self._skip_ws()
        if self.i >= len(self.text):
            raise _YamlError("empty flow value")
        ch = self.text[self.i]
        if ch == "{":
            return self._mapping()
        if ch == "[":
            return self._sequence()
        if ch in "\"'":
            value, self.i = _parse_quoted(self.text, self.i)
            return value
        if ch in "&*!":
            raise _YamlError("anchors/aliases/tags are not supported")
        return self._plain()

    def _plain(self) -> object:
        # A plain scalar may carry balanced {...}/[...] spans as literal
        # text (OpenAPI URLs are full of ``{version}`` templates), so
        # `,` / `}` / `]` only end the scalar at depth 0. Strict YAML
        # forbids flow indicators in plain scalars; this parser is
        # deliberately more lenient — the value is unambiguous here.
        start = self.i
        depth = 0
        while self.i < len(self.text):
            ch = self.text[self.i]
            if ch in "\"'":
                _value, self.i = _parse_quoted(self.text, self.i)
                continue
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            elif ch == ":" and depth == 0 and (
                self.i + 1 == len(self.text)
                or self.text[self.i + 1] in " ,}]"
            ):
                break
            self.i += 1
        raw = self.text[start:self.i].strip()
        if not raw:
            raise _YamlError("empty plain scalar in flow value")
        return _typed_scalar(raw)

    def _mapping(self) -> dict:
        result: dict = {}
        self.i += 1  # consume "{"
        self._skip_ws()
        if self.i < len(self.text) and self.text[self.i] == "}":
            self.i += 1
            return result
        while True:
            self._skip_ws()
            if self.i >= len(self.text):
                raise _YamlError("unterminated flow mapping")
            ch = self.text[self.i]
            if ch in "\"'":
                key, self.i = _parse_quoted(self.text, self.i)
            elif ch in "&*!?":
                raise _YamlError("unsupported flow mapping key")
            else:
                key = self._plain_key()
            self._skip_ws()
            if self.i >= len(self.text) or self.text[self.i] != ":":
                raise _YamlError("expected ':' in flow mapping")
            self.i += 1
            result[key] = self._value()
            self._skip_ws()
            if self.i >= len(self.text):
                raise _YamlError("unterminated flow mapping")
            if self.text[self.i] == ",":
                self.i += 1
                continue
            if self.text[self.i] == "}":
                self.i += 1
                return result
            raise _YamlError("expected ',' or '}' in flow mapping")

    def _plain_key(self) -> object:
        start = self.i
        while self.i < len(self.text):
            ch = self.text[self.i]
            if ch == ":" and (
                self.i + 1 == len(self.text)
                or self.text[self.i + 1] in " ,}]"
            ):
                break
            if ch in ",}]":
                break
            self.i += 1
        raw = self.text[start:self.i].strip()
        if not raw:
            raise _YamlError("empty flow mapping key")
        return _typed_scalar(raw)

    def _sequence(self) -> list:
        result: list = []
        self.i += 1  # consume "["
        self._skip_ws()
        if self.i < len(self.text) and self.text[self.i] == "]":
            self.i += 1
            return result
        while True:
            result.append(self._value())
            self._skip_ws()
            if self.i >= len(self.text):
                raise _YamlError("unterminated flow sequence")
            if self.text[self.i] == ",":
                self.i += 1
                continue
            if self.text[self.i] == "]":
                self.i += 1
                return result
            raise _YamlError("expected ',' or ']' in flow sequence")


def _parse_key(text: str) -> object:
    if text == "":
        raise _YamlError("empty mapping key")
    if text.startswith(("\"", "'")):
        value, end = _parse_quoted(text, 0)
        if text[end:].strip() != "":
            raise _YamlError("trailing characters after quoted key")
        return value
    if text and text[0] in "{[&*!?":
        raise _YamlError("unsupported mapping key")
    return _typed_scalar(text)


class _BlockParser:
    """Indentation-based parser for block-style YAML documents."""

    def __init__(self, text: str) -> None:
        # Each line is (indent, stripped content, raw line). Blank lines
        # are kept (a block scalar needs them); comment lines are kept
        # too and skipped lazily, so a ``#`` inside a block scalar stays
        # content instead of being stripped as a comment.
        self.lines: list[tuple[int, str, str]] = []
        seen_content = False
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped == "":
                self.lines.append((0, "", raw))
                continue
            if stripped == "---":
                if seen_content:
                    raise _YamlError("multiple documents are not supported")
                continue
            if stripped == "...":
                break
            leading = raw[:len(raw) - len(raw.lstrip())]
            if "\t" in leading:
                raise _YamlError("tab character in indentation")
            indent = len(raw) - len(raw.lstrip(" "))
            if stripped.startswith("#"):
                self.lines.append((indent, stripped, raw))
                continue
            self.lines.append((indent, stripped, raw))
            seen_content = True
        self.i = 0

    def _peek(self) -> tuple[int, str] | None:
        """Next structural line (indent, comment-stripped content)."""
        while self.i < len(self.lines):
            indent, content, _raw = self.lines[self.i]
            if content == "" or content.startswith("#"):
                self.i += 1
                continue
            return indent, _strip_comment(content)
        return None

    def _next(self) -> tuple[int, str]:
        peeked = self._peek()
        if peeked is None:
            raise _YamlError("unexpected end of document")
        self.i += 1
        return peeked

    def _parse_block(self, indent: int) -> object:
        peeked = self._peek()
        if peeked is None:
            return None
        line_indent, content = peeked
        if line_indent < indent:
            return None
        if line_indent > indent:
            raise _YamlError("unexpected indentation")
        if content == "-" or content.startswith("- "):
            return self._parse_sequence(indent)
        if _split_key(content) is not None:
            return self._parse_map(indent)
        # Bare scalar block (e.g. a multi-line plain value under a key).
        _indent, text = self._next()
        return self._parse_inline_value(text, line_indent - 1)

    def _parse_map(
        self, indent: int, first: tuple[int, str] | None = None
    ) -> dict:
        result: dict = {}
        pending = first
        while True:
            if pending is not None:
                line_indent, content = pending
                pending = None
            else:
                peeked = self._peek()
                if peeked is None:
                    break
                line_indent, content = peeked
                if line_indent != indent:
                    break
                if content == "-" or content.startswith("- "):
                    break
                self._next()
            split = _split_key(content)
            if split is None:
                raise _YamlError(f"expected mapping key, got {content!r}")
            key_text, value_text = split
            key = _parse_key(key_text)
            if value_text == "":
                peeked = self._peek()
                if peeked is not None and peeked[0] > indent:
                    value = self._parse_block(peeked[0])
                else:
                    value = None
            else:
                value = self._parse_inline_value(value_text, indent)
            result[key] = value
        return result

    def _parse_sequence(self, indent: int) -> list:
        items: list = []
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            line_indent, content = peeked
            if line_indent != indent:
                break
            if not (content == "-" or content.startswith("- ")):
                break
            self._next()
            after = content[1:].lstrip()
            if after == "":
                peeked = self._peek()
                if peeked is not None and peeked[0] > indent:
                    items.append(self._parse_block(peeked[0]))
                else:
                    items.append(None)
            elif _split_key(after) is not None:
                # Inline map start: the map continues on following lines
                # at the content column (indent of the text after "- ").
                content_indent = line_indent + (len(content) - len(after))
                items.append(
                    self._parse_map(content_indent, first=(content_indent, after))
                )
            else:
                items.append(self._parse_inline_value(after, line_indent))
        return items

    def _parse_inline_value(self, text: str, min_fold_indent: int) -> object:
        """Parse a value written on the same line as its key/item.

        ``min_fold_indent`` is the indent a following line must exceed
        to fold into a plain scalar (the key's indent for map values,
        the dash indent for sequence items, one less than the first
        line's indent for bare scalar blocks).
        """
        if text.startswith(("|", ">")):
            match = _BLOCK_SCALAR_RE.match(text)
            if match is None:
                raise _YamlError(f"bad block scalar header {text!r}")
            return self._read_block_scalar(match, min_fold_indent)
        if text[0] in "{[":
            return _FlowParser(text).parse()
        if text[0] in "\"'":
            value, end = _parse_quoted(text, 0)
            if text[end:].strip() != "":
                raise _YamlError("trailing characters after quoted scalar")
            return value
        if text[0] in "&*!":
            raise _YamlError("anchors/aliases/tags are not supported")
        if text == "?" or text.startswith("? "):
            raise _YamlError("explicit keys are not supported")
        # Plain scalar, folding more-indented following lines with a space
        # (YAML multi-line plain scalar). A deeper line can never start a
        # nested structure here — a non-empty scalar value forbids it.
        parts = [text]
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            line_indent, content = peeked
            if line_indent <= min_fold_indent:
                break
            self._next()
            parts.append(content)
        return _typed_scalar(" ".join(parts))

    def _read_block_scalar(
        self, match: re.Match[str], key_indent: int
    ) -> str:
        style = match.group(1)
        chomp = match.group(3) or match.group(4) or ""
        explicit = match.group(2) or match.group(5)
        block_indent = key_indent + int(explicit) if explicit else None
        collected: list[str] = []
        j = self.i
        while j < len(self.lines):
            indent, content, raw = self.lines[j]
            if content == "":
                collected.append("")
                j += 1
                continue
            if block_indent is None:
                if indent <= key_indent:
                    # No indented content follows: an empty block scalar.
                    break
                block_indent = indent
            if indent < block_indent:
                break
            collected.append(raw[block_indent:] if len(raw) > block_indent else "")
            j += 1
        self.i = j
        while collected and collected[-1] == "":
            collected.pop()
        if not collected:
            return ""
        if style == "|":
            body = "\n".join(collected)
        else:
            parts: list[str] = []
            prev_blank = True
            for line in collected:
                if line == "":
                    parts.append("\n")
                    prev_blank = True
                else:
                    if not prev_blank:
                        parts.append(" ")
                    parts.append(line)
                    prev_blank = False
            body = "".join(parts)
        if chomp == "-":
            return body
        if chomp == "+":
            # Trailing blank lines were popped above; keep the single
            # trailing newline rather than inventing the exact count.
            return body + "\n"
        return body + "\n"


def parse_yaml_subset(text: str) -> dict | None:
    """Parse YAML text into a dict, or ``None`` if it is not a dict or
    uses any construct outside the supported subset (see module docs).
    """
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parser = _BlockParser(text)
        first = parser._peek()
        if first is None:
            return None
        result = parser._parse_block(first[0])
        if parser._peek() is not None:
            return None  # trailing content after the document
        if not isinstance(result, dict):
            return None
        return result
    except _YamlError:
        return None
