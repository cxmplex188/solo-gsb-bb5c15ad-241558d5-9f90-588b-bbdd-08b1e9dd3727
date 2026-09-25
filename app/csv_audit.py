"""CSV cell formula-spoofing auditing.

A position-tracking parser for RFC 4180 CSV (comma-separated fields,
double-quote enclosure, doubled-quote escaping, CRLF record breaks)
splits raw CSV text into records without losing positions: line breaks
inside quoted fields, escaped quotes and empty cells never shift record
or field numbering.

Every cell is then inspected for *formula injection* (CVE-2014-3524 /
CSV formula spoofing): after skipping leading spaces, tabs and Unicode
bidirectional control characters, a cell whose first character is one
of ``=`` ``+`` ``-`` ``@`` is reported.  The same bidi parser used by
the other auditors additionally assigns the cell a risk level, which
catacks that hide the formula trigger behind bidi controls (Trojan
Source style).

The audit is read-only and the original text is never modified.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from .bidi import BIDI_ABBREVIATIONS, BIDI_CODEPOINTS, parse_bidi
from .diff_audit import highest_risk

# Characters that spreadsheet software treats as a formula trigger when
# they are the first non-ignored character of a cell.
FORMULA_TRIGGERS = frozenset("=+-@")

# Characters ignored before the formula trigger: ordinary ASCII space /
# horizontal tab plus every recognised Unicode bidi control.
_SKIP_CODEPOINTS: frozenset[int] = frozenset({0x20, 0x09}) | BIDI_CODEPOINTS


class CsvParseError(ValueError):
    """The CSV text violates RFC 4180 quoting rules.

    ``offset`` is the 0-based code-point offset in the original text
    where the problem was detected; ``line`` / ``column`` are the
    corresponding 1-based position in the original text.
    """

    def __init__(self, offset: int, line: int, column: int, message: str):
        super().__init__(f"line {line}, column {column}: {message}")
        self.offset = offset
        self.line = line
        self.column = column
        self.message = message


# ---------------------------------------------------------------------------
# Parsed model
# ---------------------------------------------------------------------------

@dataclass
class CsvCell:
    value: str                    # decoded cell content (quotes unescaped)
    start: int                    # raw offset of the first cell character
    end: int                      # raw offset just past the last cell char
    quoted: bool                 # whether the cell was double-quote enclosed
    # Raw offset of the source unit each decoded character came from: a
    # plain character maps to itself; a character produced by a doubled
    # quote ("" -> ") maps to the first quote of the pair.  Length equals
    # ``len(value)``, so every decoded position maps back to the raw text.
    char_offsets: list[int] = field(default_factory=list)


@dataclass
class CsvRecord:
    cells: list[CsvCell]
    start: int                    # raw offset of the record's first cell
    start_line: int               # 1-based raw line of the record's start


class _LineIndex:
    """Precomputed line-start offsets for O(log n) line/column lookups."""

    def __init__(self, text: str):
        starts = [0]
        for i, ch in enumerate(text):
            # Every raw newline (including line breaks inside quoted
            # fields) starts a new visual line in the original text.
            if ch == "\n":
                starts.append(i + 1)
        self._starts = starts

    def line_col(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset)
        column = offset - self._starts[line - 1] + 1
        return line, column


# ---------------------------------------------------------------------------
# Parser (RFC 4180, strict quoting, CRLF record separators)
# ---------------------------------------------------------------------------

def parse_csv(text: str) -> list[CsvRecord]:
    """Parse raw CSV ``text`` into records.

    Quoting rules are enforced strictly: a double quote is only legal at
    the very beginning of a field or, inside a quoted field, doubled as
    an escape.  Record separators outside quoted fields must be CRLF; a
    bare CR or LF there is rejected.  Any violation raises
    :class:`CsvParseError` with the offending position in the original
    text.
    """
    n = len(text)
    index = _LineIndex(text)
    records: list[CsvRecord] = []

    def error(offset: int, message: str) -> None:
        line, column = index.line_col(offset)
        raise CsvParseError(offset, line, column, message)

    i = 0
    while i < n:
        record_start = i
        record_start_line, _ = index.line_col(i)
        cells: list[CsvCell] = []
        while True:
            cell, i = _parse_field(text, i, index, error)
            cells.append(cell)
            if i < n and text[i] == ",":
                i += 1
                continue
            # The only legal field terminator besides a comma is CRLF
            # (ending the record) or end of text.
            if i < n:
                if text[i] == "\r" and i + 1 < n and text[i + 1] == "\n":
                    i += 2
                elif text[i] == "\r":
                    error(i, "bare CR outside quoted field: CSV records "
                             "must be separated by CRLF")
                elif text[i] == "\n":
                    error(i, "bare LF outside quoted field: CSV records "
                             "must be separated by CRLF")
                else:  # pragma: no cover - _parse_field leaves only , \r
                    error(i, f"unexpected character {text[i]!r} after field")
            break
        records.append(CsvRecord(cells, record_start, record_start_line))
    return records


def _parse_field(text, start, index, error) -> tuple[CsvCell, int]:
    n = len(text)
    i = start
    if i < n and text[i] == '"':
        return _parse_quoted_field(text, i, index, error)

    # Unquoted field: runs until comma, CR or end of text.  A quote here
    # is illegal (RFC 4180 allows quotes only as the first character),
    # and a bare LF is not a record separator.
    chars: list[str] = []
    offsets: list[int] = []
    while i < n:
        ch = text[i]
        if ch == "," or ch == "\r":
            break
        if ch == '"':
            error(i, "unescaped double quote in unquoted field: fields "
                     "containing '\"' must be enclosed in double quotes")
        if ch == "\n":
            error(i, "bare LF outside quoted field: CSV records must be "
                     "separated by CRLF")
        chars.append(ch)
        offsets.append(i)
        i += 1
    return CsvCell("".join(chars), start, i, False, offsets), i


def _parse_quoted_field(text, start, index, error) -> tuple[CsvCell, int]:
    n = len(text)
    i = start + 1  # opening quote
    chars: list[str] = []
    offsets: list[int] = []
    while True:
        if i >= n:
            error(start, "unterminated quoted field: opening double quote "
                         "is never closed")
        ch = text[i]
        if ch == '"':
            # Doubled quote -> literal quote; otherwise the field ends.
            if i + 1 < n and text[i + 1] == '"':
                chars.append('"')
                offsets.append(i)
                i += 2
                continue
            i += 1  # consume the closing quote
            break
        # Any other character (including commas, CR/LF of any kind) is
        # literal field content, so quoted line breaks cannot disturb
        # record or field numbering.
        chars.append(ch)
        offsets.append(i)
        i += 1

    # After the closing quote only a comma, CRLF or end of text may
    # follow; anything else (a doubled-quote escape included) is invalid.
    if i < n and text[i] not in (",", "\r"):
        error(i, f"unexpected character {text[i]!r} after closing quote: "
                 "a quoted field must be followed by ',', CRLF or end of "
                 "text (use \"\" for a literal quote)")
    if i < n and text[i] == "\r" and (i + 1 >= n or text[i + 1] != "\n"):
        error(i, "bare CR outside quoted field: CSV records must be "
                 "separated by CRLF")
    return CsvCell("".join(chars), start, i, True, offsets), i


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dataclass
class FormulaFinding:
    record_no: int          # 1-based record number
    field_no: int           # 1-based field number within the record
    line: int               # position of the formula trigger in raw text
    column: int
    trigger: str            # formula-starting character (=, +, - or @)
    prefix: list[dict]      # ignored chars before the trigger
    cell_start_line: int    # raw line where the cell starts
    cell_start_column: int
    cell_end_line: int
    cell_end_column: int
    risk_level: str
    result: dict            # full bidi parse result of the decoded cell

    def to_dict(self) -> dict:
        return {
            "record_no": self.record_no,
            "field_no": self.field_no,
            "position": {"line": self.line, "column": self.column},
            "trigger": self.trigger,
            "prefix_control_chars": self.prefix,
            "cell_position": {
                "start": {"line": self.cell_start_line,
                          "column": self.cell_start_column},
                "end": {"line": self.cell_end_line,
                        "column": self.cell_end_column},
            },
            "risk_level": self.risk_level,
            "result": self.result,
        }


def _prefix_entry(ch: str, raw_offset: int,
                  index: _LineIndex) -> dict:
    cp = ord(ch)
    abbr = BIDI_ABBREVIATIONS.get(cp)
    line, column = index.line_col(raw_offset)
    if abbr is not None:
        kind = f"bidi:{abbr}"
    elif ch == " ":
        kind = "space"
    else:
        kind = "tab"
    return {
        "char": ch,
        "codepoint": f"U+{cp:04X}",
        "kind": kind,
        "offset": raw_offset,
        "position": {"line": line, "column": column},
    }


def audit_csv(csv_text: str) -> dict:
    """Parse and audit raw CSV text.  Raises :class:`CsvParseError` on
    any RFC 4180 quoting/line-break violation; otherwise returns the
    audit report.  Nothing is persisted or modified."""
    records = parse_csv(csv_text)
    index = _LineIndex(csv_text)

    findings: list[FormulaFinding] = []
    record_summaries: list[dict] = []
    total_cells = 0

    for record_no, record in enumerate(records, start=1):
        total_cells += len(record.cells)
        record_summaries.append({
            "record_no": record_no,
            "field_count": len(record.cells),
            "start_line": record.start_line,
        })
        for field_no, cell in enumerate(record.cells, start=1):
            value = cell.value
            # Skip leading spaces, tabs and bidi controls.
            pos = 0
            prefix: list[dict] = []
            while pos < len(value) and ord(value[pos]) in _SKIP_CODEPOINTS:
                raw_offset = cell.char_offsets[pos]
                prefix.append(
                    _prefix_entry(value[pos], raw_offset, index)
                )
                pos += 1
            if pos >= len(value) or value[pos] not in FORMULA_TRIGGERS:
                continue

            trigger = value[pos]
            trigger_offset = cell.char_offsets[pos]
            trig_line, trig_col = index.line_col(trigger_offset)
            result = parse_bidi(value).to_dict()
            start_line, start_col = index.line_col(cell.start)
            # end is exclusive; position it on the character right after
            # the cell content (a quote, comma, CR or end of text).
            end_line, end_col = index.line_col(cell.end)

            findings.append(FormulaFinding(
                record_no=record_no,
                field_no=field_no,
                line=trig_line,
                column=trig_col,
                trigger=trigger,
                prefix=prefix,
                cell_start_line=start_line,
                cell_start_column=start_col,
                cell_end_line=end_line,
                cell_end_column=end_col,
                risk_level=result["risk_level"],
                result=result,
            ))

    return {
        "stored": False,
        "record_count": len(records),
        "cell_count": total_cells,
        "finding_count": len(findings),
        "risk_level": highest_risk([f.risk_level for f in findings]),
        "records": record_summaries,
        "findings": [f.to_dict() for f in findings],
    }
