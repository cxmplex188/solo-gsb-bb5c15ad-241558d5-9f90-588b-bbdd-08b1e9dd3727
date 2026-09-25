"""Tests for the CSV formula-spoofing audit endpoint (POST /api/v1/audits/csv).

Covers: RFC 4180 parsing (comma separation, double-quote enclosure,
doubled-quote escaping, CRLF record breaks), formula-trigger detection
(=, +, -, @) after skipping leading spaces/tabs/Unicode bidi controls,
record/field numbering and original-text line/column, bidi-prefixed
triggers with the prefix controls and risk level, quoted line breaks /
escaped quotes / empty cells never shifting positions, the endpoint
being read-only, and 422 responses (unclosed/illegal quotes and
non-CRLF separators) carrying the original-text row/column.

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

from app.csv_audit import CsvParseError, audit_csv, parse_csv

LRE = "‪"   # U+202A LEFT-TO-RIGHT EMBEDDING
RLO = "‮"   # U+202E RIGHT-TO-LEFT OVERRIDE
PDF = "‬"   # U+202C POP DIRECTIONAL FORMATTING
RLM = "‏"   # U+200F RIGHT-TO-LEFT MARK
LRM = "‎"   # U+200E LEFT-TO-RIGHT MARK
PDI = "⁩"   # U+2069 POP DIRECTIONAL ISOLATE


# ------------------------------------------------------- parser basics ---

def test_simple_records_and_cells():
    report = audit_csv("a,b,c\r\n1,2,3\r\n")
    assert report["record_count"] == 2
    assert report["cell_count"] == 6
    assert report["finding_count"] == 0
    assert report["risk_level"] == "info"
    assert report["records"] == [
        {"record_no": 1, "field_count": 3, "start_line": 1},
        {"record_no": 2, "field_count": 3, "start_line": 2},
    ]
    assert report["findings"] == []


def test_empty_input_has_zero_records():
    report = audit_csv("")
    assert report["record_count"] == 0
    assert report["cell_count"] == 0
    assert report["finding_count"] == 0
    assert report["risk_level"] == "info"
    assert report["records"] == []


def test_trailing_crlf_does_not_create_blank_record():
    assert audit_csv("a\r\n")["record_count"] == 1
    assert audit_csv("a\r\n\r\n")["record_count"] == 2


def test_empty_cells_count_as_fields():
    report = audit_csv(",,\r\n,,,\r\n")
    assert [(r["record_no"], r["field_count"]) for r in report["records"]] == [
        (1, 3), (2, 4),
    ]
    assert report["cell_count"] == 7


def test_quoted_field_with_escaped_quote_decodes():
    cells = parse_csv('"he said ""hi""",x\r\n')[0].cells
    assert cells[0].value == 'he said "hi"'
    assert cells[0].quoted is True
    assert cells[1].value == "x"
    assert cells[1].quoted is False


def test_comma_and_equals_inside_quotes_are_literal():
    report = audit_csv('"=not,a,trigger",plain\r\n')
    # the quoted cell starts with '=' and IS one formula finding, but the
    # embedded commas never split it into separate fields
    assert report["record_count"] == 1
    assert report["records"][0]["field_count"] == 2
    finding = report["findings"][0]
    assert finding["record_no"] == 1
    assert finding["field_no"] == 1
    assert finding["trigger"] == "="


# ------------------------------------------------- formula triggers ------

def test_all_four_triggers_reported_in_order():
    report = audit_csv("=1\r\n+2\r\n-3\r\n@4\r\n")
    triggers = [(f["record_no"], f["field_no"], f["trigger"])
                for f in report["findings"]]
    assert triggers == [
        (1, 1, "="), (2, 1, "+"), (3, 1, "-"), (4, 1, "@"),
    ]
    assert [f["position"] for f in report["findings"]] == [
        {"line": 1, "column": 1},
        {"line": 2, "column": 1},
        {"line": 3, "column": 1},
        {"line": 4, "column": 1},
    ]


def test_trigger_in_later_field_position():
    report = audit_csv("abc,de,=cmd\r\n")
    finding = report["findings"][0]
    assert finding["record_no"] == 1
    assert finding["field_no"] == 3
    # '=' is at raw offset 7 -> line 1, column 8
    assert finding["position"] == {"line": 1, "column": 8}
    assert finding["cell_position"]["start"] == {"line": 1, "column": 8}
    assert finding["cell_position"]["end"] == {"line": 1, "column": 12}


def test_spaces_and_tabs_are_skipped_before_trigger():
    report = audit_csv("  \t\t=1\r\n")
    finding = report["findings"][0]
    assert finding["trigger"] == "="
    assert finding["position"] == {"line": 1, "column": 5}
    kinds = [p["kind"] for p in finding["prefix_control_chars"]]
    assert kinds == ["space", "space", "tab", "tab"]
    cols = [p["position"]["column"] for p in finding["prefix_control_chars"]]
    assert cols == [1, 2, 3, 4]
    assert all(p["codepoint"] in ("U+0020", "U+0009")
               for p in finding["prefix_control_chars"])


def test_whitespace_only_and_non_trigger_cells_not_reported():
    report = audit_csv("   \t\r\nabc\r\n1+1=2\r\n\t x\r\n")
    assert report["finding_count"] == 0
    assert report["record_count"] == 4


def test_trigger_after_quote_still_skipped_inside_value():
    # leading spaces inside a quoted field count toward the prefix too
    report = audit_csv('"  @sum(A1)"\r\n')
    finding = report["findings"][0]
    assert finding["trigger"] == "@"
    assert finding["position"] == {"line": 1, "column": 4}
    assert [p["kind"] for p in finding["prefix_control_chars"]] == [
        "space", "space",
    ]


# ------------------------------------------------- bidi prefix + risk ---

def test_bidi_control_before_trigger_is_skipped_and_reported():
    report = audit_csv(f"a,{RLO}=evil.exe\r\n")
    finding = report["findings"][0]
    assert finding["record_no"] == 1
    assert finding["field_no"] == 2
    assert finding["trigger"] == "="
    # RLO at offset 2 (col 3), '=' at offset 3 (col 4)
    assert finding["position"] == {"line": 1, "column": 4}
    prefix = finding["prefix_control_chars"]
    assert len(prefix) == 1
    assert prefix[0]["codepoint"] == "U+202E"
    assert prefix[0]["kind"] == "bidi:RLO"
    assert prefix[0]["position"] == {"line": 1, "column": 3}
    # unclosed RLO makes the cell critical
    assert finding["risk_level"] == "critical"
    assert report["risk_level"] == "critical"


def test_mixed_space_tab_bidi_prefix():
    report = audit_csv(f" \t{RLM}+x\r\n")
    finding = report["findings"][0]
    assert finding["trigger"] == "+"
    assert finding["position"] == {"line": 1, "column": 4}
    assert [p["codepoint"] for p in finding["prefix_control_chars"]] == [
        "U+0020", "U+0009", "U+200F",
    ]
    # RLM is a harmless mark -> info
    assert finding["risk_level"] == "info"


def test_balanced_bidi_in_formula_cell_sets_cell_risk():
    # balanced LRE...PDF inside the formula -> low cell risk
    report = audit_csv(f"={LRE}x{PDF}\r\n")
    finding = report["findings"][0]
    assert finding["risk_level"] == "low"
    # the trigger itself is at column 1; controls are not part of prefix
    assert finding["prefix_control_chars"] == []
    assert finding["result"]["stats"]["total_control_chars"] == 2


def test_bidi_after_trigger_still_audited():
    report = audit_csv(f"=a{RLO}b\r\n")
    finding = report["findings"][0]
    assert finding["prefix_control_chars"] == []
    assert finding["risk_level"] == "critical"


def test_lrm_prefix_is_info():
    report = audit_csv(f"{LRM}-5\r\n")
    finding = report["findings"][0]
    assert finding["trigger"] == "-"
    assert finding["risk_level"] == "info"
    assert finding["prefix_control_chars"][0]["kind"] == "bidi:LRM"


def test_pdi_after_rli_medium():
    report = audit_csv(f"=x{PDI}\r\n")
    # lone PDI orphan closer -> medium
    assert report["findings"][0]["risk_level"] == "medium"


def test_overall_risk_is_highest_cell_risk():
    report = audit_csv(f"=clean\r\n{RLO}=evil\r\n+ok\r\n")
    assert report["risk_level"] == "critical"
    assert [f["risk_level"] for f in report["findings"]] == [
        "info", "critical", "info",
    ]


# ------------------------ quoted line breaks / escapes / empty cells ----

def test_quoted_crlf_does_not_split_record():
    text = '"line1\r\nline2",=x\r\n'
    report = audit_csv(text)
    assert report["record_count"] == 1
    assert report["records"][0]["field_count"] == 2
    finding = report["findings"][0]
    assert finding["record_no"] == 1
    assert finding["field_no"] == 2
    # raw line 2 is 'line2",=x': '=' is column 8
    assert finding["position"] == {"line": 2, "column": 8}


def test_quoted_bare_lf_does_not_split_record_and_advances_line():
    text = '"a\nb\nc",@cmd\r\n'
    report = audit_csv(text)
    assert report["record_count"] == 1
    assert report["records"][0]["field_count"] == 2
    assert report["records"][0]["start_line"] == 1
    finding = report["findings"][0]
    assert finding["trigger"] == "@"
    assert finding["position"] == {"line": 3, "column": 4}


def test_escaped_quotes_do_not_shift_positions():
    # cell value: "x""y" (decodes to x"y); following field holds formula
    text = '"x""y",=z\r\n'
    report = audit_csv(text)
    assert report["records"][0]["field_count"] == 2
    finding = report["findings"][0]
    assert finding["field_no"] == 2
    assert finding["position"] == {"line": 1, "column": 8}
    cells = parse_csv(text)[0].cells
    assert cells[0].value == 'x"y'
    # decoded '"' maps to the first quote of the doubled pair
    quote_decoded_pos = cells[0].char_offsets[1]
    assert text[quote_decoded_pos:quote_decoded_pos + 2] == '""'


def test_multiple_quoted_newlines_then_more_records():
    text = '"a\r\nb\r\nc",1\r\n=2,3\r\n'
    report = audit_csv(text)
    assert [(r["record_no"], r["field_count"], r["start_line"])
            for r in report["records"]] == [
        (1, 2, 1),
        (2, 2, 4),
    ]
    finding = report["findings"][0]
    assert finding["record_no"] == 2
    assert finding["field_no"] == 1
    assert finding["position"] == {"line": 4, "column": 1}


def test_empty_cells_between_formulas_keep_numbering():
    report = audit_csv("=1,,=3\r\n")
    findings = report["findings"]
    assert [(f["field_no"], f["trigger"]) for f in findings] == [
        (1, "="), (3, "="),
    ]
    assert findings[1]["position"] == {"line": 1, "column": 5}


def test_empty_quoted_field():
    cells = parse_csv('""\r\n')[0].cells
    assert cells[0].value == ""
    assert cells[0].quoted is True
    assert audit_csv('""\r\n')["finding_count"] == 0


# --------------------------------------------------------- 422 errors ---

def _expect_error(text):
    try:
        audit_csv(text)
    except CsvParseError as exc:
        return exc
    raise AssertionError(f"expected CsvParseError for {text!r}")


def test_unclosed_quote_422_points_at_opening_quote():
    exc = _expect_error('abc,"def\r\n')
    assert exc.offset == 4
    assert (exc.line, exc.column) == (1, 5)
    assert "unterminated" in exc.message


def test_quote_inside_unquoted_field_422():
    exc = _expect_error('a"b,c\r\n')
    assert exc.offset == 1
    assert (exc.line, exc.column) == (1, 2)


def test_garbage_after_closing_quote_422():
    exc = _expect_error('"ab"x,c\r\n')
    assert exc.offset == 4
    assert (exc.line, exc.column) == (1, 5)
    assert "closing quote" in exc.message


def test_bare_lf_outside_quote_422():
    exc = _expect_error("a,b\nc,d\r\n")
    assert exc.offset == 3
    assert (exc.line, exc.column) == (1, 4)


def test_bare_cr_outside_quote_422():
    exc = _expect_error("a,b\rc,d")
    assert exc.offset == 3
    assert (exc.line, exc.column) == (1, 4)


def test_error_after_quoted_newline_has_raw_position():
    exc = _expect_error('"a\nb",x"y\r\n')
    # raw line 2 is 'b",x"y': the stray quote is column 5
    assert exc.line == 2
    assert exc.column == 5


# ------------------------------------------------------------- API ------

def test_api_success(client):
    resp = client.post("/api/v1/audits/csv",
                       json={"csv": "a,=1+2\r\n", "filename": "sheet.csv"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is False
    assert body["filename"] == "sheet.csv"
    assert body["record_count"] == 1
    assert body["finding_count"] == 1
    finding = body["findings"][0]
    assert finding["trigger"] == "="
    assert finding["record_no"] == 1
    assert finding["field_no"] == 2
    assert finding["risk_level"] == "info"


def test_api_422_on_unclosed_quote(client):
    resp = client.post("/api/v1/audits/csv", json={"csv": '"abc'})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_csv"
    assert detail["line"] == 1
    assert detail["column"] == 1
    assert detail["offset"] == 0
    assert "message" in detail


def test_api_422_on_illegal_quote_has_row_column(client):
    resp = client.post("/api/v1/audits/csv", json={"csv": 'x,y"z\r\n'})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail == {
        "error": "invalid_csv",
        "offset": 3,
        "line": 1,
        "column": 4,
        "message": detail["message"],
    }


def test_api_missing_csv_field_is_422(client):
    resp = client.post("/api/v1/audits/csv", json={"filename": "x.csv"})
    assert resp.status_code == 422


def test_api_endpoint_is_read_only(client):
    before = client.get("/api/v1/audits").json()["total"]
    resp = client.post("/api/v1/audits/csv",
                       json={"csv": f"{RLO}=evil\r\n"})
    assert resp.status_code == 200
    assert resp.json()["risk_level"] == "critical"
    after = client.get("/api/v1/audits").json()["total"]
    assert before == after
