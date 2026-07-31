# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic ANSI-free ASCII renderer for a DAS v1 ReportModel."""

import re

from .constants import (
    CHANGE_KIND_ORDER,
    ENDPOINT_COLUMNS,
    PRESENTATION_SCHEMA_VERSION,
    REPORT_HEADER_FIELDS,
    REPORT_MODEL_FIELDS,
    REPORT_NOTICE_FIELDS,
    REPORT_TABLE_FIELDS,
    RUN_WINDOW_COLUMNS,
)
from .image import visible_escape
from .model import ModelError, normalize_warnings, require_exact_fields
from .report import table_content_widths


_ESCAPE_ATOM_RE = re.compile(r"\\x[0-9a-f]{2}")


def _visible_atoms(value):
    atoms = []
    index = 0
    while index < len(value):
        candidate = value[index : index + 4]
        if len(candidate) == 4 and _ESCAPE_ATOM_RE.match(candidate):
            atoms.append(candidate)
            index += 4
        else:
            atoms.append(value[index])
            index += 1
    return atoms


def _atom_chunks(value, width):
    if width < 1:
        raise ModelError("line content width must be positive")
    atoms = _visible_atoms(value)
    chunks = []
    current = []
    used = 0
    for atom in atoms:
        if len(atom) > width:
            raise ModelError("a visible escape atom does not fit")
        if current and used + len(atom) > width:
            chunks.append("".join(current))
            current = []
            used = 0
        current.append(atom)
        used += len(atom)
    if current:
        chunks.append("".join(current))
    return chunks or [""]


def _wrap_fields(fields, width):
    """Wrap semantic metadata fields before splitting an individual value."""

    lines = []
    current = ""
    for field in fields:
        if not isinstance(field, str):
            raise ModelError("metadata fields must be strings")
        if not current:
            prefix = "" if not lines else "  "
            if len(prefix) + len(field) <= width:
                current = prefix + field
            else:
                chunks = _atom_chunks(field, width - len(prefix))
                lines.extend(prefix + item for item in chunks[:-1])
                current = prefix + chunks[-1]
            continue

        candidate = current + " | " + field
        if len(candidate) <= width:
            current = candidate
            continue

        lines.append(current)
        prefix = "  "
        if len(prefix) + len(field) <= width:
            current = prefix + field
        else:
            chunks = _atom_chunks(field, width - len(prefix))
            lines.extend(prefix + item for item in chunks[:-1])
            current = prefix + chunks[-1]
    if current:
        lines.append(current)
    return lines


def _wrap_visible_line(value, width):
    if len(value) <= width:
        return [value]
    chunks = _atom_chunks(value, width)
    lines = [chunks[0]]
    remainder = "".join(chunks[1:])
    if remainder:
        lines.extend(
            "  " + chunk for chunk in _atom_chunks(remainder, width - 2)
        )
    return lines


def render_warning_lines(warnings, report_width):
    """Render each warning once with exact fixed-prefix hard wrapping."""

    if not warnings:
        return ["Warnings: none"]
    lines = []
    for index, warning in enumerate(warnings):
        escaped = visible_escape(warning)
        prefix = "Warnings: " if index == 0 else "  "
        chunks = _atom_chunks(escaped, report_width - len(prefix))
        lines.append(prefix + chunks[0])
        remainder = "".join(chunks[1:])
        if remainder:
            lines.extend(
                "  " + chunk
                for chunk in _atom_chunks(remainder, report_width - 2)
            )
    return lines


def _validate_notice(value, label):
    if value is None:
        return
    require_exact_fields(value, REPORT_NOTICE_FIELDS, label)
    if value["comparability"] not in (
        "exact",
        "degraded",
        "no_baseline",
        "incomplete",
        "incompatible_scope",
    ):
        raise ModelError("%s comparability is invalid" % label)
    if not isinstance(value["message"], str):
        raise ModelError("%s message must be a string" % label)


def validate_report_model(model):
    """Validate the exact closed model shape and internal count invariants."""

    require_exact_fields(model, REPORT_MODEL_FIELDS, "ReportModel")
    if model["presentation_schema_version"] != PRESENTATION_SCHEMA_VERSION:
        raise ModelError("unsupported presentation schema")
    header = model["header"]
    require_exact_fields(header, REPORT_HEADER_FIELDS, "ReportHeader")
    for field in (
        "host",
        "instance_id",
        "operation",
        "observed_at",
        "observation_status",
    ):
        if not isinstance(header[field], str) or not header[field]:
            raise ModelError("ReportHeader.%s must be a nonempty string" % field)
    if header["correlation_id"] is not None and not isinstance(
        header["correlation_id"], str
    ):
        raise ModelError("ReportHeader.correlation_id must be a string or null")
    if not isinstance(header["simulated"], bool):
        raise ModelError("ReportHeader.simulated must be Boolean")
    if header["replay_outcome"] not in (None, "idempotent"):
        raise ModelError("ReportHeader.replay_outcome is invalid")
    table = model["primary_table"]
    require_exact_fields(table, REPORT_TABLE_FIELDS, "ReportTable")
    kind = table["kind"]
    if kind == "run_window":
        expected_columns = list(RUN_WINDOW_COLUMNS)
        row_fields = frozenset(
            ("container_name", "machine_before", "machine_after", "cells")
        )
        cell_fields = frozenset(("container", "before", "after", "change"))
    elif kind in ("current", "known_endpoint"):
        expected_columns = list(ENDPOINT_COLUMNS)
        row_fields = frozenset(("container_name", "machine_current", "cells"))
        cell_fields = frozenset(("container", "image", "state"))
    else:
        raise ModelError("unknown report table kind")
    if table["columns"] != expected_columns:
        raise ModelError("report columns do not match the table kind")
    if not isinstance(table["rows"], list):
        raise ModelError("report rows must be a list")
    for index, row in enumerate(table["rows"]):
        require_exact_fields(row, row_fields, "ReportRow[%d]" % index)
        require_exact_fields(
            row["cells"], cell_fields, "ReportCells[%d]" % index
        )

    _validate_notice(
        model["between_observation_summary"],
        "between_observation_summary",
    )
    _validate_notice(model["run_window_notice"], "run_window_notice")

    counts = model["counts"]
    if not isinstance(counts, dict):
        raise ModelError("report counts must be a mapping")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts.values()
    ):
        raise ModelError("report counts must be nonnegative integers")
    if kind == "run_window":
        permitted = set(CHANGE_KIND_ORDER) | set(("total",))
        if set(counts) - permitted or "total" not in counts:
            raise ModelError("invalid run-window count keys")
        if any(
            key != "total" and value == 0 for key, value in counts.items()
        ):
            raise ModelError("zero-valued run-window kind counts are forbidden")
        if counts["total"] != len(table["rows"]):
            raise ModelError("run-window total does not match row count")
        if sum(
            value for key, value in counts.items() if key != "total"
        ) != counts["total"]:
            raise ModelError("run-window kind counts do not sum to total")
    else:
        expected = frozenset(
            (
                "authoritative_changes",
                "known_rows",
                "rows_with_required_gaps",
            )
        )
        if frozenset(counts) != expected:
            raise ModelError("invalid endpoint count keys")
        if counts["authoritative_changes"] != 0:
            raise ModelError("endpoint reports cannot assert changes")
        if counts["known_rows"] != len(table["rows"]):
            raise ModelError("known_rows does not match row count")

    warnings = model["warnings"]
    # Construction owns sorting; rendering owns preservation.  Validation
    # still applies every safety bound so the renderer can also exercise
    # deliberately ordered internal layout fixtures without silently sorting.
    normalize_warnings(warnings)
    baseline = model["baseline_outcome"]
    if baseline is not None:
        require_exact_fields(
            baseline, frozenset(("advanced", "before", "after")), "BaselineResult"
        )
        if not isinstance(baseline["advanced"], bool):
            raise ModelError("BaselineResult.advanced must be Boolean")
        for field in ("before", "after"):
            if baseline[field] is not None and not isinstance(
                baseline[field], str
            ):
                raise ModelError(
                    "BaselineResult.%s must be a string or null" % field
                )
    if model["journal_status"] not in (
        None,
        "open",
        "complete",
        "incomplete_pre",
        "incomplete_post",
        "incomplete_both",
        "scope_mismatch",
    ):
        raise ModelError("journal status is invalid")
    if model["persistence_outcome"] not in (
        "committed",
        "not_attempted",
        "failed",
        "conflict",
    ):
        raise ModelError("persistence outcome is invalid")
    return model


def _table_lines(table, report_width):
    widths = table_content_widths(table["kind"], report_width)
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def row_line(values):
        if len(values) != len(widths):
            raise ModelError("table row has the wrong cell count")
        for value, width in zip(values, widths):
            if not isinstance(value, str):
                raise ModelError("rendered table cells must be strings")
            try:
                encoded = value.encode("ascii")
            except UnicodeEncodeError:
                raise ModelError(
                    "rendered table cells must be printable ASCII"
                )
            if any(byte < 0x20 or byte > 0x7E for byte in bytearray(encoded)):
                raise ModelError(
                    "rendered table cells must be printable ASCII"
                )
            if len(value) > width:
                raise ModelError("a projected table cell exceeds its width")
        return (
            "|"
            + "|".join(
                " %s " % value.ljust(width)
                for value, width in zip(values, widths)
            )
            + "|"
        )

    lines = [border, row_line(table["columns"]), border]
    for row in table["rows"]:
        cells = row["cells"]
        if table["kind"] == "run_window":
            values = (
                cells["container"],
                cells["before"],
                cells["after"],
                cells["change"],
            )
        else:
            values = (cells["container"], cells["image"], cells["state"])
        lines.append(row_line(values))
    lines.append(border)
    return lines


def _counts_line(table_kind, counts):
    if table_kind == "run_window":
        ordered = [
            "%s=%s" % (kind, counts[kind])
            for kind in CHANGE_KIND_ORDER
            if kind in counts
        ]
        ordered.append("total=%s" % counts["total"])
    else:
        ordered = [
            "authoritative_changes=%s" % counts["authoritative_changes"],
            "known_rows=%s" % counts["known_rows"],
            "rows_with_required_gaps=%s"
            % counts["rows_with_required_gaps"],
        ]
    return "Counts: " + ", ".join(ordered)


def _baseline_line(baseline):
    if baseline is None:
        return "Baseline: not applicable"
    before = (
        "<none>"
        if baseline.get("before") is None
        else visible_escape(str(baseline["before"]))
    )
    after = (
        "<none>"
        if baseline.get("after") is None
        else visible_escape(str(baseline["after"]))
    )
    outcome = "advanced" if baseline.get("advanced") else "unchanged"
    return "Baseline: %s (%s -> %s)" % (outcome, before, after)


def render_report(model, report_width=120):
    """Render one complete host-identifiable block without a trailing LF."""

    validate_report_model(model)
    # Also validates the supported width before any partial block is returned.
    table_content_widths(model["primary_table"]["kind"], report_width)

    header = model["header"]
    first_fields = [
        "DAS v1",
        "host=" + visible_escape(str(header["host"])),
        "instance=" + visible_escape(str(header["instance_id"])),
        "operation=" + visible_escape(str(header["operation"])),
    ]
    second_fields = [
        "Observed " + visible_escape(str(header["observed_at"])),
        "status=" + visible_escape(str(header["observation_status"])),
    ]
    if header["correlation_id"] is not None:
        second_fields.append(
            "correlation=" + visible_escape(str(header["correlation_id"]))
        )
    if header["simulated"]:
        second_fields.append("mode=simulation")
    if header["replay_outcome"] is not None:
        second_fields.append(
            "replay=" + visible_escape(str(header["replay_outcome"]))
        )

    lines = []
    lines.extend(_wrap_fields(first_fields, report_width))
    lines.extend(_wrap_fields(second_fields, report_width))
    lines.extend(_table_lines(model["primary_table"], report_width))

    table = model["primary_table"]
    if not table["rows"]:
        if table["kind"] == "current":
            lines.append("No containers observed in complete scope")
        elif table["kind"] == "run_window":
            lines.append(
                "No containers observed in either complete run-window endpoint"
            )

    for key in ("between_observation_summary", "run_window_notice"):
        notice = model[key]
        if notice is not None:
            lines.extend(_wrap_visible_line(notice["message"], report_width))

    lines.extend(
        _wrap_visible_line(
            _counts_line(table["kind"], model["counts"]), report_width
        )
    )
    lines.extend(
        _wrap_visible_line(
            _baseline_line(model["baseline_outcome"]), report_width
        )
    )
    journal = (
        "not applicable"
        if model["journal_status"] is None
        else visible_escape(str(model["journal_status"]))
    )
    persistence = visible_escape(str(model["persistence_outcome"]))
    lines.extend(
        _wrap_visible_line(
            "Journal: %s | Persistence: %s" % (journal, persistence),
            report_width,
        )
    )
    lines.extend(render_warning_lines(model["warnings"], report_width))

    if any(len(line) > report_width for line in lines):
        raise ModelError("renderer produced an over-width physical line")
    if any("\x1b" in line for line in lines):
        raise ModelError("ANSI escape sequences are forbidden")
    rendered = "\n".join(lines)
    if rendered.splitlines() != lines:
        raise ModelError("renderer produced an unexpected physical line")
    if any(
        ord(character) < 0x20 or ord(character) > 0x7E
        for line in lines
        for character in line
    ):
        raise ModelError("renderer produced a non-printable ASCII byte")
    return rendered
