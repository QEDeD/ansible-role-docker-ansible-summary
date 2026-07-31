# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure controller-side helpers for the DAS action plugin."""

from __future__ import absolute_import, division, print_function

import textwrap

from .constants import (
    OUTPUT_VARIABLE,
    PUBLIC_INPUT_NAMES,
    PUBLIC_PREFIX,
    REMOVED_PREFIX,
    REMOVED_PUBLIC_SUFFIXES,
)
from .image import visible_escape
from .result import safe_hash_projection
from .validation import ValidationError


PUBLIC_VARIABLES = frozenset(
    PUBLIC_PREFIX + name for name in PUBLIC_INPUT_NAMES
)


class PublicVariableError(ValidationError):
    """One bounded variable-namespace failure with a total offender count."""

    def __init__(self, code, field, count):
        ValidationError.__init__(self, code, field)
        self.count = count


def _is_removed_same_namespace(name):
    suffix = name[len(PUBLIC_PREFIX) :]
    return (
        suffix in REMOVED_PUBLIC_SUFFIXES
        or (
            suffix.startswith("table_")
            and suffix.endswith(("_width", "_min", "_max"))
        )
    )


def detect_public_variable_error(task_arguments, task_variables):
    """Return the first strict namespace violation, or ``None``.

    The caller must validate and short-circuit ``enabled`` before invoking
    this helper.
    """

    offenders = []
    for name in task_arguments:
        if name not in PUBLIC_INPUT_NAMES:
            offenders.append(("unknown_public_variable", str(name)))

    for name in task_variables:
        if not isinstance(name, str):
            continue
        if name == OUTPUT_VARIABLE:
            continue
        if name.startswith(REMOVED_PREFIX):
            offenders.append(("removed_variable", name))
        elif name.startswith(PUBLIC_PREFIX) and name not in PUBLIC_VARIABLES:
            code = (
                "removed_variable"
                if _is_removed_same_namespace(name)
                else "unknown_public_variable"
            )
            offenders.append((code, name))

    if not offenders:
        return None
    offenders.sort(key=lambda item: item[1].encode("utf-8"))
    code, field = offenders[0]
    return PublicVariableError(code, field, len(offenders))


def effective_diagnostic_width(task_arguments):
    """Use a validated report width, otherwise the frozen 120-column fallback."""

    value = task_arguments.get("report_width", 120)
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 100 <= value <= 240
    ):
        return value
    return 120


def _wrap_semantic_lines(lines, width):
    output = []
    for line in lines:
        wrapped = textwrap.wrap(
            line,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=True,
        )
        output.extend(wrapped or [""])
    return "\n".join(output)


def input_error_block(error, report_width=120):
    """Render a value-free, width-bounded public-input diagnostic."""

    raw_code = getattr(error, "code", "invalid_input")
    code = (
        raw_code
        if raw_code in ("unknown_public_variable", "removed_variable")
        else "invalid_input"
    )
    field = getattr(error, "field", None)
    count = getattr(error, "count", 1)
    field_label = "<none>" if field is None else safe_hash_projection(field)
    return _wrap_semantic_lines(
        (
            "DAS input error | code=%s" % code,
            "Variable %s | offending variables=%d | values omitted"
            % (field_label, count),
        ),
        report_width,
    )


def failure_block(
    host,
    failure_reason,
    instance_id=None,
    operation=None,
    report_width=120,
    record_id=None,
    persistence_outcome=None,
    replay_guidance=None,
):
    """Render the minimum safe diagnostic for a non-input hard failure."""

    safe_host = safe_hash_projection(host)
    lines = [
        (
            "DAS error | host=%s | instance=%s | operation=%s"
            % (
                safe_host,
                instance_id if instance_id is not None else "<none>",
                operation if operation is not None else "<none>",
            )
        ),
        (
            "Failure %s | no Docker process output or container data shown"
            % failure_reason
        ),
    ]
    if record_id is not None or persistence_outcome is not None:
        lines.append(
            "Record %s | persistence=%s"
            % (
                record_id if record_id is not None else "<none>",
                (
                    persistence_outcome
                    if persistence_outcome is not None
                    else "<none>"
                ),
            )
        )
    if failure_reason == "revision_conflict":
        lines.extend(
            (
                "Concurrent writer conflict | Store unchanged",
                (
                    "Recovery: Use a post-only observation or start a new "
                    "pre/post window"
                ),
            )
        )
    if replay_guidance is not None:
        lines.append("Recovery: " + replay_guidance)
    return _wrap_semantic_lines(lines, report_width)


def presentation_kind(machine_result, report_mode):
    """Return ``table``, ``warning``, or ``none`` for one successful result."""

    observation = machine_result.get("observation")
    if observation is None:
        return "none"
    status = observation.get("status")
    operation = machine_result.get("operation")
    if status != "complete" and (
        report_mode == "none"
        or (report_mode == "final" and operation == "pre")
    ):
        return "warning"
    if report_mode == "none":
        return "none"
    if report_mode == "final" and operation == "pre":
        return "none"
    return "table"


def compact_warning_block(
    machine_result, host, report_mode, report_width=120
):
    """Render the exact two semantic lines for a suppressed noncomplete table."""

    observation = machine_result["observation"]
    mode = (
        "final"
        if machine_result["operation"] == "pre" and report_mode == "final"
        else "none"
    )
    lines = (
        "DAS warning | host=%s | instance=%s | operation=%s"
        % (
            visible_escape(safe_hash_projection(host)),
            machine_result["instance_id"],
            machine_result["operation"],
        ),
        "Observation %s | reason=%s | table suppressed in report_mode=%s"
        % (observation["status"], observation["reason_code"], mode),
    )
    return _wrap_semantic_lines(lines, width=report_width)
