# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure construction of the closed Docker Ansible Summary v1 ReportModel."""

import hashlib

from .constants import (
    CHANGE_KIND_ORDER,
    ENDPOINT_COLUMNS,
    OBSERVATION_STATUS_WARNING,
    PRESENTATION_SCHEMA_VERSION,
    REQUIRED_CONTAINER_FIELDS,
    RUN_WINDOW_COLUMNS,
    SUMMARY_LABEL_ORDER,
)
from .image import (
    project_image_labels,
    tail_weighted_elide,
)
from .model import ModelError, PresentationCapacityError, clone, normalize_warnings


def table_content_widths(kind, report_width):
    """Return the exact v1 content widths for one table kind."""

    if (
        not isinstance(report_width, int)
        or isinstance(report_width, bool)
        or not 100 <= report_width <= 240
    ):
        raise ModelError("report width must be an integer from 100 through 240")
    extra = report_width - 100
    if kind == "run_window":
        quotient, remainder = divmod(extra, 3)
        return (
            26 + quotient + remainder,
            22 + quotient,
            22 + quotient,
            17,
        )
    if kind in ("current", "known_endpoint"):
        quotient, remainder = divmod(extra, 2)
        return (34 + quotient + remainder, 46 + quotient, 10)
    raise ModelError("unknown report table kind")


def _container_hash(name):
    return hashlib.sha256(name.encode("ascii")).hexdigest()


def project_container_labels(names, width):
    """Assign stable readable container labels without hiding collisions."""

    distinct = sorted(set(names), key=lambda item: item.encode("ascii"))
    candidates = {
        name: tail_weighted_elide(name, width) for name in distinct
    }
    groups = {}
    for name, label in candidates.items():
        groups.setdefault(label, []).append(name)

    for group in groups.values():
        if len(group) <= 1:
            continue
        hashes = [_container_hash(name) for name in group]
        prefix_length = 4
        while prefix_length <= 64:
            if len(set(item[:prefix_length] for item in hashes)) == len(group):
                break
            prefix_length += 1
        if prefix_length > 64:
            raise PresentationCapacityError(
                "container identities cannot be separated"
            )
        readable_width = width - prefix_length - 1
        if readable_width < 1:
            raise PresentationCapacityError(
                "a readable container label and unique hash suffix do not fit"
            )
        for name, digest in zip(group, hashes):
            candidates[name] = (
                tail_weighted_elide(name, readable_width)
                + "#"
                + digest[:prefix_length]
            )
    return candidates


def change_label(change):
    """Return one member of the closed, facet-aware v1 CHANGE vocabulary."""

    primary = change.get("primary_kind")
    reference = change.get("image_reference_changed")
    content = change.get("image_content_changed")

    if primary == "image_changed":
        if content and reference:
            return "img+ref changed"
        if content and not reference:
            return "img changed"
        if reference and not content:
            return "ref changed"
        raise ModelError("image_changed requires at least one positive facet")
    if primary == "recreated":
        if content and reference:
            return "recreated+img+ref"
        if content and not reference:
            return "recreated+img"
        if reference and not content:
            return "recreated+ref"
        return "recreated"
    labels = {
        "added": "added",
        "removed": "removed",
        "started": "started",
        "stopped": "stopped",
        "restarted": "restarted",
        "state_changed": "state changed",
        "unchanged": "unchanged",
    }
    try:
        return labels[primary]
    except KeyError:
        raise ModelError("unknown primary change kind")


def build_between_observation_summary(delta):
    """Apply the exhaustive A-to-B summary mapping."""

    if delta is None:
        return None
    comparability = delta.get("comparability")
    changes = delta.get("changes") or []
    material = [
        item for item in changes if item.get("primary_kind") != "unchanged"
    ]

    if comparability in ("exact", "degraded") and material:
        labels = set(change_label(item) for item in material)
        ordered = [item for item in SUMMARY_LABEL_ORDER if item in labels]
        count = len(material)
        noun = "difference" if count == 1 else "differences"
        message = "Before run window: %d observed %s (%s)" % (
            count,
            noun,
            ", ".join(ordered),
        )
        if comparability == "degraded":
            message += "; restart evidence incomplete"
    elif comparability == "exact":
        return None
    elif comparability == "degraded":
        message = (
            "Before run window: no observed difference; restart evidence "
            "incomplete"
        )
    elif comparability == "no_baseline":
        message = "Before run window: no previous complete observation"
    elif comparability == "incomplete":
        message = (
            "Before run window: comparison unavailable because one or both "
            "endpoints are incomplete"
        )
    elif comparability == "incompatible_scope":
        message = (
            "Before run window: scopes are incompatible; no additions or "
            "removals inferred"
        )
    else:
        raise ModelError("unknown between-observation comparability")
    return {"comparability": comparability, "message": message}


def _run_window_notice(machine_result):
    operation = machine_result.get("operation")
    if operation != "post":
        return None
    delta = machine_result.get("run_window_delta")
    if delta is None:
        if machine_result.get("simulated"):
            return {
                "comparability": "incomplete",
                "message": (
                    "Run-window comparison unavailable: check-mode simulation "
                    "does not read retained state"
                ),
            }
        return {
            "comparability": "incomplete",
            "message": (
                "Run-window comparison unavailable: no pre-observation was "
                "recorded"
            ),
        }

    comparability = delta.get("comparability")
    if comparability == "exact":
        return None
    if comparability == "degraded":
        return {
            "comparability": "degraded",
            "message": (
                "Run-window comparison degraded: restart evidence incomplete"
            ),
        }
    if comparability == "incompatible_scope":
        return {
            "comparability": "incompatible_scope",
            "message": (
                "Scopes are incompatible; no additions or removals inferred"
            ),
        }
    if comparability in ("incomplete", "no_baseline"):
        return {
            "comparability": "incomplete",
            "message": "Run-window comparison unavailable",
        }
    raise ModelError("unknown run-window comparability")


def _fallback_machine_warnings(machine_result, observation):
    if "warnings" in machine_result:
        return machine_result.get("warnings") or []
    sources = []
    if observation is not None:
        sources.extend(observation.get("warnings") or [])
    for key in ("between_observation_delta", "run_window_delta"):
        delta = machine_result.get(key)
        if delta is not None:
            sources.extend(delta.get("warnings") or [])
    return sources


def _table_kind(machine_result, observation):
    if observation["status"] != "complete":
        return "known_endpoint"
    run_window = machine_result.get("run_window_delta")
    if (
        machine_result.get("operation") == "post"
        and run_window is not None
        and run_window.get("comparability") in ("exact", "degraded")
    ):
        return "run_window"
    return "current"


def _change_order(change):
    unchanged = change.get("primary_kind") == "unchanged"
    return (1 if unchanged else 0, change["container_name"].encode("ascii"))


def _endpoint_cell(container, image_label):
    if container is None:
        return "<absent>"
    state = container.get("runtime_state")
    if state is None:
        state = "<unknown>"
    return image_label + " / " + state


def _build_run_window_table(delta, report_width):
    widths = table_content_widths("run_window", report_width)
    changes = sorted(delta.get("changes") or [], key=_change_order)
    names = [item["container_name"] for item in changes]
    container_labels = project_container_labels(names, widths[0])

    identities = {}
    for index, change in enumerate(changes):
        if change.get("before") is not None:
            identities[(index, "before")] = change["before"]
        if change.get("after") is not None:
            identities[(index, "after")] = change["after"]
    # Runtime state always reserves " / " plus all ten columns needed for the
    # longest canonical state ("restarting").
    image_width = widths[1] - 13
    image_labels = project_image_labels(identities, image_width)

    rows = []
    for index, change in enumerate(changes):
        before = change.get("before")
        after = change.get("after")
        before_label = (
            None if before is None else image_labels[(index, "before")]
        )
        after_label = None if after is None else image_labels[(index, "after")]
        rows.append(
            {
                "container_name": change["container_name"],
                "machine_before": clone(before),
                "machine_after": clone(after),
                "cells": {
                    "container": container_labels[change["container_name"]],
                    "before": _endpoint_cell(before, before_label),
                    "after": _endpoint_cell(after, after_label),
                    "change": change_label(change),
                },
            }
        )
    return {
        "kind": "run_window",
        "columns": list(RUN_WINDOW_COLUMNS),
        "rows": rows,
    }


def _row_has_required_gap(container):
    return any(container.get(field) is None for field in REQUIRED_CONTAINER_FIELDS)


def _build_endpoint_table(observation, kind, report_width):
    widths = table_content_widths(kind, report_width)
    containers = observation.get("containers") or {}
    names = sorted(containers, key=lambda item: item.encode("ascii"))
    container_labels = project_container_labels(names, widths[0])
    identities = {
        name: containers[name]
        for name in names
    }
    image_labels = project_image_labels(identities, widths[1])
    rows = []
    for name in names:
        container = containers[name]
        rows.append(
            {
                "container_name": name,
                "machine_current": clone(container),
                "cells": {
                    "container": container_labels[name],
                    "image": image_labels[name],
                    "state": (
                        container.get("runtime_state")
                        if container.get("runtime_state") is not None
                        else "<unknown>"
                    ),
                },
            }
        )
    return {"kind": kind, "columns": list(ENDPOINT_COLUMNS), "rows": rows}


def _run_window_counts(table, changes):
    values = {}
    for change in changes:
        kind = change["primary_kind"]
        values[kind] = values.get(kind, 0) + 1
    result = {}
    for kind in CHANGE_KIND_ORDER:
        if values.get(kind, 0):
            result[kind] = values[kind]
    result["total"] = len(table["rows"])
    return result


def build_report_model(machine_result, host, report_width=120):
    """Derive the exact ephemeral ReportModel from a public machine result."""

    if not isinstance(machine_result, dict):
        raise ModelError("machine result must be a mapping")
    observation = machine_result.get("observation")
    if not isinstance(observation, dict):
        raise ModelError("a report requires a current observation")
    if not isinstance(host, str):
        raise ModelError("host must be a string")

    kind = _table_kind(machine_result, observation)
    if kind == "run_window":
        delta = machine_result["run_window_delta"]
        primary_table = _build_run_window_table(delta, report_width)
        counts = _run_window_counts(primary_table, delta.get("changes") or [])
    else:
        primary_table = _build_endpoint_table(
            observation, kind, report_width
        )
        counts = {
            "authoritative_changes": 0,
            "known_rows": len(primary_table["rows"]),
            "rows_with_required_gaps": sum(
                1
                for row in primary_table["rows"]
                if _row_has_required_gap(row["machine_current"])
            ),
        }

    machine_warnings = _fallback_machine_warnings(
        machine_result, observation
    )
    status_warning = OBSERVATION_STATUS_WARNING.get(observation["status"])
    warnings = normalize_warnings(
        machine_warnings,
        [] if status_warning is None else [status_warning],
    )

    return {
        "presentation_schema_version": PRESENTATION_SCHEMA_VERSION,
        "header": {
            "host": host,
            "instance_id": machine_result.get("instance_id"),
            "operation": machine_result.get("operation"),
            "observed_at": observation.get("observed_at"),
            "observation_status": observation.get("status"),
            "correlation_id": machine_result.get("correlation_id"),
            "simulated": bool(machine_result.get("simulated", False)),
            "replay_outcome": machine_result.get("replay_outcome"),
        },
        "primary_table": primary_table,
        "between_observation_summary": build_between_observation_summary(
            machine_result.get("between_observation_delta")
        ),
        "run_window_notice": _run_window_notice(machine_result),
        "counts": counts,
        "warnings": warnings,
        "baseline_outcome": clone(machine_result.get("baseline")),
        "journal_status": machine_result.get("journal_status"),
        "persistence_outcome": machine_result.get("persistence_outcome"),
    }
