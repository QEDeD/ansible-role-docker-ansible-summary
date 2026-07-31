# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Closed public result and bounded failure envelopes for DAS v1."""

from __future__ import absolute_import, division, print_function

import hashlib
import json

from .constants import (
    DOCKER_REASON_CODES as OBSERVATION_REASONS,
    ROLE_SCHEMA_VERSION as SCHEMA_VERSION,
)
from .model import ModelError, clone, normalize_warnings
from .validation import (
    JOURNAL_STATUSES,
    ValidationError,
    validate_baseline,
    validate_correlation_id,
    validate_delta,
    validate_instance_id,
    validate_observation,
    validate_record_id,
)

MACHINE_RESULT_FIELDS = (
    "schema_version",
    "operation",
    "instance_id",
    "record_id",
    "correlation_id",
    "observation",
    "observation_status",
    "scope_identity",
    "between_observation_delta",
    "run_window_delta",
    "baseline",
    "baseline_advanced",
    "journal_status",
    "persistence_outcome",
    "replay_outcome",
    "simulated",
    "skipped",
    "warnings",
)

FAILURE_FIELDS = (
    "schema_version",
    "host",
    "instance_id",
    "operation",
    "record_id",
    "observation_status",
    "failure_reason",
    "observation_reason",
    "persistence_outcome",
    "committed_result_replayable",
    "replay_guidance",
)

PRIVATE_FAILURE_FIELDS = (
    "failure_reason",
    "persistence_outcome",
    "record_id",
    "observation_status",
    "observation_reason",
    "committed_result_replayable",
    "retry_unchanged_phase",
)

FAILURE_REASONS = frozenset(
    (
        "observation_noncomplete",
        "invalid_input",
        "unsafe_state_namespace",
        "corrupt_state",
        "state_lock_timeout",
        "state_write_failed",
        "state_size_limit_exceeded",
        "revision_conflict",
        "signature_conflict",
        "record_pruned",
        "unknown_record",
        "render_failed",
        "presentation_capacity_exceeded",
    )
)

RETRY_WITH_REPORT = "Retry the retained record with failure_policy=report"
RETRY_WITHOUT_REPORT = "Retry the retained record with report_mode=none"
RETRY_UNCHANGED_PHASE = (
    "Retry with the same record_id and unchanged phase inputs"
)


class ResultContractError(ModelError):
    """Raised when an internal result violates the closed public contract."""


def disabled_machine_result():
    """Return the exact disabled short-circuit result."""

    return {
        "schema_version": SCHEMA_VERSION,
        "operation": None,
        "instance_id": None,
        "record_id": None,
        "correlation_id": None,
        "observation": None,
        "observation_status": None,
        "scope_identity": None,
        "between_observation_delta": None,
        "run_window_delta": None,
        "baseline": None,
        "baseline_advanced": None,
        "journal_status": None,
        "persistence_outcome": "not_attempted",
        "replay_outcome": None,
        "simulated": False,
        "skipped": True,
        "warnings": [],
    }


def build_machine_result(
    inputs,
    observation,
    lifecycle=None,
    simulated=False,
):
    """Build the exact 18-key successful result from canonical evidence."""

    lifecycle = lifecycle or {}
    baseline = lifecycle.get("baseline")
    between = lifecycle.get("between_observation_delta")
    run_window = lifecycle.get("run_window_delta")
    warnings = normalize_warnings(
        [] if observation is None else observation.get("warnings", []),
        [] if between is None else between.get("warnings", []),
        [] if run_window is None else run_window.get("warnings", []),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "operation": inputs["operation"],
        "instance_id": inputs["instance_id"],
        "record_id": (
            None if simulated else lifecycle.get("record_id")
        ),
        "correlation_id": lifecycle.get(
            "correlation_id", inputs.get("correlation_id")
        ),
        "observation": observation,
        "observation_status": (
            None if observation is None else observation["status"]
        ),
        "scope_identity": (
            None if observation is None else observation["scope"]["identity"]
        ),
        "between_observation_delta": between,
        "run_window_delta": run_window,
        "baseline": baseline,
        "baseline_advanced": (
            None if baseline is None else baseline["advanced"]
        ),
        "journal_status": lifecycle.get("journal_status"),
        "persistence_outcome": lifecycle.get(
            "persistence_outcome", "not_attempted"
        ),
        "replay_outcome": lifecycle.get("replay_outcome"),
        "simulated": bool(simulated),
        "skipped": False,
        "warnings": warnings,
    }


def sanitize_machine_result(
    value, expected_inputs=None, check_mode=None
):
    """Copy only the exact public machine allowlist from module output."""

    validate_machine_result(
        value,
        expected_inputs=expected_inputs,
        check_mode=check_mode,
    )
    return {name: clone(value[name]) for name in MACHINE_RESULT_FIELDS}


def _delta_endpoint(delta, prefix):
    return (
        delta[prefix + "_observation_id"],
        delta[prefix + "_observed_at"],
        delta[prefix + "_scope"],
    )


def _observation_endpoint(observation):
    return (
        observation["observation_id"],
        observation["observed_at"],
        observation["scope"],
    )


def _between_comparabilities(delta, target_complete):
    if not target_complete:
        return frozenset(("incomplete",))
    if delta["from_observation_id"] is None:
        return frozenset(("no_baseline",))
    if delta["from_scope"] != delta["to_scope"]:
        return frozenset(("incompatible_scope",))
    return frozenset(("exact", "degraded"))


def _run_window_comparabilities(delta, pre_complete, post_complete):
    if not pre_complete or not post_complete:
        return frozenset(("incomplete",))
    if delta["from_scope"] != delta["to_scope"]:
        return frozenset(("incompatible_scope",))
    return frozenset(("exact", "degraded"))


def _validate_pre_lifecycle(selected, observation):
    between = selected["between_observation_delta"]
    baseline = selected["baseline"]
    if _delta_endpoint(between, "to") != _observation_endpoint(observation):
        raise ResultContractError("pre delta target mismatch")
    if (
        baseline["advanced"]
        or baseline["before"] != baseline["after"]
        or baseline["before"] != between["from_observation_id"]
    ):
        raise ResultContractError("invalid pre baseline lifecycle")
    allowed_comparabilities = _between_comparabilities(
        between, observation["status"] == "complete"
    )
    if between["comparability"] not in allowed_comparabilities:
        raise ResultContractError("invalid pre delta lifecycle")

    journal_status = selected["journal_status"]
    if selected["replay_outcome"] is None:
        if journal_status != "open":
            raise ResultContractError("committed pre result is not open")
        return
    if observation["status"] == "complete":
        allowed_statuses = frozenset(
            ("open", "complete", "scope_mismatch", "incomplete_post")
        )
    else:
        allowed_statuses = frozenset(
            ("open", "incomplete_pre", "incomplete_both")
        )
    if journal_status not in allowed_statuses:
        raise ResultContractError("invalid replayed pre journal status")


def _validate_post_baseline(baseline, observation):
    if observation["status"] == "complete":
        if (
            not baseline["advanced"]
            or baseline["after"] != observation["observation_id"]
        ):
            raise ResultContractError("invalid complete post baseline")
    elif (
        baseline["advanced"]
        or baseline["after"] != baseline["before"]
    ):
        raise ResultContractError("invalid noncomplete post baseline")


def _validate_post_lifecycle(selected, observation):
    between = selected["between_observation_delta"]
    run_window = selected["run_window_delta"]
    baseline = selected["baseline"]
    post_complete = observation["status"] == "complete"
    _validate_post_baseline(baseline, observation)

    if run_window is None:
        expected_status = (
            "incomplete_pre" if post_complete else "incomplete_both"
        )
        if selected["journal_status"] != expected_status:
            raise ResultContractError("invalid post-only journal status")
        return

    if _delta_endpoint(run_window, "to") != _observation_endpoint(observation):
        raise ResultContractError("post delta target mismatch")
    if _delta_endpoint(between, "to") != _delta_endpoint(
        run_window, "from"
    ):
        raise ResultContractError("paired post delta boundary mismatch")
    if baseline["before"] != between["from_observation_id"]:
        raise ResultContractError("paired post baseline source mismatch")

    pre_complete = between["comparability"] != "incomplete"
    allowed_between = _between_comparabilities(between, pre_complete)
    if between["comparability"] not in allowed_between:
        raise ResultContractError("invalid paired pre delta lifecycle")
    allowed_run_window = _run_window_comparabilities(
        run_window, pre_complete, post_complete
    )
    if run_window["comparability"] not in allowed_run_window:
        raise ResultContractError("invalid run-window delta lifecycle")

    if not pre_complete:
        expected_status = (
            "incomplete_pre" if post_complete else "incomplete_both"
        )
    elif not post_complete:
        expected_status = "incomplete_post"
    elif run_window["from_scope"] == run_window["to_scope"]:
        expected_status = "complete"
    else:
        expected_status = "scope_mismatch"
    if selected["journal_status"] != expected_status:
        raise ResultContractError("invalid paired post journal status")


def validate_machine_result(
    value, expected_inputs=None, check_mode=None
):
    """Validate the nested semantic boundary before controller exposure."""

    if not isinstance(value, dict):
        raise ResultContractError("module result must be a mapping")
    missing = [name for name in MACHINE_RESULT_FIELDS if name not in value]
    if missing:
        raise ResultContractError(
            "module result is missing required public fields"
        )

    selected = {name: value[name] for name in MACHINE_RESULT_FIELDS}
    if selected["schema_version"] != SCHEMA_VERSION:
        raise ResultContractError("unsupported result schema")
    if not isinstance(selected["simulated"], bool):
        raise ResultContractError("simulated must be a boolean")
    if not isinstance(selected["skipped"], bool):
        raise ResultContractError("skipped must be a boolean")
    if selected["skipped"]:
        if selected != disabled_machine_result():
            raise ResultContractError("invalid disabled machine result")
        return selected

    operation = selected["operation"]
    if operation not in ("pre", "post", "status"):
        raise ResultContractError("invalid operation")
    try:
        validate_instance_id(selected["instance_id"])
        validate_correlation_id(selected["correlation_id"])
        if selected["record_id"] is not None:
            validate_record_id(selected["record_id"])
        observation = selected["observation"]
        validate_observation(observation, release=True)
        for name in ("between_observation_delta", "run_window_delta"):
            if selected[name] is not None:
                validate_delta(selected[name], name)
        if selected["baseline"] is not None:
            validate_baseline(selected["baseline"])
    except ValidationError:
        raise ResultContractError("invalid nested machine result")

    if selected["observation_status"] != observation["status"]:
        raise ResultContractError("observation status summary mismatch")
    if selected["scope_identity"] != observation["scope"]["identity"]:
        raise ResultContractError("scope identity summary mismatch")
    baseline = selected["baseline"]
    if selected["baseline_advanced"] != (
        None if baseline is None else baseline["advanced"]
    ):
        raise ResultContractError("baseline summary mismatch")
    if (
        selected["journal_status"] is not None
        and selected["journal_status"] not in JOURNAL_STATUSES
    ):
        raise ResultContractError("invalid journal status")
    if selected["persistence_outcome"] not in (
        "committed",
        "not_attempted",
    ):
        raise ResultContractError("invalid successful persistence outcome")
    if selected["replay_outcome"] not in (None, "idempotent"):
        raise ResultContractError("invalid replay outcome")

    if operation == "pre" and selected["run_window_delta"] is not None:
        raise ResultContractError("pre result has a run-window delta")

    if operation == "status" or selected["simulated"]:
        if any(
            selected[name] is not None
            for name in (
                "record_id",
                "between_observation_delta",
                "run_window_delta",
                "baseline",
                "baseline_advanced",
                "journal_status",
                "replay_outcome",
            )
        ):
            raise ResultContractError("store-free result has lifecycle state")
        if selected["persistence_outcome"] != "not_attempted":
            raise ResultContractError("store-free persistence was attempted")
    else:
        if selected["record_id"] is None:
            raise ResultContractError("writing result has no record ID")
        if selected["baseline"] is None:
            raise ResultContractError("writing result has no baseline outcome")
        if selected["journal_status"] is None:
            raise ResultContractError("writing result has no journal status")
        committed = selected["persistence_outcome"] == "committed"
        replayed = selected["replay_outcome"] == "idempotent"
        if committed == replayed:
            raise ResultContractError(
                "writing result must be one commit or one replay"
            )
        if replayed and selected["persistence_outcome"] != "not_attempted":
            raise ResultContractError("replay attempted persistence")
        if operation == "pre":
            if selected["between_observation_delta"] is None:
                raise ResultContractError("pre result has no baseline delta")
        elif (
            (selected["between_observation_delta"] is None)
            != (selected["run_window_delta"] is None)
        ):
            raise ResultContractError("post pairing deltas are inconsistent")
        if operation == "pre":
            _validate_pre_lifecycle(selected, observation)
        else:
            _validate_post_lifecycle(selected, observation)

    if expected_inputs is not None:
        if not isinstance(expected_inputs, dict):
            raise ResultContractError("expected inputs must be a mapping")
        if selected["operation"] != expected_inputs.get("operation"):
            raise ResultContractError("operation differs from controller input")
        if selected["instance_id"] != expected_inputs.get("instance_id"):
            raise ResultContractError("instance differs from controller input")
        if observation["scope"] != expected_inputs.get("scope"):
            raise ResultContractError("scope differs from controller input")
        expected_check_mode = (
            expected_inputs.get("check_mode", False)
            if check_mode is None
            else check_mode
        )
        if selected["simulated"] is not bool(expected_check_mode):
            raise ResultContractError("simulation differs from check mode")
        requested_record = expected_inputs.get("record_id")
        if (
            requested_record is not None
            and not selected["simulated"]
            and selected["record_id"] != requested_record
        ):
            raise ResultContractError("record differs from controller input")
        requested_correlation = expected_inputs.get("correlation_id")
        if (
            operation != "post"
            or requested_correlation is not None
            or requested_record is None
            or selected["simulated"]
        ) and selected["correlation_id"] != requested_correlation:
            raise ResultContractError(
                "correlation differs from controller input"
            )
        if (
            operation == "post"
            and not selected["simulated"]
            and requested_record is None
            and (
                selected["between_observation_delta"] is not None
                or selected["run_window_delta"] is not None
            )
        ):
            raise ResultContractError(
                "post-only result invented a pairing comparison"
            )
        if (
            operation == "post"
            and not selected["simulated"]
            and requested_record is not None
            and selected["persistence_outcome"] == "committed"
            and selected["run_window_delta"] is None
        ):
            raise ResultContractError(
                "committed matching post lost its pairing comparison"
            )

    expected_warnings = normalize_warnings(
        observation["warnings"],
        (
            []
            if selected["between_observation_delta"] is None
            else selected["between_observation_delta"]["warnings"]
        ),
        (
            []
            if selected["run_window_delta"] is None
            else selected["run_window_delta"]["warnings"]
        ),
    )
    if selected["warnings"] != expected_warnings:
        raise ResultContractError("machine warning union mismatch")
    return selected


def safe_hash_projection(value, maximum=128):
    """Retain bounded printable ASCII or return a full SHA-256 projection."""

    if not isinstance(value, str):
        value = str(value)
    try:
        encoded = value.encode("utf-8")
        ascii_encoded = value.encode("ascii")
    except UnicodeError:
        encoded = value.encode("utf-8", "surrogatepass")
        ascii_encoded = b""
    if (
        ascii_encoded
        and len(ascii_encoded) <= maximum
        and all(0x20 <= byte <= 0x7E for byte in bytearray(ascii_encoded))
    ):
        return value
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def sanitize_private_failure(value):
    """Validate the managed-host failure channel before using any value."""

    if not isinstance(value, dict) or set(value) != set(PRIVATE_FAILURE_FIELDS):
        raise ResultContractError("invalid private failure envelope")
    if value["failure_reason"] not in FAILURE_REASONS:
        raise ResultContractError("invalid private failure reason")
    if value["persistence_outcome"] not in (
        "not_attempted",
        "failed",
        "conflict",
    ):
        raise ResultContractError("invalid private persistence outcome")
    if value["record_id"] is not None:
        try:
            validate_record_id(value["record_id"])
        except ValidationError:
            raise ResultContractError("invalid private record ID")
    if value["observation_status"] not in (
        None,
        "complete",
        "partial",
        "unavailable",
    ):
        raise ResultContractError("invalid private observation status")
    if (
        value["observation_reason"] is not None
        and value["observation_reason"] not in OBSERVATION_REASONS
    ):
        raise ResultContractError("invalid private observation reason")
    for name in (
        "committed_result_replayable",
        "retry_unchanged_phase",
    ):
        if not isinstance(value[name], bool):
            raise ResultContractError("invalid private failure boolean")
    if (
        value["committed_result_replayable"]
        and value["retry_unchanged_phase"]
    ):
        raise ResultContractError("conflicting private replay guidance")
    return {name: clone(value[name]) for name in PRIVATE_FAILURE_FIELDS}


def _guidance(failure_reason, replayable, retry_unchanged_phase):
    if retry_unchanged_phase:
        return RETRY_UNCHANGED_PHASE
    if not replayable:
        return None
    if failure_reason == "observation_noncomplete":
        return RETRY_WITH_REPORT
    if failure_reason in (
        "render_failed",
        "presentation_capacity_exceeded",
    ):
        return RETRY_WITHOUT_REPORT
    return None


def failure_result(
    host,
    failure_reason,
    instance_id=None,
    operation=None,
    record_id=None,
    observation_status=None,
    observation_reason=None,
    persistence_outcome="not_attempted",
    committed_result_replayable=False,
    retry_unchanged_phase=False,
):
    """Return the exact bounded failed-task result."""

    if failure_reason not in FAILURE_REASONS:
        raise ResultContractError("unknown failure reason")
    if (
        observation_reason is not None
        and observation_reason not in OBSERVATION_REASONS
    ):
        raise ResultContractError("unknown observation reason")

    envelope = {
        "schema_version": SCHEMA_VERSION,
        "host": safe_hash_projection(host),
        "instance_id": instance_id,
        "operation": operation,
        "record_id": record_id,
        "observation_status": observation_status,
        "failure_reason": failure_reason,
        "observation_reason": observation_reason,
        "persistence_outcome": persistence_outcome,
        "committed_result_replayable": bool(
            committed_result_replayable
        ),
        "replay_guidance": _guidance(
            failure_reason,
            committed_result_replayable,
            retry_unchanged_phase,
        ),
    }
    result = {
        "changed": False,
        "failed": True,
        "docker_ansible_summary_failure": envelope,
    }
    encoded = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > 1024:
        raise ResultContractError("failure result exceeds 1024 bytes")
    return result
