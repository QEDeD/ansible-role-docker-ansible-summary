# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validation and canonical serialization for the DAS v1 contract.

This module deliberately has no Ansible dependency.  Controller, managed-host,
and unit-test callers all use the same closed-schema validators.
"""

import datetime
import hashlib
import json
import posixpath
import re
import unicodedata

from .constants import (
    CHANGE_KIND_ORDER as CHANGE_KINDS,
    COMPARISON_SCHEMA_VERSION,
    CONTAINER_DELTA_FIELDS as CONTAINER_DELTA_KEYS,
    CONTAINER_ID_PATTERN,
    CONTAINER_NAME_PATTERN,
    DELTA_RESULT_FIELDS as DELTA_KEYS,
    DOCKER_WARNING_BY_REASON as REASON_WARNINGS,
    IMAGE_ID_PATTERN,
    OUTPUT_VARIABLE,
    PUBLIC_INPUT_NAMES,
    PUBLIC_PREFIX,
    REMOVED_PREFIX,
    REMOVED_PUBLIC_SUFFIXES,
    ROLE_SCHEMA_VERSION as SCHEMA_VERSION,
    RUNTIME_STATES,
    SIGNATURE_SCHEMA_VERSION,
)


DEFAULT_STATE_ROOT = "/var/lib/docker-ansible-summary"
DEFAULT_JOURNAL_MAX_RECORDS = 30
DEFAULT_STATE_MAX_BYTES = 16777216
DEFAULT_REPORT_MODE = "final"
DEFAULT_REPORT_WIDTH = 120
DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 30
DEFAULT_FAILURE_POLICY = "report"

INSTANCE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")
RECORD_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CONTAINER_NAME_RE = re.compile(CONTAINER_NAME_PATTERN)
CONTAINER_ID_RE = re.compile(CONTAINER_ID_PATTERN)
IMAGE_ID_RE = re.compile(IMAGE_ID_PATTERN)
SHA256_RE = re.compile(IMAGE_ID_PATTERN)
UTC_TIMESTAMP_RE = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z\Z"
)
SCOPE_PATTERN_RE = re.compile(r"\A[A-Za-z0-9_.?*\[\]!-]+\Z")

OBSERVATION_STATUSES = frozenset(("complete", "partial", "unavailable"))
JOURNAL_STATUSES = frozenset(
    (
        "open",
        "complete",
        "scope_mismatch",
        "incomplete_pre",
        "incomplete_post",
        "incomplete_both",
    )
)
COMPARABILITIES = frozenset(
    ("exact", "degraded", "no_baseline", "incomplete", "incompatible_scope")
)
CHANGE_KIND_SET = frozenset(CHANGE_KINDS)

STATE_KEYS = frozenset(
    (
        "schema_version",
        "comparison_schema_version",
        "instance_id",
        "revision",
        "latest_complete_post",
        "journal",
        "recently_pruned_record_ids",
    )
)
RUN_RECORD_KEYS = frozenset(
    (
        "record_id",
        "correlation_id",
        "created_at",
        "updated_at",
        "expected_post_revision",
        "pre_signature",
        "post_signature",
        "status",
        "pre",
        "post",
        "between_observation_delta",
        "run_window_delta",
        "pre_baseline",
        "post_baseline",
    )
)
OBSERVATION_KEYS = frozenset(
    (
        "observation_id",
        "observed_at",
        "scope",
        "status",
        "reason_code",
        "warnings",
        "discovery_backend",
        "metadata_gaps",
        "containers",
    )
)
SCOPE_KEYS = frozenset(("patterns", "identity", "comparison_schema_version"))
CONTAINER_KEYS = frozenset(
    (
        "name",
        "container_id",
        "full_image_reference",
        "image_id",
        "runtime_state",
        "created_at",
        "started_at",
        "finished_at",
        "restart_count",
    )
)
BASELINE_KEYS = frozenset(("advanced", "before", "after"))


class ValidationError(ValueError):
    """A bounded validation failure suitable for conversion to invalid_input."""

    def __init__(self, code, field=None):
        ValueError.__init__(self, code)
        self.code = code
        self.field = field


def _fail(code, field=None):
    raise ValidationError(code, field)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _require_mapping(value, field):
    if not isinstance(value, dict):
        _fail("invalid_type", field)


def _require_exact_keys(value, expected, field):
    _require_mapping(value, field)
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            _fail("missing_field", field + "." + missing[0])
        _fail("unknown_field", field + "." + unknown[0])


def _require_list(value, field):
    if not isinstance(value, list):
        _fail("invalid_type", field)


def _require_bool(value, field):
    if not isinstance(value, bool):
        _fail("invalid_type", field)


def _require_int_range(value, minimum, maximum, field):
    if not _is_int(value):
        _fail("invalid_type", field)
    if value < minimum or value > maximum:
        _fail("out_of_range", field)


def _require_enum(value, allowed, field):
    if not isinstance(value, str) or value not in allowed:
        _fail("invalid_value", field)


def _require_nullable_record_id(value, field):
    if value is not None:
        validate_record_id(value, field)


def _json_without_lf(value):
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail("not_json_serializable")


def canonical_json_bytes(value):
    """Return canonical v1 JSON bytes, including the required trailing LF."""

    return _json_without_lf(value) + b"\n"


def validate_instance_id(value, field="instance_id"):
    if not isinstance(value, str) or not INSTANCE_ID_RE.match(value):
        _fail("invalid_instance_id", field)
    return value


def validate_record_id(value, field="record_id"):
    if not isinstance(value, str) or not RECORD_ID_RE.match(value):
        _fail("invalid_record_id", field)
    return value


def validate_state_root(value, field="state_root"):
    if not isinstance(value, str):
        _fail("invalid_type", field)
    if "\x00" in value:
        _fail("nul", field)
    if not value.startswith("/"):
        _fail("not_absolute", field)
    if value == "/":
        _fail("filesystem_root_forbidden", field)
    if value.endswith("/"):
        _fail("trailing_separator", field)
    if "//" in value:
        _fail("repeated_separator", field)
    components = value.split("/")[1:]
    if "." in components:
        _fail("current_component", field)
    if ".." in components:
        _fail("parent_component", field)
    if not components or any(not component for component in components):
        _fail("invalid_state_root", field)
    if posixpath.normpath(value) != value:
        _fail("not_lexically_normal", field)
    return value


def validate_correlation_id(value, field="correlation_id"):
    if value is None:
        return None
    if not isinstance(value, str):
        _fail("invalid_type", field)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        _fail("invalid_utf8", field)
    if len(encoded) > 256:
        _fail("too_long", field)
    if any(
        unicodedata.category(character) == "Cc" for character in value
    ):
        _fail("control_character", field)
    return value


def _validate_scope_pattern(pattern, field):
    if not isinstance(pattern, str):
        _fail("invalid_type", field)
    pattern = pattern.strip()
    if not pattern:
        _fail("invalid_empty_scope_entry", field)
    try:
        encoded = pattern.encode("ascii")
    except UnicodeEncodeError:
        _fail("non_printable_ascii", field)
    if len(encoded) > 256:
        _fail("scope_pattern_too_long", field)
    if not SCOPE_PATTERN_RE.match(pattern):
        _fail("forbidden_scope_character", field)
    return pattern


def normalize_scope(value, comparison_schema_version=COMPARISON_SCHEMA_VERSION):
    """Normalize a public scope and return its exact canonical Scope object."""

    if comparison_schema_version != COMPARISON_SCHEMA_VERSION:
        _fail("unsupported_comparison_schema_version", "comparison_schema_version")
    if isinstance(value, str):
        entries = [value]
    elif isinstance(value, list):
        entries = list(value)
    else:
        _fail("invalid_type", "scope")
    if not entries:
        _fail("invalid_empty_scope", "scope")

    normalized = []
    selects_all = False
    for index, entry in enumerate(entries):
        pattern = _validate_scope_pattern(entry, "scope[{0}]".format(index))
        if pattern in ("all", "*"):
            selects_all = True
        else:
            normalized.append(pattern)
    patterns = ["*"] if selects_all else sorted(set(normalized))
    if len(patterns) > 64:
        _fail("scope_pattern_count_exceeded", "scope")
    if sum(len(pattern.encode("ascii")) for pattern in patterns) > 4096:
        _fail("scope_pattern_bytes_exceeded", "scope")

    identity_input = {
        "comparison_schema_version": comparison_schema_version,
        "patterns": patterns,
    }
    identity = "sha256:" + hashlib.sha256(
        _json_without_lf(identity_input)
    ).hexdigest()
    return {
        "patterns": patterns,
        "identity": identity,
        "comparison_schema_version": comparison_schema_version,
    }


def phase_signature(operation, instance_id, scope, correlation_id=None):
    """Return the v1 replay signature for one validated phase."""

    _require_enum(operation, frozenset(("pre", "post")), "operation")
    validate_instance_id(instance_id)
    if isinstance(scope, dict):
        validate_scope(scope)
        patterns = scope["patterns"]
    else:
        patterns = normalize_scope(scope)["patterns"]
    validate_correlation_id(correlation_id)
    value = {
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "correlation_id": correlation_id,
        "instance_id": instance_id,
        "operation": operation,
        "scope": patterns,
        "signature_schema_version": SIGNATURE_SCHEMA_VERSION,
    }
    return "sha256:" + hashlib.sha256(_json_without_lf(value)).hexdigest()


def _unprefix_inputs(values):
    """Accept either action arguments or a task-variable namespace."""

    _require_mapping(values, "inputs")
    prefixed = [
        name
        for name in values
        if name.startswith(PUBLIC_PREFIX) or name.startswith(REMOVED_PREFIX)
    ]
    if not prefixed:
        unknown = sorted(set(values) - PUBLIC_INPUT_NAMES)
        if unknown:
            _fail("unknown_public_variable", unknown[0])
        return dict(values)

    removed = sorted(name for name in prefixed if name.startswith(REMOVED_PREFIX))
    if removed:
        _fail("removed_variable", removed[0])
    result = {}
    for full_name in sorted(prefixed):
        if full_name == OUTPUT_VARIABLE:
            continue
        short_name = full_name[len(PUBLIC_PREFIX) :]
        if (
            short_name in REMOVED_PUBLIC_SUFFIXES
            or short_name.startswith("table_")
            and short_name.endswith(
                (
                    "_width",
                    "_min",
                    "_max",
                )
            )
        ):
            _fail("removed_variable", full_name)
        if short_name not in PUBLIC_INPUT_NAMES:
            _fail("unknown_public_variable", full_name)
        result[short_name] = values[full_name]
    return result


def validate_public_inputs(values, check_mode=False):
    """Validate and default the exact v1 public input namespace.

    The disabled short circuit intentionally validates only ``enabled``.
    """

    _require_mapping(values, "inputs")
    uses_prefixed_namespace = any(
        name.startswith(PUBLIC_PREFIX) or name.startswith(REMOVED_PREFIX)
        for name in values
    )
    if uses_prefixed_namespace:
        enabled = values.get(PUBLIC_PREFIX + "enabled", True)
    else:
        enabled = values.get("enabled", True)
    _require_bool(enabled, "enabled")
    if not enabled:
        return {"enabled": False}

    raw = _unprefix_inputs(values)
    unknown = sorted(set(raw) - PUBLIC_INPUT_NAMES)
    if unknown:
        _fail("unknown_public_variable", unknown[0])

    operation = raw.get("operation")
    _require_enum(operation, frozenset(("pre", "post", "status")), "operation")
    instance_id = validate_instance_id(raw.get("instance_id"))
    if "scope" not in raw:
        _fail("missing_field", "scope")
    scope = normalize_scope(raw["scope"])

    record_id = raw.get("record_id")
    if record_id is not None:
        validate_record_id(record_id)
    if operation == "status" and record_id is not None:
        _fail("record_id_forbidden_for_status", "record_id")

    state_root = validate_state_root(raw.get("state_root", DEFAULT_STATE_ROOT))
    journal_max_records = raw.get(
        "journal_max_records", DEFAULT_JOURNAL_MAX_RECORDS
    )
    _require_int_range(journal_max_records, 1, 100, "journal_max_records")
    state_max_bytes = raw.get("state_max_bytes", DEFAULT_STATE_MAX_BYTES)
    _require_int_range(
        state_max_bytes, 1048576, 268435456, "state_max_bytes"
    )
    correlation_id = validate_correlation_id(raw.get("correlation_id"))
    report_mode = raw.get("report_mode", DEFAULT_REPORT_MODE)
    _require_enum(report_mode, frozenset(("final", "each", "none")), "report_mode")
    report_width = raw.get("report_width", DEFAULT_REPORT_WIDTH)
    _require_int_range(report_width, 100, 240, "report_width")
    discovery_timeout = raw.get(
        "discovery_timeout_seconds", DEFAULT_DISCOVERY_TIMEOUT_SECONDS
    )
    _require_int_range(
        discovery_timeout, 1, 300, "discovery_timeout_seconds"
    )
    failure_policy = raw.get("failure_policy", DEFAULT_FAILURE_POLICY)
    _require_enum(
        failure_policy,
        frozenset(("report", "fail_after_report")),
        "failure_policy",
    )
    _require_bool(check_mode, "check_mode")

    return {
        "enabled": True,
        "operation": operation,
        "instance_id": instance_id,
        "scope": scope,
        "record_id": record_id,
        "state_root": state_root,
        "journal_max_records": journal_max_records,
        "state_max_bytes": state_max_bytes,
        "correlation_id": correlation_id,
        "report_mode": report_mode,
        "report_width": report_width,
        "discovery_timeout_seconds": discovery_timeout,
        "failure_policy": failure_policy,
        "check_mode": check_mode,
    }


def validate_utc_timestamp(value, field):
    if not isinstance(value, str):
        _fail("invalid_timestamp", field)
    match = UTC_TIMESTAMP_RE.match(value)
    if not match:
        _fail("invalid_timestamp", field)
    year, month, day, hour, minute, second, fraction = match.groups()
    if fraction and fraction.endswith("0"):
        _fail("noncanonical_timestamp", field)
    try:
        datetime.datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
        )
    except ValueError:
        _fail("invalid_timestamp", field)
    return value


def _validate_sorted_unique_strings(values, field, maximum=None):
    _require_list(values, field)
    if any(not isinstance(value, str) for value in values):
        _fail("invalid_type", field)
    if values != sorted(set(values)):
        _fail("not_sorted_unique", field)
    if maximum is not None and len(values) > maximum:
        _fail("too_many_items", field)


def validate_scope(scope, field="scope"):
    _require_exact_keys(scope, SCOPE_KEYS, field)
    if scope["comparison_schema_version"] != COMPARISON_SCHEMA_VERSION:
        _fail("unsupported_comparison_schema_version", field)
    normalized = normalize_scope(
        scope["patterns"], scope["comparison_schema_version"]
    )
    if scope != normalized:
        _fail("invalid_scope_identity", field)
    return scope


def _validate_optional_timestamp(value, field):
    if value is not None:
        validate_utc_timestamp(value, field)


def _validate_container(container, field, complete=False, map_name=None):
    _require_exact_keys(container, CONTAINER_KEYS, field)
    name = container["name"]
    if not isinstance(name, str) or not CONTAINER_NAME_RE.match(name):
        _fail("invalid_container_name", field + ".name")
    if map_name is not None and name != map_name:
        _fail("container_map_key_mismatch", field + ".name")

    container_id = container["container_id"]
    if container_id is not None and (
        not isinstance(container_id, str) or not CONTAINER_ID_RE.match(container_id)
    ):
        _fail("invalid_container_id", field + ".container_id")
    image_reference = container["full_image_reference"]
    if image_reference is not None:
        if not isinstance(image_reference, str):
            _fail("invalid_type", field + ".full_image_reference")
        try:
            image_reference_bytes = image_reference.encode("ascii")
        except UnicodeEncodeError:
            _fail("invalid_image_reference", field + ".full_image_reference")
        if (
            not image_reference_bytes
            or len(image_reference_bytes) > 4096
            or any(character.isspace() for character in image_reference)
            or any(
                ord(character) < 33 or ord(character) > 126
                for character in image_reference
            )
        ):
            _fail("invalid_image_reference", field + ".full_image_reference")
    image_id = container["image_id"]
    if image_id is not None and (
        not isinstance(image_id, str) or not IMAGE_ID_RE.match(image_id)
    ):
        _fail("invalid_image_id", field + ".image_id")
    runtime_state = container["runtime_state"]
    if runtime_state is not None and runtime_state not in RUNTIME_STATES:
        _fail("invalid_runtime_state", field + ".runtime_state")
    if complete and (
        container_id is None
        or image_reference is None
        or image_id is None
        or runtime_state is None
    ):
        _fail("complete_observation_missing_required_field", field)

    _validate_optional_timestamp(container["created_at"], field + ".created_at")
    _validate_optional_timestamp(container["started_at"], field + ".started_at")
    _validate_optional_timestamp(container["finished_at"], field + ".finished_at")
    restart_count = container["restart_count"]
    if restart_count is not None and (
        not _is_int(restart_count) or restart_count < 0
    ):
        _fail("invalid_restart_count", field + ".restart_count")
    return container


def _validate_warnings(warnings, field):
    _validate_sorted_unique_strings(warnings, field, 64)
    total = len(_json_without_lf(warnings))
    if total > 8192:
        _fail("warnings_too_large", field)
    for warning in warnings:
        try:
            encoded = warning.encode("ascii")
        except UnicodeEncodeError:
            _fail("invalid_warning", field)
        if (
            not encoded
            or len(encoded) > 256
            or any(byte < 32 or byte > 126 for byte in bytearray(encoded))
        ):
            _fail("invalid_warning", field)


def _gap_is_valid(gap):
    if gap == "docker.catalogue":
        return True
    if not isinstance(gap, str) or "." not in gap:
        return False
    name, gap_field = gap.rsplit(".", 1)
    return bool(CONTAINER_NAME_RE.match(name)) and gap_field in (
        "name",
        "container_id",
        "full_image_reference",
        "image_id",
        "runtime_state",
        "created_at",
        "started_at",
        "finished_at",
        "restart_count",
        "container_inspect",
    )


def validate_observation(observation, field="observation", release=False):
    _require_exact_keys(observation, OBSERVATION_KEYS, field)
    validate_record_id(observation["observation_id"], field + ".observation_id")
    validate_utc_timestamp(observation["observed_at"], field + ".observed_at")
    validate_scope(observation["scope"], field + ".scope")
    status = observation["status"]
    _require_enum(status, OBSERVATION_STATUSES, field + ".status")
    reason = observation["reason_code"]
    warnings = observation["warnings"]
    _validate_warnings(warnings, field + ".warnings")
    if status == "complete":
        if reason is not None or warnings != []:
            _fail("complete_observation_has_failure", field)
    else:
        if reason not in REASON_WARNINGS:
            _fail("invalid_reason_code", field + ".reason_code")
        if warnings != [REASON_WARNINGS[reason]]:
            _fail("invalid_reason_warning_mapping", field + ".warnings")

    backend = observation["discovery_backend"]
    if release:
        if backend != "docker_cli_v1":
            _fail("invalid_release_discovery_backend", field + ".discovery_backend")
    elif not isinstance(backend, str) or not backend:
        _fail("invalid_discovery_backend", field + ".discovery_backend")

    gaps = observation["metadata_gaps"]
    _validate_sorted_unique_strings(gaps, field + ".metadata_gaps")
    if any(not _gap_is_valid(gap) for gap in gaps):
        _fail("invalid_metadata_gap", field + ".metadata_gaps")

    containers = observation["containers"]
    if status == "unavailable":
        if containers is not None:
            _fail("unavailable_observation_has_catalogue", field + ".containers")
        return observation
    if not isinstance(containers, dict):
        _fail("invalid_type", field + ".containers")
    if len(containers) > 4096:
        _fail("catalogue_capacity_exceeded", field + ".containers")
    for name in sorted(containers):
        _validate_container(
            containers[name],
            field + ".containers." + name,
            complete=status == "complete",
            map_name=name,
        )
    if status == "complete":
        required_suffixes = (
            ".name",
            ".container_id",
            ".full_image_reference",
            ".image_id",
            ".runtime_state",
            ".container_inspect",
        )
        if "docker.catalogue" in gaps or any(
            gap.endswith(required_suffixes) for gap in gaps
        ):
            _fail("complete_observation_has_required_gap", field + ".metadata_gaps")
    else:
        for name, container in containers.items():
            for key in (
                "container_id",
                "full_image_reference",
                "image_id",
                "runtime_state",
            ):
                if container[key] is None and name + "." + key not in gaps:
                    _fail("missing_required_gap", field + ".metadata_gaps")
    return observation


def _validate_endpoint(identifier, observed_at, scope, field):
    values = (identifier, observed_at, scope)
    if all(value is None for value in values):
        return
    if any(value is None for value in values):
        _fail("partial_delta_endpoint", field)
    validate_record_id(identifier, field + ".observation_id")
    validate_utc_timestamp(observed_at, field + ".observed_at")
    validate_scope(scope, field + ".scope")


def _endpoint_matches(delta, prefix, observation):
    if observation is None:
        return (
            delta[prefix + "_observation_id"] is None
            and delta[prefix + "_observed_at"] is None
            and delta[prefix + "_scope"] is None
        )
    return (
        delta[prefix + "_observation_id"] == observation["observation_id"]
        and delta[prefix + "_observed_at"] == observation["observed_at"]
        and delta[prefix + "_scope"] == observation["scope"]
    )


def _validate_container_delta(delta, field):
    _require_exact_keys(delta, CONTAINER_DELTA_KEYS, field)
    name = delta["container_name"]
    if not isinstance(name, str) or not CONTAINER_NAME_RE.match(name):
        _fail("invalid_container_name", field + ".container_name")
    kinds = delta["kinds"]
    _require_list(kinds, field + ".kinds")
    if (
        not kinds
        or len(kinds) != len(set(kinds))
        or any(kind not in CHANGE_KIND_SET for kind in kinds)
    ):
        _fail("invalid_change_kinds", field + ".kinds")
    expected_order = sorted(kinds, key=lambda item: CHANGE_KINDS.index(item))
    if kinds != expected_order:
        _fail("invalid_change_kind_order", field + ".kinds")
    if delta["primary_kind"] != kinds[0]:
        _fail("invalid_primary_kind", field + ".primary_kind")
    if "unchanged" in kinds and kinds != ["unchanged"]:
        _fail("invalid_unchanged_combination", field + ".kinds")
    if "added" in kinds or "removed" in kinds:
        if len(kinds) != 1:
            _fail("invalid_membership_combination", field + ".kinds")

    before = delta["before"]
    after = delta["after"]
    if delta["primary_kind"] == "added":
        if before is not None or after is None:
            _fail("invalid_added_endpoints", field)
    elif delta["primary_kind"] == "removed":
        if before is None or after is not None:
            _fail("invalid_removed_endpoints", field)
    elif before is None or after is None:
        _fail("missing_change_endpoint", field)
    if before is not None:
        _validate_container(before, field + ".before", complete=True)
        if before["name"] != name:
            _fail("container_delta_name_mismatch", field + ".before")
    if after is not None:
        _validate_container(after, field + ".after", complete=True)
        if after["name"] != name:
            _fail("container_delta_name_mismatch", field + ".after")
    for key in ("image_reference_changed", "image_content_changed"):
        value = delta[key]
        if value is not None and not isinstance(value, bool):
            _fail("invalid_type", field + "." + key)
    if delta["image_content_evidence"] not in (None, "image_id"):
        _fail("invalid_image_content_evidence", field + ".image_content_evidence")
    if before is None or after is None:
        if (
            delta["image_reference_changed"] is not None
            or delta["image_content_changed"] is not None
            or delta["image_content_evidence"] is not None
        ):
            _fail("membership_delta_has_image_facets", field)
    else:
        reference_changed = (
            before["full_image_reference"] != after["full_image_reference"]
        )
        content_changed = before["image_id"] != after["image_id"]
        if (
            delta["image_reference_changed"] is not reference_changed
            or delta["image_content_changed"] is not content_changed
            or delta["image_content_evidence"] != "image_id"
        ):
            _fail("image_facet_mismatch", field)
        if ("image_changed" in kinds) != (
            reference_changed or content_changed
        ):
            _fail("image_change_kind_mismatch", field + ".kinds")
        recreated = before["container_id"] != after["container_id"]
        if ("recreated" in kinds) != recreated:
            _fail("recreated_kind_mismatch", field + ".kinds")
    return delta


def validate_delta(delta, field="delta"):
    _require_exact_keys(delta, DELTA_KEYS, field)
    _require_enum(delta["comparability"], COMPARABILITIES, field + ".comparability")
    if delta["comparison_schema_version"] != COMPARISON_SCHEMA_VERSION:
        _fail("unsupported_comparison_schema_version", field)
    _validate_endpoint(
        delta["from_observation_id"],
        delta["from_observed_at"],
        delta["from_scope"],
        field + ".from",
    )
    _validate_endpoint(
        delta["to_observation_id"],
        delta["to_observed_at"],
        delta["to_scope"],
        field + ".to",
    )
    if delta["to_observation_id"] is None:
        _fail("missing_delta_target", field)
    comparability = delta["comparability"]
    source_missing = delta["from_observation_id"] is None
    if comparability == "no_baseline" and not source_missing:
        _fail("no_baseline_has_source", field)
    if comparability in ("exact", "degraded", "incompatible_scope") and source_missing:
        _fail("comparable_delta_missing_source", field)
    if comparability in ("exact", "degraded") and (
        delta["from_scope"] != delta["to_scope"]
    ):
        _fail("comparable_delta_scope_mismatch", field)
    if comparability == "incompatible_scope" and (
        delta["from_scope"] == delta["to_scope"]
    ):
        _fail("incompatible_delta_equal_scope", field)
    if delta["warnings"] != []:
        _fail("delta_warnings_reserved", field + ".warnings")
    changes = delta["changes"]
    _require_list(changes, field + ".changes")
    names = []
    for index, change in enumerate(changes):
        _validate_container_delta(change, field + ".changes[{0}]".format(index))
        names.append(change["container_name"])
    if names != sorted(set(names)):
        _fail("changes_not_sorted_unique", field + ".changes")
    if delta["comparability"] not in ("exact", "degraded") and changes:
        _fail("incomparable_delta_has_changes", field + ".changes")
    return delta


def validate_baseline(baseline, field="baseline"):
    _require_exact_keys(baseline, BASELINE_KEYS, field)
    _require_bool(baseline["advanced"], field + ".advanced")
    _require_nullable_record_id(baseline["before"], field + ".before")
    _require_nullable_record_id(baseline["after"], field + ".after")
    return baseline


def _derived_status(pre, post):
    if post is None:
        return "open"
    pre_complete = pre is not None and pre["status"] == "complete"
    post_complete = post["status"] == "complete"
    if pre_complete and post_complete:
        if pre["scope"] == post["scope"]:
            return "complete"
        return "scope_mismatch"
    if post_complete:
        return "incomplete_pre"
    if pre_complete:
        return "incomplete_post"
    return "incomplete_both"


def _recompute_delta(before, after, field):
    try:
        from .compare import compare_observations

        return compare_observations(
            before, after, instance_compatible=True
        )
    except Exception:
        _fail("delta_recomputation_failed", field)


def _validate_recomputable_delta(delta, before, after, field):
    recomputed = _recompute_delta(before, after, field)
    if delta != recomputed:
        _fail("delta_semantic_mismatch", field)


def _reconstructed_source_observation(delta):
    containers = {}
    for change in delta["changes"]:
        before = change["before"]
        if before is not None:
            # A shallow copy is sufficient: container values are scalars.
            containers[change["container_name"]] = dict(before)
    return {
        "observation_id": delta["from_observation_id"],
        "observed_at": delta["from_observed_at"],
        "scope": delta["from_scope"],
        "status": "complete",
        "reason_code": None,
        "warnings": [],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": containers,
    }


def _validate_record(
    record,
    store_revision,
    instance_id,
    latest_baseline,
    field,
    release,
):
    _require_exact_keys(record, RUN_RECORD_KEYS, field)
    validate_record_id(record["record_id"], field + ".record_id")
    correlation = validate_correlation_id(
        record["correlation_id"], field + ".correlation_id"
    )
    validate_utc_timestamp(record["created_at"], field + ".created_at")
    validate_utc_timestamp(record["updated_at"], field + ".updated_at")
    expected_revision = record["expected_post_revision"]
    if expected_revision is not None:
        if not _is_int(expected_revision) or not (
            1 <= expected_revision <= store_revision
        ):
            _fail("invalid_expected_post_revision", field)
    _require_enum(record["status"], JOURNAL_STATUSES, field + ".status")

    pre = record["pre"]
    post = record["post"]
    if pre is not None:
        validate_observation(pre, field + ".pre", release=release)
    if post is not None:
        validate_observation(post, field + ".post", release=release)

    pre_signature_value = record["pre_signature"]
    post_signature_value = record["post_signature"]
    for name, signature in (
        ("pre_signature", pre_signature_value),
        ("post_signature", post_signature_value),
    ):
        if signature is not None and (
            not isinstance(signature, str) or not SHA256_RE.match(signature)
        ):
            _fail("invalid_phase_signature", field + "." + name)

    between = record["between_observation_delta"]
    run_window = record["run_window_delta"]
    pre_baseline = record["pre_baseline"]
    post_baseline = record["post_baseline"]

    if pre is None:
        if any(
            value is not None
            for value in (
                expected_revision,
                pre_signature_value,
                between,
                pre_baseline,
            )
        ):
            _fail("absent_pre_has_pre_fields", field)
    else:
        if expected_revision is None or pre_signature_value is None:
            _fail("present_pre_missing_fields", field)
        if pre_signature_value != phase_signature(
            "pre", instance_id, pre["scope"], correlation
        ):
            _fail("stale_pre_signature", field + ".pre_signature")
        if between is None or pre_baseline is None:
            _fail("present_pre_missing_derived_fields", field)
        validate_delta(between, field + ".between_observation_delta")
        validate_baseline(pre_baseline, field + ".pre_baseline")
        if not _endpoint_matches(between, "to", pre):
            _fail("between_delta_target_mismatch", field)
        if pre_baseline["advanced"]:
            _fail("pre_baseline_advanced", field)
        if pre_baseline["before"] != pre_baseline["after"]:
            _fail("pre_baseline_endpoint_mismatch", field)
        if between["from_observation_id"] != pre_baseline["before"]:
            _fail("between_delta_source_mismatch", field)
        if (
            latest_baseline is not None
            and latest_baseline["observation_id"]
            == between["from_observation_id"]
            and not _endpoint_matches(between, "from", latest_baseline)
        ):
            _fail("between_delta_source_mismatch", field)
        if pre_baseline["before"] is None:
            expected_between = (
                "no_baseline" if pre["status"] == "complete" else "incomplete"
            )
        elif pre["status"] != "complete":
            expected_between = "incomplete"
        elif between["from_scope"] != pre["scope"]:
            expected_between = "incompatible_scope"
        else:
            expected_between = None
        if (
            expected_between is not None
            and between["comparability"] != expected_between
        ):
            _fail("between_delta_comparability_mismatch", field)
        if (
            expected_between is None
            and between["comparability"] not in ("exact", "degraded")
        ):
            _fail("between_delta_comparability_mismatch", field)
        if between["comparability"] in ("exact", "degraded"):
            if (
                latest_baseline is not None
                and latest_baseline["observation_id"]
                == between["from_observation_id"]
            ):
                comparison_source = latest_baseline
            else:
                comparison_source = _reconstructed_source_observation(
                    between
                )
            reconstructed_target = {
                change["container_name"]: change["after"]
                for change in between["changes"]
                if change["after"] is not None
            }
            if reconstructed_target != pre["containers"]:
                _fail("between_delta_target_catalogue_mismatch", field)
            _validate_recomputable_delta(
                between,
                comparison_source,
                pre,
                field + ".between_observation_delta",
            )
        if record["created_at"] != pre["observed_at"]:
            _fail("record_created_at_mismatch", field)

    if post is None:
        if any(
            value is not None
            for value in (post_signature_value, run_window, post_baseline)
        ):
            _fail("absent_post_has_post_fields", field)
        if pre is None:
            _fail("empty_record", field)
        if record["updated_at"] != pre["observed_at"]:
            _fail("record_updated_at_mismatch", field)
    else:
        if post_signature_value is None or post_baseline is None:
            _fail("present_post_missing_fields", field)
        if post_signature_value != phase_signature(
            "post", instance_id, post["scope"], correlation
        ):
            _fail("stale_post_signature", field + ".post_signature")
        validate_baseline(post_baseline, field + ".post_baseline")
        if record["updated_at"] != post["observed_at"]:
            _fail("record_updated_at_mismatch", field)
        if pre is None:
            if run_window is not None:
                _fail("post_only_has_run_window_delta", field)
            if record["created_at"] != post["observed_at"]:
                _fail("record_created_at_mismatch", field)
        else:
            if run_window is None:
                _fail("missing_run_window_delta", field)
            validate_delta(run_window, field + ".run_window_delta")
            if not _endpoint_matches(run_window, "from", pre):
                _fail("run_window_source_mismatch", field)
            if not _endpoint_matches(run_window, "to", post):
                _fail("run_window_target_mismatch", field)
            if pre["status"] != "complete" or post["status"] != "complete":
                expected_run_comparability = "incomplete"
            elif pre["scope"] != post["scope"]:
                expected_run_comparability = "incompatible_scope"
            else:
                expected_run_comparability = None
            if (
                expected_run_comparability is not None
                and run_window["comparability"] != expected_run_comparability
            ):
                _fail("run_window_comparability_mismatch", field)
            if (
                expected_run_comparability is None
                and run_window["comparability"] not in ("exact", "degraded")
            ):
                _fail("run_window_comparability_mismatch", field)
            _validate_recomputable_delta(
                run_window,
                pre,
                post,
                field + ".run_window_delta",
            )
            if post_baseline["before"] != pre_baseline["before"]:
                _fail("post_baseline_source_mismatch", field)
        if post["status"] == "complete":
            if (
                not post_baseline["advanced"]
                or post_baseline["after"] != post["observation_id"]
            ):
                _fail("complete_post_baseline_mismatch", field)
        else:
            if (
                post_baseline["advanced"]
                or post_baseline["after"] != post_baseline["before"]
            ):
                _fail("noncomplete_post_baseline_mismatch", field)

    expected_status = _derived_status(pre, post)
    if record["status"] != expected_status:
        _fail("journal_status_mismatch", field + ".status")
    return record


def validate_state_store(store, expected_instance_id=None, release=True):
    """Validate the exact closed v1 StateStore shape and cross-field invariants."""

    _require_exact_keys(store, STATE_KEYS, "state")
    if store["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported_store_schema_version", "state.schema_version")
    if store["comparison_schema_version"] != COMPARISON_SCHEMA_VERSION:
        _fail(
            "unsupported_comparison_schema_version",
            "state.comparison_schema_version",
        )
    instance_id = validate_instance_id(store["instance_id"], "state.instance_id")
    if expected_instance_id is not None and instance_id != expected_instance_id:
        _fail("store_instance_mismatch", "state.instance_id")
    if not _is_int(store["revision"]) or store["revision"] < 0:
        _fail("invalid_revision", "state.revision")

    baseline = store["latest_complete_post"]
    if baseline is not None:
        validate_observation(baseline, "state.latest_complete_post", release=release)
        if baseline["status"] != "complete":
            _fail("baseline_not_complete", "state.latest_complete_post")

    journal = store["journal"]
    _require_list(journal, "state.journal")
    if len(journal) > 100:
        _fail("journal_record_limit_exceeded", "state.journal")
    record_ids = []
    expected_revisions = []
    for index, record in enumerate(journal):
        _validate_record(
            record,
            store["revision"],
            instance_id,
            baseline,
            "state.journal[{0}]".format(index),
            release,
        )
        record_ids.append(record["record_id"])
        if record["expected_post_revision"] is not None:
            expected_revisions.append(record["expected_post_revision"])
    if len(record_ids) != len(set(record_ids)):
        _fail("duplicate_record_id", "state.journal")
    if expected_revisions != sorted(set(expected_revisions)):
        _fail("invalid_record_revision_order", "state.journal")

    recent = store["recently_pruned_record_ids"]
    _require_list(recent, "state.recently_pruned_record_ids")
    if len(recent) > 100:
        _fail(
            "recent_record_limit_exceeded",
            "state.recently_pruned_record_ids",
        )
    for index, record_id in enumerate(recent):
        validate_record_id(
            record_id, "state.recently_pruned_record_ids[{0}]".format(index)
        )
    if len(recent) != len(set(recent)):
        _fail("duplicate_recent_record_id", "state.recently_pruned_record_ids")
    if set(recent).intersection(record_ids):
        _fail("recent_record_still_in_journal", "state.recently_pruned_record_ids")
    if store["revision"] == 0 and (
        baseline is not None or journal or recent
    ):
        _fail("nonempty_revision_zero_store", "state")

    if journal:
        timeline_baseline = None
        timeline_initialized = False
        for record in journal:
            phase_baseline = (
                record["pre_baseline"]
                if record["pre_baseline"] is not None
                else record["post_baseline"]
            )
            phase_before = phase_baseline["before"]
            if not timeline_initialized:
                timeline_baseline = phase_before
                timeline_initialized = True
            elif phase_before != timeline_baseline:
                _fail("journal_baseline_timeline_mismatch", "state.journal")
            if (
                record["post_baseline"] is not None
                and record["post_baseline"]["advanced"]
            ):
                timeline_baseline = record["post"]["observation_id"]
        durable_baseline_id = (
            None if baseline is None else baseline["observation_id"]
        )
        if timeline_baseline != durable_baseline_id:
            _fail(
                "journal_baseline_timeline_mismatch",
                "state.latest_complete_post",
            )

    if baseline is not None:
        advancing_posts = [
            record["post"]
            for record in journal
            if record["post_baseline"] is not None
            and record["post_baseline"]["advanced"]
        ]
        if (
            advancing_posts
            and advancing_posts[-1] != baseline
        ):
            _fail("latest_baseline_mismatch", "state.latest_complete_post")
    return store


def canonical_store_bytes(store, expected_instance_id=None, release=True):
    validate_state_store(
        store, expected_instance_id=expected_instance_id, release=release
    )
    return canonical_json_bytes(store)
