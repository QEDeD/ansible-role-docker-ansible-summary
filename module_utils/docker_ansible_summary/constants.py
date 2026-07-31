# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Frozen Docker Ansible Summary v1 contract constants.

This module is the single production owner for values shared across contract
boundaries.  The tuples are intentionally ordered.  Changing a schema version,
an ordered tuple, a public name, or a protocol grammar is a contract change,
not a cosmetic refactor.
"""

ROLE_SCHEMA_VERSION = 1
COMPARISON_SCHEMA_VERSION = 1
SIGNATURE_SCHEMA_VERSION = 1
PRESENTATION_SCHEMA_VERSION = 1

ACTIVE_RUNTIME_STATES = frozenset(("running", "paused", "restarting"))
INACTIVE_RUNTIME_STATES = frozenset(("created", "removing", "stopped", "dead"))
RUNTIME_STATES = ACTIVE_RUNTIME_STATES | INACTIVE_RUNTIME_STATES

CHANGE_KIND_ORDER = (
    "added",
    "removed",
    "recreated",
    "image_changed",
    "started",
    "stopped",
    "restarted",
    "state_changed",
    "unchanged",
)

MATERIAL_CHANGE_KINDS = frozenset(CHANGE_KIND_ORDER[:-1])

DOCKER_WARNING_BY_REASON = {
    "docker_cli_absent": "Docker CLI is unavailable",
    "docker_daemon_unreachable": "Docker daemon was unreachable",
    "docker_daemon_unauthorized": "Docker daemon access was unauthorized",
    "docker_unavailable": "Docker daemon was unavailable",
    "docker_command_timeout": "Docker discovery command timed out",
    "docker_output_limit_exceeded": (
        "Docker discovery output exceeded the byte limit"
    ),
    "docker_protocol_error": "Docker discovery output violated the v1 protocol",
    "discovery_capacity_exceeded": (
        "Docker catalogue exceeded the 4096-container limit"
    ),
    "inspect_identifier_argv_too_large": (
        "A selected container identifier exceeded the inspect argument limit"
    ),
    "required_field_missing": (
        "Required container evidence is missing; inspect metadata_gaps"
    ),
    "scope_membership_unknown": "Container scope membership is unknown",
    "unsupported_runtime_state": (
        "A selected container reported an unsupported runtime state"
    ),
}
DOCKER_REASON_CODES = frozenset(DOCKER_WARNING_BY_REASON)

CONTAINER_NAME_PATTERN = r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z"
CONTAINER_ID_PATTERN = r"\A[0-9a-f]{64}\Z"
IMAGE_ID_PATTERN = r"\Asha256:[0-9a-f]{64}\Z"

PUBLIC_INPUT_NAMES = frozenset(
    (
        "enabled",
        "operation",
        "instance_id",
        "scope",
        "record_id",
        "state_root",
        "journal_max_records",
        "state_max_bytes",
        "correlation_id",
        "report_mode",
        "report_width",
        "discovery_timeout_seconds",
        "failure_policy",
    )
)
PUBLIC_PREFIX = "docker_ansible_summary_"
REMOVED_PREFIX = "docker_summary_"
OUTPUT_VARIABLE = "docker_ansible_summary_result"
REMOVED_PUBLIC_SUFFIXES = frozenset(
    (
        "history_max_entries",
        "retention_days",
        "show_history",
        "versions_fact_file",
        "history_fact_file",
        "display_state_fact_file",
        "facts_dir",
        "write_facts",
        "write_facts_become",
        "enable_discovery",
        "container_overrides",
        "ansible_local_override",
        "mock_mode",
        "mock_metadata",
        "display",
        "quiet_tasks",
        "table_style_unicode",
        "table_auto_width",
        "table_show_notes",
        "table_notes_include_state",
        "version_extract_smart",
        "mode",
        "service_filter",
        "view_mode",
    )
)

SUMMARY_LABEL_ORDER = (
    "added",
    "removed",
    "recreated",
    "recreated+img",
    "recreated+ref",
    "recreated+img+ref",
    "img changed",
    "ref changed",
    "img+ref changed",
    "started",
    "stopped",
    "restarted",
    "state changed",
    "unchanged",
)

RUN_WINDOW_COLUMNS = ("CONTAINER", "BEFORE", "AFTER", "CHANGE")
ENDPOINT_COLUMNS = ("CONTAINER", "IMAGE", "STATE")

REQUIRED_CONTAINER_FIELDS = (
    "name",
    "container_id",
    "full_image_reference",
    "image_id",
    "runtime_state",
)

OBSERVATION_STATUS_WARNING = {
    "partial": (
        "Observation partial: known rows only; absence is not authoritative."
    ),
    "unavailable": (
        "Observation unavailable: no container state observed; absence is not "
        "authoritative."
    ),
}

REPORT_MODEL_FIELDS = frozenset(
    (
        "presentation_schema_version",
        "header",
        "primary_table",
        "between_observation_summary",
        "run_window_notice",
        "counts",
        "warnings",
        "baseline_outcome",
        "journal_status",
        "persistence_outcome",
    )
)

REPORT_HEADER_FIELDS = frozenset(
    (
        "host",
        "instance_id",
        "operation",
        "observed_at",
        "observation_status",
        "correlation_id",
        "simulated",
        "replay_outcome",
    )
)

REPORT_TABLE_FIELDS = frozenset(("kind", "columns", "rows"))
REPORT_NOTICE_FIELDS = frozenset(("comparability", "message"))

DELTA_RESULT_FIELDS = frozenset(
    (
        "comparability",
        "comparison_schema_version",
        "from_observation_id",
        "from_observed_at",
        "from_scope",
        "to_observation_id",
        "to_observed_at",
        "to_scope",
        "changes",
        "warnings",
    )
)

CONTAINER_DELTA_FIELDS = frozenset(
    (
        "container_name",
        "primary_kind",
        "kinds",
        "before",
        "after",
        "image_reference_changed",
        "image_content_changed",
        "image_content_evidence",
    )
)

MAX_WARNING_ENTRIES = 64
MAX_WARNING_ITEM_BYTES = 256
MAX_WARNING_SERIALIZED_BYTES = 8192
