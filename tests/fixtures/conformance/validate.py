# SPDX-FileCopyrightText: 2026 MDAD project contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate the synthetic planning fixtures for the DAS rewrite.

This is deliberately a fixture linter, not a DAS reference implementation.
It checks that the planning corpus is internally well-formed and that the
coverage inventory does not silently shrink.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
    from yaml.constructor import ConstructorError
except ImportError as error:  # pragma: no cover - environment diagnostic
    print(f"ERROR: PyYAML is required to validate DAS fixtures: {error}", file=sys.stderr)
    raise SystemExit(2) from error


ROOT = Path(__file__).resolve().parent
SPDX_COPYRIGHT = "SPDX-File" "CopyrightText:"
SPDX_LICENSE = "SPDX-License-" "Identifier: AGPL-3.0-or-later"
HEX_64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
SHA256_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
CONTAINER_ID_RE = re.compile(r"\A[0-9a-f]{64}\Z")
CONTAINER_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
INSTANCE_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")
RECORD_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SCOPE_PATTERN_RE = re.compile(r"\A[A-Za-z0-9_.?*\[\]!-]+\Z")
PRINTABLE_ASCII_RE = re.compile(r"\A[\x20-\x7e]+\Z")
REPOSITORY_COMPONENT_RE = re.compile(
    r"\A[a-z0-9]+(?:[._-][a-z0-9]+)*\Z"
)
AUTHORITY_LABEL_RE = re.compile(
    r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
CANONICAL_PORT_RE = re.compile(r"\A[1-9][0-9]{0,4}\Z")
UTC_TIMESTAMP_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.(?P<fraction>\d{1,9}))?Z\Z"
)
NUMBERED_FILE_RE = re.compile(
    r"\A(?P<id>\d{2})-[a-z0-9][a-z0-9-]*\.yml\Z"
)

EXACT_REPORT_MODEL_FIELDS = {
    "report_model": [
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
    ],
    "report_header": [
        "host",
        "instance_id",
        "operation",
        "observed_at",
        "observation_status",
        "correlation_id",
        "simulated",
        "replay_outcome",
    ],
    "report_table": ["kind", "columns", "rows"],
    "run_window_row": [
        "container_name",
        "machine_before",
        "machine_after",
        "cells",
    ],
    "endpoint_row": ["container_name", "machine_current", "cells"],
    "run_window_cells": ["container", "before", "after", "change"],
    "endpoint_cells": ["container", "image", "state"],
    "report_notice": ["comparability", "message"],
}

PRIMARY_KIND_PRECEDENCE_ORDER = [
    "added",
    "removed",
    "recreated",
    "image_changed",
    "started",
    "stopped",
    "restarted",
    "state_changed",
    "unchanged",
]

ENDPOINT_COUNT_FIELDS = [
    "authoritative_changes",
    "known_rows",
    "rows_with_required_gaps",
]

EXACT_CORE_MODEL_FIELDS = {
    "scope": ["patterns", "identity", "comparison_schema_version"],
    "state_store": [
        "schema_version",
        "comparison_schema_version",
        "instance_id",
        "revision",
        "latest_complete_post",
        "journal",
        "recently_pruned_record_ids",
    ],
    "run_record": [
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
    ],
    "observation": [
        "observation_id",
        "observed_at",
        "scope",
        "status",
        "reason_code",
        "warnings",
        "discovery_backend",
        "metadata_gaps",
        "containers",
    ],
    "container_observation": [
        "name",
        "container_id",
        "full_image_reference",
        "image_id",
        "runtime_state",
        "created_at",
        "started_at",
        "finished_at",
        "restart_count",
    ],
    "delta_result": [
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
    ],
    "container_delta": [
        "container_name",
        "primary_kind",
        "kinds",
        "before",
        "after",
        "image_reference_changed",
        "image_content_changed",
        "image_content_evidence",
    ],
    "baseline_result": ["advanced", "before", "after"],
}

EXACT_PHASE_SIGNATURE_FIELDS = [
    "comparison_schema_version",
    "correlation_id",
    "instance_id",
    "operation",
    "scope",
    "signature_schema_version",
]

EXACT_FAILURE_ENVELOPE_FIELDS = [
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
]

FAILURE_REASON_VALUES = [
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
]

OBSERVATION_REASON_VALUES = [
    "docker_cli_absent",
    "docker_daemon_unreachable",
    "docker_daemon_unauthorized",
    "docker_unavailable",
    "docker_command_timeout",
    "docker_output_limit_exceeded",
    "docker_protocol_error",
    "discovery_capacity_exceeded",
    "inspect_identifier_argv_too_large",
    "required_field_missing",
    "scope_membership_unknown",
    "unsupported_runtime_state",
]

OBSERVATION_WARNING_BY_REASON = {
    "docker_cli_absent": "Docker CLI is unavailable",
    "docker_daemon_unreachable": "Docker daemon was unreachable",
    "docker_daemon_unauthorized": (
        "Docker daemon access was unauthorized"
    ),
    "docker_unavailable": "Docker daemon was unavailable",
    "docker_command_timeout": "Docker discovery command timed out",
    "docker_output_limit_exceeded": (
        "Docker discovery output exceeded the byte limit"
    ),
    "docker_protocol_error": (
        "Docker discovery output violated the v1 protocol"
    ),
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

REPORT_PRESENTATION_WARNING_BY_STATUS = {
    "complete": None,
    "partial": (
        "Observation partial: known rows only; absence is not authoritative."
    ),
    "unavailable": (
        "Observation unavailable: no container state observed; absence is "
        "not authoritative."
    ),
}

DELTA_WARNINGS_BY_COMPARABILITY = {
    "exact": [],
    "degraded": [],
    "no_baseline": [],
    "incomplete": [],
    "incompatible_scope": [],
}

REQUIRED_FAILURE_CALLBACK_OUTCOMES = [
    "fail_after_report",
    "validation_failure",
    "state_size_failure",
    "corrupt_state_failure",
    "lock_timeout_failure",
    "revision_conflict",
    "persistence_io_failure",
    "post_replace_state_write_failure",
    "render_failure_after_commit",
    "presentation_capacity_after_commit",
]

REPLAY_GUIDANCE_VALUES = [
    None,
    "Retry the retained record with failure_policy=report",
    "Retry the retained record with report_mode=none",
    "Retry with the same record_id and unchanged phase inputs",
]

EXPECTED_INVENTORY = {
    "scenarios": 22,
    "legacy": 5,
    "focused": 8,
}

EXPECTED_FOCUSED_CASES = {
    "operation_contract": {
        "disabled_short_circuits_before_validation",
        "pre_commits_open_record",
        "absent_store_unavailable_pre_commits_open",
        "complete_post_after_unavailable_pre_advances_baseline",
        "fail_after_report_commits_renders_then_fails",
        "retained_noncomplete_replay_reapplies_failure_policy",
        "check_pre_is_independent_simulation",
        "check_post_is_independent_simulation",
        "check_post_supplied_record_id_is_not_looked_up",
        "check_post_noncomplete_fail_after_report_is_store_free",
        "status_noncomplete_fail_after_report_is_store_free",
        "status_rejects_supplied_record_id",
        "incompatible_a_to_b_with_compatible_b_to_c",
        "deliberate_post_only_complete",
        "post_only_unavailable_commits_incomplete_both_without_deltas",
        "pre_cannot_fill_retained_post_only_record",
        "incomplete_pre_and_post",
        "correlation_inherits_to_matching_post_and_header",
        "correlation_mismatch_conflicts_before_discovery",
        "correlation_is_grouping_not_lookup",
        "correlation_validation_is_bounded",
    },
    "change_kinds": {
        "delta_endpoint_shapes",
        "restart_evidence_comparability_matrix",
        "same_container_restarted_by_start_time",
        "same_container_restarted_by_restart_count",
        "active_state_changed_paused_to_running",
        "inactive_state_changed_created_to_stopped",
        "same_container_reference_only_image_change",
        "same_container_same_tag_new_image_id",
    },
    "persistence": {
        "state_root_lexical_contract",
        "instance_id_namespace_grammar",
        "secure_posix_namespace_is_accepted",
        "unsafe_preexisting_namespace_fails_closed",
        "absent_namespace_creation_is_operation_bounded",
        "stable_lock_and_atomic_commit_trace",
        "preexisting_temporary_names_are_ignored",
        "fault_before_atomic_replace",
        "fault_after_replace_before_directory_fsync",
        "lost_ack_replay_with_caller_id",
        "delayed_pre_replay_after_completed_post",
        "lost_ack_replay_of_committed_post",
        "retained_delta_preserves_endpoint_context",
        "retained_record_signature_conflict",
        "recently_pruned_record_conflict",
        "record_pruned_during_discovery",
        "concurrent_same_phase_commit_becomes_idempotent_replay",
        "concurrent_pre_commit_becomes_idempotent_replay",
        "never_known_record",
        "retention_prunes_oldest_open_record",
        "recent_id_cap_evicts_oldest",
        "store_byte_cap_prunes_oldest_full_record",
        "required_state_exceeds_byte_cap_fails",
        "render_failure_after_commit",
        "presentation_capacity_failure_after_commit",
        "canonical_complete_store_known_answer",
        "invalid_existing_store_fails_closed",
        "state_lock_timeout_is_bounded",
        "oversized_existing_store_fails_before_parse",
        "canonical_byte_pressure_prunes_real_serialization",
    },
    "normalization": {
        "scalar_scope",
        "sort_and_deduplicate",
        "explicit_all",
        "invalid_empty",
        "invalid_whitespace_scalar",
        "invalid_mixed_empty_entry",
        "fnmatchcase_full_name_dialect",
        "invalid_scope_pattern_characters",
        "scope_pattern_item_byte_bound",
        "scope_pattern_count_bound",
        "scope_pattern_total_byte_bound",
        "api_leading_slash_and_registry_port",
        "digest_reference_preserved",
        "untagged_reference_preserved",
        "raw_exited_normalizes_to_stopped",
        "unknown_runtime_makes_observation_partial",
        "docker_zero_time_sentinels_normalize_to_null",
        "invalid_optional_evidence_normalizes_to_gap",
        "canonical_observation_bounds_and_allowlist_reject_mutations",
        "complete_empty_catalogue",
        "docker_cli_absent",
        "docker_daemon_unreachable",
        "docker_daemon_unauthorized",
        "catalogue_deadline_is_unavailable",
        "selected_inspect_deadline_is_partial",
        "monotonic_deadline_decreases_across_container_chunks",
        "failed_inspect_chunk_is_atomic_and_stops_later_chunks",
        "selected_container_inspect_failure_is_partial",
        "malformed_catalogue_is_protocol_unavailable",
        "catalogue_capacity_is_unavailable",
        "inspect_selected_id_disappears",
        "inspect_identity_mismatch_is_partial",
        "inspect_name_mismatch_is_scope_unknown",
        "inspect_output_cap_is_partial",
        "known_out_of_scope_catalogue_row_is_not_inspected",
        "catalogue_name_missing_is_partial",
        "mixed_catalogue_case_sensitive_overlapping_scope",
        "explicit_all_selects_mixed_catalogue",
    },
    "legacy_boundary": {
        "core_role_rejects_legacy_initialize",
        "canonical_store_rejects_legacy_field",
        "native_observation_does_not_read_cutover_report",
        "first_native_post_after_cutover_establishes_baseline",
        "valid_legacy_assessment_writes_only_mdad_report",
        "missing_legacy_sources_is_clean_fresh_start",
        "malformed_legacy_source_is_backed_up_and_blocks",
        "unresolved_legacy_conflict_is_backed_up_and_blocks",
        "explicit_source_policy_resolves_legacy_conflict",
        "repeated_assessment_is_idempotent",
    },
    "presentation": {
        "lifecycle_messages_are_distinct",
        "machine_values_are_never_presentation_truncated",
        "host_blocks_identify_independent_results",
        "warning_normalization_is_exact_bounded_and_sorted",
        "warning_generation_aggregates_metadata_gaps",
        "comparable_post_includes_changed_and_unchanged_rows",
        "complete_all_removals_still_render_rows",
        "complete_empty_renders_explicit_zero_row_table",
        "incomplete_endpoint_shows_known_state_without_absence",
        "between_observation_summary_is_exact",
        "degraded_run_window_notice_is_exact",
        "unavailable_endpoint_renders_no_invented_rows",
        "status_uses_current_state_columns",
        "baseline_null_endpoint_rendering_is_exact",
        "table_selection_and_footer_matrix_is_exact",
        "header_truthfulness_annotations_are_exact",
        "semantic_missing_tokens_are_distinct",
        "visible_escape_is_exact_utf8_byte_projection",
        "container_shortening_and_collision_are_exact",
        "change_vocabulary_is_closed_and_bounded",
        "same_tag_new_image_id_projects_distinct_row",
        "repository_change_equal_image_id_projects_distinct_row",
        "tag_digest_change_equal_image_id_projects_distinct_row",
        "callback_transport_is_atomic_and_unescaped",
        "structured_stdout_callback_is_not_human_report_transport",
        "failed_callback_uses_bounded_envelope",
        "ascii_layout_is_deterministic_and_aligned",
    },
    "execution_surface": {
        "public_input_contract_is_frozen",
        "complete_pre_default_is_quiet",
        "complete_post_emits_one_final_block",
        "status_emits_one_store_free_block",
        "complete_empty_uses_only_catalogue_process",
        "complete_all_removals_zero_current_still_reports_union_rows",
        "omitted_report_mode_defaults_final_and_display_is_last",
        "large_catalogue_task_count_is_constant",
        "synthetic_scaling_guard_100_to_1000",
        "near_cap_store_rewrite_is_measured_and_bounded",
        "argument_byte_limit_splits_before_item_limit",
        "disabled_short_circuit_has_no_work",
        "static_import_repeated_handoff_is_host_local",
        "dynamic_include_exceeds_reference_event_budget",
        "enabled_missing_inputs_fails_before_module",
        "module_result_is_sanitized",
        "oversize_identifier_is_not_invoked_or_echoed",
        "partial_pre_final_emits_one_warning_without_table",
        "unavailable_pre_final_emits_one_warning_without_table",
        "each_mode_pre_emits_one_block",
        "none_mode_noncomplete_warning_matrix_is_exact",
        "none_mode_suppresses_table_not_machine_result",
        "none_mode_fail_after_report_keeps_minimum_safe_diagnostic",
        "phase_signature_known_answer",
        "phase_signature_non_ascii_correlation_known_answer",
        "observed_at_opens_bounded_sampling_interval",
        "production_docker_argv_projection_and_caps_are_exact",
        "fake_docker_transcript_projects_one_selected_container",
        "fake_docker_no_such_object_race_is_partial",
        "fake_docker_success_with_bounded_stderr_is_accepted",
    },
    "image_display": {
        "registry_port_with_explicit_tag",
        "registry_port_without_explicit_tag",
        "digest_reference",
        "tag_plus_digest_reference",
        "bare_image_id_reference",
        "reference_grammar_boundaries_are_exact",
        "opaque_tags_are_preserved_not_ordered",
        "repository_collision_expands_context",
        "mutable_tag_adds_image_id_evidence",
        "long_colliding_references_preserve_suffix_and_identity",
        "colliding_short_id_prefix_extends_until_unique",
        "report_wide_repository_collisions_are_globally_unique",
        "readable_collision_fallback_uses_hash_suffix",
        "colliding_digest_prefix_extends_until_unique",
        "hash_prefix_extends_past_four_until_unique",
        "presentation_capacity_failure_is_bounded",
        "missing_reference_never_uses_identifier_fallback",
        "opaque_long_reference_escapes_then_shortens_atoms",
        "opaque_width_collision_uses_identity_hash",
        "opaque_equal_reference_adds_image_id_evidence",
        "opaque_minimum_and_default_run_window_budgets",
        "unsupported_digest_algorithm_is_opaque",
        "unsupported_authority_is_opaque",
        "unsupported_repository_component_is_opaque",
        "unsupported_reference_is_opaque_not_guessed",
    },
}

EXPECTED_LEGACY_VARIANTS = {
    "valid",
    "missing",
    "partial",
    "malformed",
    "valid_source_conflict",
}


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses duplicate mapping keys."""

    def construct_mapping(
        self, node: yaml.nodes.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        if not isinstance(node, yaml.nodes.MappingNode):
            raise ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )

        authored_keys: set[Any] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in authored_keys
            except TypeError as error:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            authored_keys.add(key)

        # SafeLoader implements YAML merge-key precedence. Checking authored
        # keys before this call rejects true duplicates without rejecting an
        # intentional local override of a value inherited through ``<<``.
        return super().construct_mapping(node, deep=deep)


class Validator:
    """Accumulate actionable fixture validation errors."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.schema: dict[str, Any] = {}
        self.documents: dict[Path, dict[str, Any]] = {}

    def error(self, path: Path, context: str, message: str) -> None:
        location = path.relative_to(ROOT)
        suffix = f": {context}" if context else ""
        self.errors.append(f"{location}{suffix}: {message}")

    def require(
        self, condition: bool, path: Path, context: str, message: str
    ) -> bool:
        if not condition:
            self.error(path, context, message)
            return False
        return True

    def require_keys(
        self,
        value: Any,
        keys: Iterable[str],
        path: Path,
        context: str,
    ) -> bool:
        if not self.require(
            isinstance(value, dict), path, context, "must be a mapping"
        ):
            return False
        missing = [key for key in keys if key not in value]
        return self.require(
            not missing,
            path,
            context,
            f"missing required key(s): {', '.join(missing)}",
        )

    def enum(
        self,
        value: Any,
        allowed: Iterable[Any],
        path: Path,
        context: str,
        *,
        nullable: bool = False,
    ) -> None:
        allowed_values = set(allowed)
        if value is None and nullable:
            return
        self.require(
            value in allowed_values,
            path,
            context,
            f"expected one of {sorted(allowed_values)!r}, got {value!r}",
        )

    def validate(self) -> int:
        self.validate_spdx_headers()
        self.load_yaml_documents()
        if self.schema:
            self.validate_inventory()
            self.validate_numbered_scenarios()
            self.validate_legacy_fixtures()
            self.validate_focused_fixtures()

        if self.errors:
            print(
                f"DAS fixture validation failed with {len(self.errors)} error(s):",
                file=sys.stderr,
            )
            for error in self.errors:
                print(f"- {error}", file=sys.stderr)
            return 1

        fixture_count = sum(EXPECTED_INVENTORY.values())
        print(
            "DAS fixture validation passed: "
            f"{fixture_count} fixture files "
            f"({EXPECTED_INVENTORY['scenarios']} numbered, "
            f"{EXPECTED_INVENTORY['legacy']} legacy, "
            f"{EXPECTED_INVENTORY['focused']} focused)."
        )
        return 0

    def validate_spdx_headers(self) -> None:
        artifact_paths = [
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and path.suffix in {".md", ".py", ".yml"}
            and "__pycache__" not in path.parts
        ]
        for path in sorted(artifact_paths):
            try:
                first_lines = path.read_text(encoding="utf-8").splitlines()[:12]
            except OSError as error:
                self.error(path, "", f"could not read file: {error}")
                continue
            self.require(
                any(SPDX_COPYRIGHT in line for line in first_lines),
                path,
                "SPDX",
                "missing SPDX-FileCopyrightText header near the start of the file",
            )
            self.require(
                any(SPDX_LICENSE in line for line in first_lines),
                path,
                "SPDX",
                f"missing {SPDX_LICENSE!r} near the start of the file",
            )

    def load_yaml_documents(self) -> None:
        for path in sorted(ROOT.rglob("*.yml")):
            try:
                document = yaml.load(
                    path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader
                )
            except (OSError, yaml.YAMLError) as error:
                self.error(path, "YAML", str(error))
                continue
            if not self.require(
                isinstance(document, dict),
                path,
                "YAML",
                "top-level document must be a mapping",
            ):
                continue
            self.documents[path] = document

        schema_path = ROOT / "schema.yml"
        self.schema = self.documents.get(schema_path, {})
        if not self.schema:
            self.error(schema_path, "schema", "schema could not be loaded")

    def validate_inventory(self) -> None:
        routed = {
            "scenarios": sorted((ROOT / "scenarios").glob("*.yml")),
            "legacy": sorted((ROOT / "legacy").glob("*.yml")),
            "focused": sorted((ROOT / "focused").glob("*.yml")),
        }
        for family, paths in routed.items():
            self.require(
                len(paths) == EXPECTED_INVENTORY[family],
                ROOT / family,
                "inventory",
                f"expected exactly {EXPECTED_INVENTORY[family]} YAML files, "
                f"found {len(paths)}",
            )

        allowed = {ROOT / "schema.yml"}
        for paths in routed.values():
            allowed.update(paths)
        unexpected = set(self.documents) - allowed
        for path in sorted(unexpected):
            self.error(
                path,
                "routing",
                "YAML file is outside schema.yml, scenarios/, legacy/, or focused/",
            )

        routing = self.schema.get("fixture_family_routing")
        self.require_keys(
            routing,
            ["numbered_scenario", "legacy_companion", "focused_cases"],
            ROOT / "schema.yml",
            "fixture_family_routing",
        )
        canonical_model = self.schema.get("canonical_model", {})
        for model_name, exact_fields in EXACT_CORE_MODEL_FIELDS.items():
            self.require(
                canonical_model.get(model_name, {}).get("exact_fields")
                == exact_fields,
                ROOT / "schema.yml",
                f"canonical_model.{model_name}.exact_fields",
                "must match the validator-owned frozen v1 field sequence",
            )
        for model_name, exact_fields in EXACT_REPORT_MODEL_FIELDS.items():
            self.require(
                canonical_model.get(model_name, {}).get("exact_fields")
                == exact_fields,
                ROOT / "schema.yml",
                f"canonical_model.{model_name}.exact_fields",
                "must match the validator-owned frozen v1 field sequence",
            )
        report_counts = canonical_model.get("report_counts", {})
        run_window_counts = report_counts.get("run_window", {})
        endpoint_counts = report_counts.get("endpoint", {})
        rendered_count_order = report_counts.get("rendered_order", {})
        self.require(
            run_window_counts.get("permitted_kind_fields")
            == PRIMARY_KIND_PRECEDENCE_ORDER
            and run_window_counts.get("required_fields") == ["total"]
            and run_window_counts.get("kind_field_inclusion")
            == "nonzero_only"
            and endpoint_counts.get("table_kinds")
            == ["current", "known_endpoint"]
            and endpoint_counts.get("exact_fields")
            == ENDPOINT_COUNT_FIELDS
            and rendered_count_order.get("run_window")
            == [*PRIMARY_KIND_PRECEDENCE_ORDER, "total"]
            and rendered_count_order.get("endpoint")
            == ENDPOINT_COUNT_FIELDS,
            ROOT / "schema.yml",
            "canonical_model.report_counts",
            "must match the validator-owned closed count shapes and render "
            "orders",
        )
        failure_envelope = canonical_model.get("failure_envelope", {})
        self.require(
            failure_envelope.get("exact_fields")
            == EXACT_FAILURE_ENVELOPE_FIELDS,
            ROOT / "schema.yml",
            "canonical_model.failure_envelope.exact_fields",
            "must match the validator-owned frozen failure-envelope sequence",
        )
        self.require(
            failure_envelope.get("failure_reason_values")
            == FAILURE_REASON_VALUES,
            ROOT / "schema.yml",
            "canonical_model.failure_envelope.failure_reason_values",
            "must match the validator-owned frozen failure-reason sequence",
        )
        self.require(
            failure_envelope.get("replay_guidance_values")
            == REPLAY_GUIDANCE_VALUES,
            ROOT / "schema.yml",
            "canonical_model.failure_envelope.replay_guidance_values",
            "must match the validator-owned fixed replay-guidance templates",
        )
        self.require(
            canonical_model.get("phase_signature", {}).get(
                "exact_input_fields"
            )
            == EXACT_PHASE_SIGNATURE_FIELDS,
            ROOT / "schema.yml",
            "canonical_model.phase_signature.exact_input_fields",
            "must match the validator-owned frozen signature-field sequence",
        )
        self.require(
            self.schema.get("observation", {}).get("reason_code_values")
            == OBSERVATION_REASON_VALUES,
            ROOT / "schema.yml",
            "observation.reason_code_values",
            "must match the validator-owned frozen observation-reason sequence",
        )
        observation_schema = self.schema.get("observation", {})
        self.require(
            observation_schema.get("reason_warning_templates")
            == OBSERVATION_WARNING_BY_REASON
            and observation_schema.get("generated_warning_policy")
            == {
                "complete_observation_count": 0,
                "noncomplete_observation_count": 1,
                "observed_identifiers_interpolated": False,
                "per_delta_count_max": 0,
                "report_presentation_warning_count_max": 1,
                "report_presentation_warning_templates": (
                    REPORT_PRESENTATION_WARNING_BY_STATUS
                ),
                "incompatible_scope_uses_notice_not_warning": True,
                "opaque_reference_uses_projection_not_warning": True,
            },
            ROOT / "schema.yml",
            "observation warning generation",
            "must match the validator-owned fixed, identifier-free warning "
            "mapping and count policy",
        )
        self.require(
            canonical_model.get("delta_result", {}).get(
                "warning_templates"
            )
            == DELTA_WARNINGS_BY_COMPARABILITY,
            ROOT / "schema.yml",
            "canonical_model.delta_result.warning_templates",
            "must match the validator-owned exact comparability-warning "
            "mapping",
        )

    def validate_numbered_scenarios(self) -> None:
        paths = sorted((ROOT / "scenarios").glob("*.yml"))
        expected_ids = set(range(1, EXPECTED_INVENTORY["scenarios"] + 1))
        found_ids: set[int] = set()
        for path in paths:
            data = self.documents.get(path)
            if data is None:
                continue
            self.validate_numbered_scenario(path, data, found_ids)
        self.require(
            found_ids == expected_ids,
            ROOT / "scenarios",
            "scenario IDs",
            f"expected {sorted(expected_ids)}, found {sorted(found_ids)}",
        )

    def validate_numbered_scenario(
        self, path: Path, data: dict[str, Any], found_ids: set[int]
    ) -> None:
        required = self.schema.get("required_top_level", [])
        if not self.require_keys(data, required, path, "top level"):
            return

        scenario = data.get("scenario")
        scenario_required = self.schema.get("scenario", {}).get("required", [])
        if not self.require_keys(scenario, scenario_required, path, "scenario"):
            return
        scenario_id = scenario.get("id")
        if self.require(
            self.is_int(scenario_id) and 1 <= scenario_id <= 22,
            path,
            "scenario.id",
            "must be an integer from 1 through 22",
        ):
            self.require(
                scenario_id not in found_ids,
                path,
                "scenario.id",
                f"duplicate scenario ID {scenario_id}",
            )
            found_ids.add(scenario_id)
        self.require(
            isinstance(scenario.get("title"), str)
            and bool(scenario["title"].strip()),
            path,
            "scenario.title",
            "must be a non-empty string",
        )

        filename_match = NUMBERED_FILE_RE.fullmatch(path.name)
        if self.require(
            filename_match is not None,
            path,
            "filename",
            "must use NN-lowercase-kebab-case.yml",
        ) and self.is_int(scenario_id):
            self.require(
                int(filename_match.group("id")) == scenario_id,
                path,
                "filename",
                f"numeric prefix does not match scenario.id {scenario_id}",
            )
        if scenario_id == 22:
            self.require(
                path.name == "22-legacy-cutover-assessment.yml",
                path,
                "filename",
                "scenario 22 must be named 22-legacy-cutover-assessment.yml",
            )

        observations = data.get("observations")
        if not self.require(
            isinstance(observations, dict),
            path,
            "observations",
            "must be a mapping",
        ):
            return
        declared_operation = (
            data.get("invocation", {}).get("operation")
            if isinstance(data.get("invocation"), dict)
            else None
        )
        scenario_slots = self.schema.get("observation", {}).get(
            "scenario_slots", {}
        )
        slot_key = (
            "status_operation"
            if declared_operation == "status"
            else "endpoint_operations"
        )
        expected_slots = tuple(
            scenario_slots.get(
                slot_key,
                ["a", "b", "c", "current"]
                if declared_operation == "status"
                else ["a", "b", "c"],
            )
        )
        self.require(
            set(observations) == set(expected_slots),
            path,
            "observations",
            f"must contain exactly the {', '.join(expected_slots)} slots",
        )
        if declared_operation == "status":
            self.require(
                observations.get("b") is None and observations.get("c") is None,
                path,
                "observations",
                "status keeps B and C null; it must not model current as B",
            )
            self.require(
                isinstance(observations.get("current"), dict),
                path,
                "observations.current",
                "status requires a distinct current observation",
            )
        observation_ids: dict[str, str] = {}
        seen_observation_ids: set[str] = set()
        for endpoint in expected_slots:
            observation = observations.get(endpoint)
            if observation is None:
                continue
            self.validate_observation(
                path, f"observations.{endpoint}", observation
            )
            if isinstance(observation, dict):
                observation_id = observation.get("observation_id")
                if isinstance(observation_id, str):
                    self.require(
                        observation_id not in seen_observation_ids,
                        path,
                        f"observations.{endpoint}.observation_id",
                        f"duplicate observation ID {observation_id!r}",
                    )
                    seen_observation_ids.add(observation_id)
                    observation_ids[endpoint] = observation_id

        prior_state = data.get("prior_state")
        self.validate_prior_state(path, prior_state, observations)
        invocation = data.get("invocation")
        operation = self.validate_invocation(
            path, invocation, prior_state, observations
        )
        self.validate_oracle(
            path,
            data.get("oracle"),
            invocation,
            operation,
            observations,
            observation_ids,
            scenario_id,
        )
        if scenario_id == 8:
            journal = (
                prior_state.get("journal")
                if isinstance(prior_state, dict)
                else None
            )
            record = (
                journal[0]
                if isinstance(journal, list)
                and len(journal) == 1
                and isinstance(journal[0], dict)
                else {}
            )
            oracle = data.get("oracle")
            machine = (
                oracle.get("machine_result")
                if isinstance(oracle, dict)
                else None
            )
            correlation_id = (
                invocation.get("correlation_id")
                if isinstance(invocation, dict)
                else None
            )
            messages = (
                oracle.get("human", {}).get("minimum_messages")
                if isinstance(oracle, dict)
                else None
            )
            self.require(
                correlation_id == "deploy-20260108T100000Z-7f3a"
                and record.get("record_id") == invocation.get("record_id")
                and record.get("correlation_id") == correlation_id
                and isinstance(machine, dict)
                and machine.get("correlation_id") == correlation_id
                and isinstance(messages, list)
                and correlation_id in messages,
                path,
                "scenario 8 correlation",
                "post must repeat the pre-established opaque correlation and "
                "project it without using intent as comparison evidence",
            )

    def validate_observation(
        self, path: Path, context: str, observation: Any
    ) -> None:
        observation_schema = self.schema.get("observation", {})
        required = observation_schema.get("required_when_present", [])
        if not self.require_keys(observation, required, path, context):
            return
        self.require(
            set(observation).issubset(
                set(EXACT_CORE_MODEL_FIELDS["observation"])
            ),
            path,
            context,
            "contains an unknown observation key",
        )

        observation_id = observation.get("observation_id")
        self.require(
            isinstance(observation_id, str)
            and RECORD_ID_RE.fullmatch(observation_id) is not None,
            path,
            f"{context}.observation_id",
            "must satisfy the bounded record-ID grammar",
        )
        self.validate_timestamp(
            observation.get("observed_at"), path, f"{context}.observed_at"
        )
        status = observation.get("status")
        self.enum(
            status,
            observation_schema.get("status_values", []),
            path,
            f"{context}.status",
        )
        scope = observation.get("scope")
        self.validate_scope(path, f"{context}.scope", scope)

        conditional_required = (
            observation_schema.get("complete_observation_required", [])
            if status == "complete"
            else observation_schema.get("noncomplete_observation_required", [])
        )
        self.require_keys(observation, conditional_required, path, context)
        self.require(
            observation.get("discovery_backend")
            in {"synthetic", "docker_cli_v1"},
            path,
            f"{context}.discovery_backend",
            "must be synthetic fixture evidence or docker_cli_v1",
        )
        metadata_gaps = observation.get("metadata_gaps")
        self.validate_string_list(
            metadata_gaps, path, f"{context}.metadata_gaps"
        )
        allowed_gap_fields = {
            *EXACT_CORE_MODEL_FIELDS["container_observation"],
            "container_inspect",
        }

        def valid_gap_path(gap: Any) -> bool:
            if gap == "docker.catalogue":
                return True
            if not isinstance(gap, str) or "." not in gap:
                return False
            container_name, field = gap.rsplit(".", 1)
            return (
                CONTAINER_NAME_RE.fullmatch(container_name) is not None
                and len(container_name.encode("ascii")) <= 255
                and field in allowed_gap_fields
            )

        self.require(
            isinstance(metadata_gaps, list)
            and all(
                isinstance(gap, str) and gap.isascii()
                for gap in metadata_gaps
            )
            and metadata_gaps
            == sorted(
                set(metadata_gaps),
                key=lambda gap: gap.encode("ascii"),
            )
            and len(metadata_gaps) <= 40961
            and all(valid_gap_path(gap) for gap in metadata_gaps),
            path,
            f"{context}.metadata_gaps",
            "must be a unique ASCII-byte-sorted list of closed adapter paths",
        )
        gaps = set(metadata_gaps) if isinstance(metadata_gaps, list) else set()

        if status in {"partial", "unavailable"}:
            self.require(
                isinstance(observation.get("reason_code"), str)
                and bool(observation["reason_code"].strip()),
                path,
                f"{context}.reason_code",
                "must be a non-empty string for a non-complete observation",
            )
            warnings = observation.get("warnings")
            self.validate_string_list(warnings, path, f"{context}.warnings")
            self.require(
                isinstance(warnings, list)
                and warnings
                == [
                    OBSERVATION_WARNING_BY_REASON.get(
                        observation.get("reason_code")
                    )
                ],
                path,
                f"{context}.warnings",
                "must contain exactly the fixed identifier-free warning "
                "mapped from the primary reason",
            )
            self.enum(
                observation.get("reason_code"),
                observation_schema.get("reason_code_values", []),
                path,
                f"{context}.reason_code",
            )
        elif "warnings" in observation:
            self.validate_string_list(
                observation.get("warnings"), path, f"{context}.warnings"
            )
            self.require(
                observation.get("warnings") == [],
                path,
                f"{context}.warnings",
                "must be empty for a complete observation",
            )
        if status == "complete":
            self.require(
                observation.get("reason_code") is None,
                path,
                f"{context}.reason_code",
                "must be null or omitted-as-default for a complete observation",
            )
        if "reason_code" in observation:
            self.require(
                observation["reason_code"] is None
                or (
                    isinstance(observation["reason_code"], str)
                    and bool(observation["reason_code"].strip())
                ),
                path,
                f"{context}.reason_code",
                "must be null or a non-empty string",
            )
            if observation["reason_code"] is not None:
                self.enum(
                    observation["reason_code"],
                    observation_schema.get("reason_code_values", []),
                    path,
                    f"{context}.reason_code",
                )

        containers = observation.get("containers")
        if status == "unavailable":
            self.require(
                containers is None,
                path,
                f"{context}.containers",
                "must be null when observation status is unavailable",
            )
            return
        if not self.require(
            isinstance(containers, dict),
            path,
            f"{context}.containers",
            "must be a mapping for complete or partial observations",
        ):
            return
        self.require(
            len(containers) <= 4096,
            path,
            f"{context}.containers",
            "must contain at most 4096 normalized containers",
        )
        container_keys_are_ascii = all(
            isinstance(name, str) and name.isascii()
            for name in containers
        )
        self.require(
            container_keys_are_ascii
            and list(containers)
            == sorted(containers, key=lambda name: name.encode("ascii")),
            path,
            f"{context}.containers",
            "must be ordered by container-name ASCII bytes",
        )
        for container_key, container in containers.items():
            self.validate_container(
                path,
                f"{context}.containers.{container_key}",
                container_key,
                container,
                status,
                gaps,
                scope,
            )

    def validate_scope(
        self,
        path: Path,
        context: str,
        scope: Any,
        *,
        comparison_schema_version_optional: bool = False,
    ) -> None:
        required = list(
            self.schema.get("observation", {}).get("scope_required", [])
        )
        if comparison_schema_version_optional:
            required = [
                key for key in required if key != "comparison_schema_version"
            ]
        if not self.require_keys(scope, required, path, context):
            return
        patterns = scope.get("patterns")
        if not self.require(
            isinstance(patterns, list) and bool(patterns),
            path,
            f"{context}.patterns",
            "must be a non-empty list",
        ):
            return
        valid_patterns = all(
            isinstance(pattern, str)
            and bool(pattern)
            and pattern == pattern.strip()
            for pattern in patterns
        )
        self.require(
            valid_patterns,
            path,
            f"{context}.patterns",
            "entries must be non-empty, already-trimmed strings",
        )
        if valid_patterns:
            valid_patterns = (
                "all" not in patterns
                and len(patterns) <= 64
                and all(
                    SCOPE_PATTERN_RE.fullmatch(pattern) is not None
                    and len(pattern.encode("ascii")) <= 256
                    for pattern in patterns
                )
                and sum(len(pattern.encode("ascii")) for pattern in patterns)
                <= 4096
            )
            self.require(
                valid_patterns,
                path,
                f"{context}.patterns",
                "must use the printable-ASCII fnmatchcase dialect with at "
                "most 64 patterns, 256 bytes per pattern, and 4096 bytes "
                "across the normalized list",
            )
        if valid_patterns:
            self.require(
                patterns == sorted(set(patterns)),
                path,
                f"{context}.patterns",
                "must be sorted and deduplicated",
            )
            if "*" in patterns:
                self.require(
                    patterns == ["*"],
                    path,
                    f"{context}.patterns",
                    "explicit all must canonicalize to the single pattern '*'",
                )

        version = scope.get("comparison_schema_version", 1)
        self.require(
            self.is_int(version) and version > 0,
            path,
            f"{context}.comparison_schema_version",
            "must be a positive integer",
        )
        identity = scope.get("identity")
        self.require(
            isinstance(identity, str) and SHA256_RE.fullmatch(identity) is not None,
            path,
            f"{context}.identity",
            "must be sha256 followed by 64 lowercase hexadecimal characters",
        )
        if valid_patterns and self.is_int(version):
            canonical = json.dumps(
                {
                    "comparison_schema_version": version,
                    "patterns": patterns,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected_identity = "sha256:" + hashlib.sha256(
                canonical.encode("utf-8")
            ).hexdigest()
            self.require(
                identity == expected_identity,
                path,
                f"{context}.identity",
                f"does not match canonical scope JSON; expected {expected_identity}",
            )

    def validate_container(
        self,
        path: Path,
        context: str,
        container_key: Any,
        container: Any,
        observation_status: str,
        metadata_gaps: set[Any],
        scope: Any,
    ) -> None:
        observation_schema = self.schema.get("observation", {})
        required = observation_schema.get("container_required", [])
        if not self.require_keys(container, required, path, context):
            return
        self.require(
            set(container).issubset(
                set(EXACT_CORE_MODEL_FIELDS["container_observation"])
            ),
            path,
            context,
            "contains an unknown container-observation key",
        )
        name = container.get("name")
        self.require(
            isinstance(container_key, str)
            and isinstance(name, str)
            and container_key == name,
            path,
            f"{context}.name",
            "container map key and normalized name must be identical strings",
        )
        self.require(
            isinstance(name, str)
            and CONTAINER_NAME_RE.fullmatch(name) is not None,
            path,
            f"{context}.name",
            "must be a normalized Docker container name without a leading slash",
        )
        self.require(
            isinstance(name, str)
            and len(name.encode("ascii")) <= 255,
            path,
            f"{context}.name",
            "must contain at most 255 ASCII bytes",
        )
        if isinstance(name, str) and isinstance(scope, dict):
            patterns = scope.get("patterns", [])
            self.require(
                any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns),
                path,
                f"{context}.name",
                f"{name!r} is outside the observation scope {patterns!r}",
            )

        container_id = container.get("container_id")
        image_id = container.get("image_id")
        self.require(
            container_id is None
            or (
                isinstance(container_id, str)
                and CONTAINER_ID_RE.fullmatch(container_id) is not None
            ),
            path,
            f"{context}.container_id",
            "when non-null, must be exactly 64 lowercase hexadecimal characters",
        )
        self.require(
            image_id is None
            or (
                isinstance(image_id, str)
                and SHA256_RE.fullmatch(image_id) is not None
            ),
            path,
            f"{context}.image_id",
            "when non-null, must be sha256 followed by 64 lowercase hexadecimal characters",
        )
        image_reference = container.get("full_image_reference")
        self.require(
            image_reference is None
            or (
                isinstance(image_reference, str)
                and image_reference.isascii()
                and 1 <= len(image_reference.encode("ascii")) <= 4096
                and all(
                    0x21 <= byte <= 0x7E
                    for byte in image_reference.encode("ascii")
                )
            ),
            path,
            f"{context}.full_image_reference",
            "must be null or 1-4096 non-whitespace printable ASCII bytes",
        )

        runtime_state = container.get("runtime_state")
        self.enum(
            runtime_state,
            observation_schema.get("canonical_runtime_state_values", []),
            path,
            f"{context}.runtime_state",
            nullable=observation_status != "complete",
        )
        if observation_status == "complete":
            for field in required:
                self.require(
                    container.get(field) is not None,
                    path,
                    f"{context}.{field}",
                    "must be non-null in a complete observation",
                )
        else:
            for field in required:
                if container.get(field) is None:
                    gap = f"{name}.{field}"
                    self.require(
                        gap in metadata_gaps,
                        path,
                        f"{context}.{field}",
                        f"null required evidence must be declared as metadata gap {gap!r}",
                    )

        optional = observation_schema.get("container_optional", [])
        for field in optional:
            gap = f"{name}.{field}"
            self.require(
                field in container or gap in metadata_gaps,
                path,
                context,
                f"missing optional evidence {field!r} must be declared as metadata gap {gap!r}",
            )
        for field in [*required, *optional]:
            gap = f"{name}.{field}"
            value = container.get(field)
            if value is not None:
                self.require(
                    gap not in metadata_gaps,
                    path,
                    f"{context}.{field}",
                    f"available evidence must not retain stale gap {gap!r}",
                )
            elif field in {"created_at", "restart_count"}:
                self.require(
                    gap in metadata_gaps,
                    path,
                    f"{context}.{field}",
                    f"unavailable optional evidence must declare gap {gap!r}",
                )

        for field in ("created_at", "started_at", "finished_at"):
            if field in container and container[field] is not None:
                self.validate_timestamp(
                    container[field], path, f"{context}.{field}"
                )
        if "restart_count" in container and container["restart_count"] is not None:
            self.require(
                self.is_int(container["restart_count"])
                and container["restart_count"] >= 0,
                path,
                f"{context}.restart_count",
                "must be a non-negative integer or null",
            )

    def validate_prior_state(
        self,
        path: Path,
        prior_state: Any,
        observations: dict[str, Any],
    ) -> None:
        required = self.schema.get("prior_state", {}).get("required", [])
        if not self.require_keys(prior_state, required, path, "prior_state"):
            return
        self.require(
            isinstance(prior_state.get("exists"), bool),
            path,
            "prior_state.exists",
            "must be boolean",
        )
        self.require(
            self.is_int(prior_state.get("revision"))
            and prior_state["revision"] >= 0,
            path,
            "prior_state.revision",
            "must be a non-negative integer",
        )
        self.require(
            isinstance(prior_state.get("instance_id"), str)
            and bool(prior_state["instance_id"].strip()),
            path,
            "prior_state.instance_id",
            "must be a non-empty string",
        )
        latest = prior_state.get("latest_complete_post")
        self.require(
            latest is None
            or (isinstance(latest, str) and latest in observations),
            path,
            "prior_state.latest_complete_post",
            "must be null or an observations key",
        )
        if isinstance(latest, str) and latest in observations:
            referenced = observations[latest]
            self.require(
                isinstance(referenced, dict)
                and referenced.get("status") == "complete",
                path,
                "prior_state.latest_complete_post",
                "must reference a complete observation",
            )

        journal = prior_state.get("journal")
        if not self.require(
            isinstance(journal, list),
            path,
            "prior_state.journal",
            "must be a list",
        ):
            return
        stable_statuses = self.schema.get("oracle", {}).get(
            "stable_journal_status_values", []
        )
        record_ids: set[str] = set()
        for index, record in enumerate(journal):
            context = f"prior_state.journal[{index}]"
            if not self.require(
                isinstance(record, dict), path, context, "must be a mapping"
            ):
                continue
            record_id = record.get("record_id")
            self.require(
                isinstance(record_id, str) and bool(record_id.strip()),
                path,
                f"{context}.record_id",
                "must be a non-empty string",
            )
            if isinstance(record_id, str):
                self.require(
                    record_id not in record_ids,
                    path,
                    f"{context}.record_id",
                    f"duplicate journal record ID {record_id!r}",
                )
                record_ids.add(record_id)
            self.enum(
                record.get("status"),
                stable_statuses,
                path,
                f"{context}.status",
            )
            if "pre_observation" in record:
                self.require(
                    record["pre_observation"] in observations,
                    path,
                    f"{context}.pre_observation",
                    "must reference an observations key",
                )
            if "expected_post_revision" in record:
                self.require(
                    self.is_int(record["expected_post_revision"])
                    and record["expected_post_revision"] >= 0,
                    path,
                    f"{context}.expected_post_revision",
                    "must be a non-negative integer",
                )

    def validate_invocation(
        self,
        path: Path,
        invocation: Any,
        prior_state: Any,
        observations: dict[str, Any],
    ) -> Any:
        invocation_schema = self.schema.get("invocation", {})
        common_required = invocation_schema.get(
            "common_required", invocation_schema.get("required", [])
        )
        if not self.require_keys(
            invocation, common_required, path, "invocation"
        ):
            return None
        operation = invocation.get("operation")
        normal_operations = invocation_schema.get("operation_values", [])
        boundary_operations = invocation_schema.get(
            "boundary_operation_values", []
        )
        self.enum(
            operation,
            [*normal_operations, *boundary_operations],
            path,
            "invocation.operation",
        )
        instance_id = invocation.get("instance_id")
        self.require(
            isinstance(instance_id, str) and bool(instance_id.strip()),
            path,
            "invocation.instance_id",
            "must be a non-empty string",
        )
        if isinstance(prior_state, dict):
            self.require(
                instance_id == prior_state.get("instance_id"),
                path,
                "invocation.instance_id",
                "must match prior_state.instance_id",
            )
        if operation in normal_operations:
            self.require_keys(
                invocation,
                invocation_schema.get(
                    "required_for_observation_operations", []
                ),
                path,
                "invocation",
            )
            self.require(
                isinstance(invocation.get("check_mode"), bool),
                path,
                "invocation.check_mode",
                "must be boolean",
            )
            record_id = invocation.get("record_id")
            self.require(
                record_id is None
                or (isinstance(record_id, str) and bool(record_id.strip())),
                path,
                "invocation.record_id",
                "must be null or a non-empty string",
            )
            normalized_scope = self.normalize_scope_input(invocation.get("scope"))
            if operation == "post":
                target_endpoint = "c"
            elif operation == "status":
                target_endpoint = "current"
            else:
                target_endpoint = "b"
            target = observations.get(target_endpoint)
            if isinstance(target, dict):
                target_scope = target.get("scope")
                target_patterns = (
                    target_scope.get("patterns")
                    if isinstance(target_scope, dict)
                    else None
                )
                self.require(
                    normalized_scope == target_patterns,
                    path,
                    "invocation.scope",
                    f"must normalize to the {target_endpoint.upper()} observation scope",
                )
            for endpoint in ("b", "c"):
                if endpoint in invocation:
                    reference = invocation[endpoint]
                    self.require(
                        reference is None or reference == endpoint,
                        path,
                        f"invocation.{endpoint}",
                        f"must be null or reference observations.{endpoint}",
                    )
            if operation == "status":
                self.require(
                    invocation.get("current_observation") == "current",
                    path,
                    "invocation.current_observation",
                    "must reference observations.current",
                )
        elif operation in boundary_operations:
            self.require_keys(
                invocation,
                invocation_schema.get(
                    "required_for_boundary_operation", []
                ),
                path,
                "invocation",
            )
            self.require(
                isinstance(invocation.get("check_mode"), bool),
                path,
                "invocation.check_mode",
                "must be boolean",
            )
            self.require(
                all(observation is None for observation in observations.values()),
                path,
                "observations",
                "MDAD legacy assessment must not create a DAS observation",
            )
            self.require(
                "scope" not in invocation and "record_id" not in invocation,
                path,
                "invocation",
                "MDAD boundary assessment must not use DAS scope or record inputs",
            )
        return operation

    def validate_oracle(
        self,
        path: Path,
        oracle: Any,
        invocation: Any,
        operation: Any,
        observations: dict[str, Any],
        observation_ids: dict[str, str],
        scenario_id: Any,
    ) -> None:
        required = self.schema.get("oracle", {}).get("required", [])
        if not self.require_keys(oracle, required, path, "oracle"):
            return
        boundary_operations = set(
            self.schema.get("invocation", {}).get(
                "boundary_operation_values", []
            )
        )
        all_observation_ids = set(observation_ids.values())
        self.validate_delta(
            path,
            "oracle.between_observation_delta",
            oracle.get("between_observation_delta"),
            all_observation_ids,
            observation_ids.get("a"),
            observation_ids.get("b"),
        )
        self.validate_delta(
            path,
            "oracle.run_window_delta",
            oracle.get("run_window_delta"),
            all_observation_ids,
            observation_ids.get("b"),
            observation_ids.get("c"),
        )

        baseline = oracle.get("baseline")
        if baseline is not None:
            baseline_required = self.schema.get("oracle", {}).get(
                "baseline_required", []
            )
            if self.require_keys(
                baseline, baseline_required, path, "oracle.baseline"
            ):
                self.require(
                    isinstance(baseline.get("advanced"), bool),
                    path,
                    "oracle.baseline.advanced",
                    "must be boolean",
                )
                for endpoint in ("before", "after"):
                    value = baseline.get(endpoint)
                    self.require(
                        value is None or value in all_observation_ids,
                        path,
                        f"oracle.baseline.{endpoint}",
                        "must be null or a known observation ID",
                    )
        else:
            self.require(
                operation == "status"
                or (
                    isinstance(invocation, dict)
                    and invocation.get("check_mode") is True
                ),
                path,
                "oracle.baseline",
                "may be null only for status or check-mode simulation",
            )

        journal = oracle.get("journal")
        if self.require(
            isinstance(journal, dict),
            path,
            "oracle.journal",
            "must be a mapping",
        ):
            journal_status = journal.get("status")
            nullable_journal = operation == "status" or (
                operation in boundary_operations
            ) or (
                isinstance(invocation, dict)
                and invocation.get("check_mode") is True
            )
            self.enum(
                journal_status,
                self.schema.get("oracle", {}).get(
                    "stable_journal_status_values", []
                ),
                path,
                "oracle.journal.status",
                nullable=nullable_journal,
            )
            if not nullable_journal:
                self.require(
                    journal_status is not None,
                    path,
                    "oracle.journal.status",
                    "must not be null for a committed observation operation",
                )

        persistence = oracle.get("persistence")
        if self.require_keys(
            persistence, ["outcome"], path, "oracle.persistence"
        ):
            self.enum(
                persistence.get("outcome"),
                self.schema.get("oracle", {}).get(
                    "persistence_outcome_values", []
                ),
                path,
                "oracle.persistence.outcome",
            )

        human = oracle.get("human")
        human_required = self.schema.get("oracle", {}).get("human_required", [])
        if self.require_keys(human, human_required, path, "oracle.human"):
            messages = human.get("minimum_messages")
            self.validate_string_list(
                messages, path, "oracle.human.minimum_messages"
            )
            self.require(
                isinstance(messages, list) and bool(messages),
                path,
                "oracle.human.minimum_messages",
                "must contain at least one semantic message",
            )

        machine = oracle.get("machine_result")
        if operation in boundary_operations:
            self.validate_boundary_machine_result(
                path, machine, invocation, oracle
            )
            if "variant_results" in oracle:
                self.validate_variant_results(
                    path,
                    oracle["variant_results"],
                    "oracle.variant_results",
                )
            return

        if scenario_id == 21:
            failure_envelope = (
                machine.get("docker_ansible_summary_failure")
                if isinstance(machine, dict)
                else None
            )
            compact_size = (
                len(
                    json.dumps(
                        machine,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                if isinstance(machine, dict)
                else 0
            )
            self.require(
                isinstance(machine, dict)
                and set(machine)
                == {
                    "changed",
                    "failed",
                    "docker_ansible_summary_failure",
                }
                and machine.get("changed") is False
                and machine.get("failed") is True
                and isinstance(failure_envelope, dict)
                and set(failure_envelope)
                == {
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
                }
                and failure_envelope.get("schema_version") == 1
                and failure_envelope.get("instance_id")
                == invocation.get("instance_id")
                and failure_envelope.get("operation") == operation
                and failure_envelope.get("record_id")
                == invocation.get("record_id")
                and failure_envelope.get("observation_status") == "complete"
                and failure_envelope.get("failure_reason")
                == "revision_conflict"
                and failure_envelope.get("observation_reason") is None
                and failure_envelope.get("persistence_outcome") == "conflict"
                and failure_envelope.get("committed_result_replayable") is False
                and failure_envelope.get("replay_guidance") is None
                and compact_size <= 1024,
                path,
                "oracle.machine_result",
                "scenario 21 must expose only the bounded conflict failure "
                "envelope, never its proposed observation or delta",
            )
            self.require(
                oracle.get("diagnostic_rendered_before_failure") is True
                and oracle.get("full_report_rendered") is False
                and oracle.get("full_machine_result_in_failed_callback")
                is False
                and oracle.get("compact_failure_envelope_present") is True
                and oracle.get("task_failed") is True,
                path,
                "oracle",
                "scenario 21 must emit one safe diagnostic and bounded "
                "envelope without an uncommitted full report",
            )
            return

        machine_required = self.schema.get("oracle", {}).get(
            "machine_result_required_observation", []
        )
        if not self.require_keys(
            machine, machine_required, path, "oracle.machine_result"
        ):
            return
        self.require(
            self.is_int(machine.get("schema_version"))
            and machine["schema_version"] > 0,
            path,
            "oracle.machine_result.schema_version",
            "must be a positive integer",
        )
        self.require(
            machine.get("operation") == operation,
            path,
            "oracle.machine_result.operation",
            "must match invocation.operation",
        )
        if isinstance(invocation, dict):
            for key in ("instance_id", "record_id"):
                self.require(
                    machine.get(key) == invocation.get(key),
                    path,
                    f"oracle.machine_result.{key}",
                    f"must match invocation.{key}",
                )

        expected_endpoint = None
        if operation == "post":
            expected_endpoint = "c"
        elif operation == "status":
            expected_endpoint = "current"
        elif operation == "pre":
            expected_endpoint = "b"
        expected_observation = observations.get(expected_endpoint)
        self.require(
            machine.get("observation") == expected_endpoint,
            path,
            "oracle.machine_result.observation",
            f"must reference the operation endpoint {expected_endpoint!r}",
        )
        expected_status = (
            expected_observation.get("status")
            if isinstance(expected_observation, dict)
            else None
        )
        self.require(
            machine.get("observation_status") == expected_status,
            path,
            "oracle.machine_result.observation_status",
            f"must match the operation observation status {expected_status!r}",
        )
        expected_scope_identity = (
            expected_observation.get("scope", {}).get("identity")
            if isinstance(expected_observation, dict)
            else None
        )
        self.require(
            machine.get("scope_identity") == expected_scope_identity,
            path,
            "oracle.machine_result.scope_identity",
            f"must match the operation observation scope {expected_scope_identity!r}",
        )
        if baseline is None:
            expected_advanced = None
        else:
            expected_advanced = baseline.get("advanced")
        self.require(
            machine.get("baseline_advanced") == expected_advanced,
            path,
            "oracle.machine_result.baseline_advanced",
            f"must match oracle baseline result {expected_advanced!r}",
        )
        self.require(
            machine.get("journal_status")
            == (
                oracle.get("journal", {}).get("status")
                if isinstance(oracle.get("journal"), dict)
                else None
            ),
            path,
            "oracle.machine_result.journal_status",
            "must match oracle.journal.status",
        )
        self.require(
            machine.get("persistence_outcome")
            == (
                oracle.get("persistence", {}).get("outcome")
                if isinstance(oracle.get("persistence"), dict)
                else None
            ),
            path,
            "oracle.machine_result.persistence_outcome",
            "must match oracle.persistence.outcome",
        )
        if "variant_results" in oracle:
            self.validate_variant_results(
                path, oracle["variant_results"], "oracle.variant_results"
            )

    def validate_boundary_machine_result(
        self,
        path: Path,
        machine: Any,
        invocation: Any,
        oracle: dict[str, Any],
    ) -> None:
        required = self.schema.get("oracle", {}).get(
            "machine_result_required_boundary", []
        )
        if not self.require_keys(
            machine, required, path, "oracle.machine_result"
        ):
            return
        self.require(
            machine.get("schema_version") == 1,
            path,
            "oracle.machine_result.schema_version",
            "must equal 1",
        )
        if isinstance(invocation, dict):
            self.require(
                machine.get("operation") == invocation.get("operation")
                and machine.get("instance_id") == invocation.get("instance_id"),
                path,
                "oracle.machine_result",
                "operation and instance must match the MDAD invocation",
            )
        self.require(
            machine.get("cutover_report_outcome") == "written"
            and machine.get("fresh_native_start_allowed") is True
            and machine.get("cutover_blocked") is False,
            path,
            "oracle.machine_result",
            "selected valid evidence must write a report and allow native start",
        )
        self.require(
            machine.get("das_invoked") is False
            and machine.get("das_persistence_outcome") == "not_attempted"
            and machine.get("latest_complete_post_after") is None
            and machine.get("journal_status") is None,
            path,
            "oracle.machine_result",
            "boundary result must leave DAS entirely untouched",
        )
        forbidden_das_fields = {
            "record_id",
            "observation",
            "observation_status",
            "scope_identity",
            "baseline_advanced",
            "persistence_outcome",
        }
        self.require(
            forbidden_das_fields.isdisjoint(machine),
            path,
            "oracle.machine_result",
            "MDAD boundary result must not masquerade as a DAS operation result",
        )

        persistence = oracle.get("persistence")
        self.require(
            isinstance(persistence, dict)
            and persistence.get("component") == "mdad_cutover_report"
            and persistence.get("outcome") == "committed",
            path,
            "oracle.persistence",
            "committed persistence belongs only to the MDAD cutover report",
        )
        das_persistence = oracle.get("das_persistence")
        self.require(
            isinstance(das_persistence, dict)
            and das_persistence.get("outcome") == "not_attempted",
            path,
            "oracle.das_persistence",
            "DAS persistence must remain not_attempted",
        )
        das_boundary = oracle.get("das")
        self.require(
            isinstance(das_boundary, dict)
            and das_boundary.get("invoked") is False
            and das_boundary.get("store_access_attempted") is False
            and das_boundary.get("legacy_values_imported") is False,
            path,
            "oracle.das",
            "legacy assessment must not invoke, access, or import into DAS",
        )

    def validate_delta(
        self,
        path: Path,
        context: str,
        delta: Any,
        observation_ids: set[str],
        expected_from: str | None,
        expected_to: str | None,
    ) -> None:
        if delta is None:
            return
        required = self.schema.get("oracle", {}).get("delta_required", [])
        if not self.require_keys(delta, required, path, context):
            return
        self.enum(
            delta.get("comparability"),
            self.schema.get("oracle", {}).get("comparability_values", []),
            path,
            f"{context}.comparability",
        )
        self.require(
            delta.get("comparison_schema_version") == 1,
            path,
            f"{context}.comparison_schema_version",
            "must equal 1",
        )
        from_observation = delta.get("from_observation_id")
        to_observation = delta.get("to_observation_id")
        self.require(
            from_observation is None
            or (
                isinstance(from_observation, str)
                and from_observation in observation_ids
            ),
            path,
            f"{context}.from_observation_id",
            "must be null or a known observation ID",
        )
        self.require(
            to_observation is None
            or (
                isinstance(to_observation, str)
                and to_observation in observation_ids
            ),
            path,
            f"{context}.to_observation_id",
            "must be null or a known observation ID",
        )
        self.require(
            from_observation == expected_from,
            path,
            f"{context}.from_observation_id",
            f"must reference the expected endpoint {expected_from!r}",
        )
        self.require(
            to_observation == expected_to,
            path,
            f"{context}.to_observation_id",
            f"must reference the expected endpoint {expected_to!r}",
        )
        changes = delta.get("changes")
        if self.require(
            isinstance(changes, list),
            path,
            f"{context}.changes",
            "must be a list",
        ):
            for index, change in enumerate(changes):
                self.validate_change(path, f"{context}.changes[{index}]", change)
        self.validate_string_list(
            delta.get("warnings"), path, f"{context}.warnings"
        )
        self.require(
            delta.get("warnings")
            == DELTA_WARNINGS_BY_COMPARABILITY.get(
                delta.get("comparability")
            ),
            path,
            f"{context}.warnings",
            "must be the exact fixed warning list for comparability",
        )

    def validate_change(self, path: Path, context: str, change: Any) -> None:
        required = self.schema.get("oracle", {}).get(
            "fixture_container_delta_required_subset", []
        )
        if not self.require_keys(change, required, path, context):
            return
        self.require(
            isinstance(change.get("container_name"), str)
            and CONTAINER_NAME_RE.fullmatch(change["container_name"]) is not None,
            path,
            f"{context}.container_name",
            "must be a normalized container name",
        )
        kinds = change.get("kinds")
        allowed = self.schema.get("oracle", {}).get(
            "container_delta_kind_values", []
        )
        if self.require(
            isinstance(kinds, list) and bool(kinds),
            path,
            f"{context}.kinds",
            "must be a non-empty list",
        ):
            self.require(
                len(kinds) == len(set(kinds)),
                path,
                f"{context}.kinds",
                "must not contain duplicate kinds",
            )
            for index, kind in enumerate(kinds):
                self.enum(kind, allowed, path, f"{context}.kinds[{index}]")
            self.require(
                change.get("primary_kind") in kinds,
                path,
                f"{context}.primary_kind",
                "must be present in kinds",
            )
            if "unchanged" in kinds:
                self.require(
                    kinds == ["unchanged"],
                    path,
                    f"{context}.kinds",
                    "unchanged must be the only kind",
                )
        for boolean_field in (
            "image_reference_changed",
            "image_content_changed",
        ):
            if boolean_field in change:
                self.require(
                    isinstance(change[boolean_field], bool),
                    path,
                    f"{context}.{boolean_field}",
                    "must be boolean",
                )

    def validate_variant_results(
        self, path: Path, results: Any, context: str
    ) -> None:
        if not self.require(
            isinstance(results, dict), path, context, "must be a mapping"
        ):
            return
        self.require(
            set(results) == EXPECTED_LEGACY_VARIANTS,
            path,
            context,
            f"must contain exactly {sorted(EXPECTED_LEGACY_VARIANTS)!r}",
        )
        expected_backups = {
            "valid": {"display_state", "history", "simple_versions"},
            "missing": set(),
            "partial": {"history", "simple_versions"},
            "malformed": {"display_state"},
            "valid_source_conflict": {"display_state", "history"},
        }
        expected_assessments = {
            "valid": "valid",
            "missing": "no_legacy_state",
            "partial": "valid_partial_source_set",
            "malformed": "malformed_input",
            "valid_source_conflict": "valid_source_conflict",
        }
        for variant, result in results.items():
            item_context = f"{context}.{variant}"
            if not self.require(
                isinstance(result, dict),
                path,
                item_context,
                "must be a mapping",
            ):
                continue
            self.require(
                result.get("latest_complete_post_after") is None,
                path,
                f"{item_context}.latest_complete_post_after",
                "must remain null",
            )
            self.require(
                result.get("journal_status") is None,
                path,
                f"{item_context}.journal_status",
                "must remain null",
            )
            self.require(
                result.get("das_invoked") is False,
                path,
                f"{item_context}.das_invoked",
                "MDAD assessment must not invoke DAS",
            )
            self.require(
                result.get("das_persistence_outcome") == "not_attempted",
                path,
                f"{item_context}.das_persistence_outcome",
                "DAS persistence must remain not_attempted",
            )
            self.require(
                result.get("cutover_report_outcome") == "written",
                path,
                f"{item_context}.cutover_report_outcome",
                "each assessment variant must write a cutover report",
            )
            backups = result.get("backups_required")
            self.require(
                isinstance(backups, list)
                and all(
                    source
                    in self.schema.get("legacy_fixture", {}).get(
                        "source_keys", []
                    )
                    for source in backups
                ),
                path,
                f"{item_context}.backups_required",
                "must be a list of known legacy source names",
            )
            if isinstance(backups, list):
                self.require(
                    set(backups) == expected_backups.get(variant, set()),
                    path,
                    f"{item_context}.backups_required",
                    "does not match the evidence sources present in this variant",
                )
            completed_backups = result.get("backups_completed")
            self.require(
                isinstance(completed_backups, list)
                and completed_backups == backups,
                path,
                f"{item_context}.backups_completed",
                "must exactly equal backups_required before cutover is assessed",
            )
            expected_backup_results = (
                {source: "completed" for source in backups}
                if isinstance(backups, list)
                and isinstance(completed_backups, list)
                and completed_backups == backups
                else None
            )
            self.require(
                expected_backup_results is not None
                and result.get("cutover_report_backup_results")
                == expected_backup_results,
                path,
                f"{item_context}.cutover_report_backup_results",
                "must map exactly each required and completed backup to completed",
            )
            allowed = variant in {"valid", "missing", "partial"}
            self.require(
                result.get("fresh_native_start_allowed") is allowed
                and result.get("cutover_blocked") is (not allowed),
                path,
                item_context,
                "fresh-start and cutover-blocked flags do not match the "
                "assessment variant",
            )
            self.require(
                isinstance(result.get("adapter_validation_result"), str)
                and bool(result["adapter_validation_result"].strip()),
                path,
                f"{item_context}.adapter_validation_result",
                "must be a non-empty assessment result",
            )
            self.require(
                result.get("adapter_validation_result")
                == expected_assessments.get(variant),
                path,
                f"{item_context}.adapter_validation_result",
                "does not match the assessment variant",
            )
            if not allowed:
                self.require(
                    result.get("source_files_unchanged") is True,
                    path,
                    f"{item_context}.source_files_unchanged",
                    "blocked evidence must remain unchanged after backup",
                )

    def validate_legacy_fixtures(self) -> None:
        paths = sorted((ROOT / "legacy").glob("*.yml"))
        found_variants: set[str] = set()
        file_variant = {
            "valid": "valid",
            "missing": "missing",
            "partial": "partial",
            "malformed": "malformed",
            "conflict": "valid_source_conflict",
        }
        for path in paths:
            data = self.documents.get(path)
            if data is None:
                continue
            required = self.schema.get("legacy_fixture", {}).get(
                "required_top_level", []
            )
            if not self.require_keys(data, required, path, "top level"):
                continue
            variant = data.get("variant")
            self.enum(
                variant,
                self.schema.get("legacy_fixture", {}).get("variant_values", []),
                path,
                "variant",
            )
            self.require(
                variant == file_variant.get(path.stem),
                path,
                "variant",
                f"does not match filename {path.name!r}",
            )
            self.require(
                variant not in found_variants,
                path,
                "variant",
                f"duplicate legacy variant {variant!r}",
            )
            if isinstance(variant, str):
                found_variants.add(variant)
            self.validate_legacy_fixture(path, data)
        self.require(
            found_variants == EXPECTED_LEGACY_VARIANTS,
            ROOT / "legacy",
            "variants",
            f"expected {sorted(EXPECTED_LEGACY_VARIANTS)!r}, "
            f"found {sorted(found_variants)!r}",
        )

    def validate_legacy_fixture(
        self, path: Path, data: dict[str, Any]
    ) -> None:
        self.require(
            data.get("legacy_fixture_schema_version") == 1,
            path,
            "legacy_fixture_schema_version",
            "must equal 1",
        )
        self.require(
            isinstance(data.get("description"), str)
            and bool(data["description"].strip()),
            path,
            "description",
            "must be a non-empty string",
        )
        sources = data.get("sources")
        source_keys = set(
            self.schema.get("legacy_fixture", {}).get("source_keys", [])
        )
        existing_sources: list[str] = []
        source_hashes: dict[str, str] = {}
        if self.require(
            isinstance(sources, dict), path, "sources", "must be a mapping"
        ):
            self.require(
                set(sources) == source_keys,
                path,
                "sources",
                f"must contain exactly {sorted(source_keys)!r}",
            )
            for source_name, source in sources.items():
                context = f"sources.{source_name}"
                if not self.require_keys(source, ["exists"], path, context):
                    continue
                self.require(
                    isinstance(source.get("exists"), bool),
                    path,
                    f"{context}.exists",
                    "must be boolean",
                )
                if source.get("exists") is not True:
                    continue
                existing_sources.append(source_name)
                self.enum(
                    source.get("parse_status"),
                    {"valid", "malformed"},
                    path,
                    f"{context}.parse_status",
                )
                self.require(
                    isinstance(source.get("synthetic_sha256"), str)
                    and HEX_64_RE.fullmatch(source["synthetic_sha256"]) is not None,
                    path,
                    f"{context}.synthetic_sha256",
                    "must be 64 lowercase hexadecimal characters",
                )
                if isinstance(source.get("synthetic_sha256"), str):
                    source_hashes[source_name] = source["synthetic_sha256"]
                if source.get("parse_status") == "valid":
                    self.require(
                        isinstance(source.get("payload"), dict),
                        path,
                        f"{context}.payload",
                        "must be a mapping for a valid source",
                    )
                if source.get("parse_status") == "malformed":
                    self.require(
                        isinstance(source.get("synthetic_payload"), str),
                        path,
                        f"{context}.synthetic_payload",
                        "must be a synthetic string for malformed input",
                    )

        prior_state = data.get("prior_state")
        if self.require(
            isinstance(prior_state, dict),
            path,
            "prior_state",
            "must be a mapping",
        ):
            self.require(
                prior_state.get("latest_complete_post") is None,
                path,
                "prior_state.latest_complete_post",
                "must be null for legacy cutover input",
            )
            self.require(
                "legacy_baseline" not in prior_state,
                path,
                "prior_state",
                "MDAD assessment state must not contain a DAS legacy_baseline",
            )
            self.require(
                self.is_int(prior_state.get("revision"))
                and prior_state["revision"] >= 0,
                path,
                "prior_state.revision",
                "must be a non-negative integer",
            )

        invocation = data.get("adapter_invocation")
        if self.require_keys(
            invocation,
            ["instance_id", "source_policy", "reset_policy"],
            path,
            "adapter_invocation",
        ):
            self.require(
                isinstance(invocation.get("instance_id"), str)
                and bool(invocation["instance_id"].strip()),
                path,
                "adapter_invocation.instance_id",
                "must be a non-empty string",
            )

        oracle = data.get("oracle")
        if not self.require(
            isinstance(oracle, dict), path, "oracle", "must be a mapping"
        ):
            return
        self.require(
            "legacy_baseline" not in oracle,
            path,
            "oracle",
            "legacy assessment reports must not create a DAS legacy_baseline",
        )
        self.require(
            oracle.get("journal_status") is None,
            path,
            "oracle.journal_status",
            "must remain null",
        )
        self.require(
            oracle.get("das_invoked") is False,
            path,
            "oracle.das_invoked",
            "MDAD assessment must not invoke DAS",
        )
        self.require(
            oracle.get("das_persistence_outcome") == "not_attempted",
            path,
            "oracle.das_persistence_outcome",
            "DAS persistence must remain not_attempted",
        )
        self.require(
            oracle.get("legacy_values_imported_into_das") is False,
            path,
            "oracle.legacy_values_imported_into_das",
            "legacy values must remain outside DAS",
        )
        latest = oracle.get("latest_complete_post")
        if self.require(
            isinstance(latest, dict),
            path,
            "oracle.latest_complete_post",
            "must be a mapping",
        ):
            self.require(
                latest.get("before") is None and latest.get("after") is None,
                path,
                "oracle.latest_complete_post",
                "before and after must remain null",
            )

        required_backups: Any = None
        completed_backups: Any = None
        backups = oracle.get("backups")
        if self.require(
            isinstance(backups, dict),
            path,
            "oracle.backups",
            "must be a mapping",
        ):
            required_backups = backups.get("required")
            if self.require(
                isinstance(required_backups, list),
                path,
                "oracle.backups.required",
                    "must be a list",
            ):
                completed_backups = backups.get("completed")
                self.require(
                    isinstance(completed_backups, list)
                    and completed_backups == required_backups,
                    path,
                    "oracle.backups.completed",
                    "must exactly equal oracle.backups.required",
                )
                self.require(
                    set(required_backups) == set(existing_sources),
                    path,
                    "oracle.backups.required",
                    "every existing source, and no absent source, must be backed up",
                )
                for source in required_backups:
                    self.require(
                        source in source_keys,
                        path,
                        "oracle.backups.required",
                        f"unknown source {source!r}",
                    )
                    self.require(
                        isinstance(sources, dict)
                        and isinstance(sources.get(source), dict)
                        and sources[source].get("exists") is True,
                        path,
                        "oracle.backups.required",
                        f"cannot back up absent source {source!r}",
                    )
                if required_backups:
                    self.require(
                        backups.get("raw_payloads_preserved") is True,
                        path,
                        "oracle.backups.raw_payloads_preserved",
                        "backups must preserve the raw legacy payloads",
                    )

        cutover_report = oracle.get("cutover_report")
        if self.require(
            isinstance(cutover_report, dict),
            path,
            "oracle.cutover_report",
            "must be a mapping",
        ):
            self.require(
                cutover_report.get("outcome") == "written",
                path,
                "oracle.cutover_report.outcome",
                "assessment must write an MDAD-owned cutover report",
            )
            self.require(
                set(cutover_report.get("evidence_sources", []))
                == set(existing_sources),
                path,
                "oracle.cutover_report.evidence_sources",
                "must identify exactly the existing evidence sources",
            )
            self.require(
                cutover_report.get("source_hashes") == source_hashes,
                path,
                "oracle.cutover_report.source_hashes",
                "must contain only the synthetic source hashes",
            )
            self.require(
                cutover_report.get("raw_legacy_values_in_report") is False,
                path,
                "oracle.cutover_report.raw_legacy_values_in_report",
                "cutover reports must not copy raw legacy values",
            )
            self.require(
                isinstance(cutover_report.get("evidence_status"), str)
                and bool(cutover_report["evidence_status"].strip()),
                path,
                "oracle.cutover_report.evidence_status",
                "must be a non-empty assessment status",
            )
            expected_backup_results = (
                {source: "completed" for source in required_backups}
                if isinstance(required_backups, list)
                and isinstance(completed_backups, list)
                and completed_backups == required_backups
                else None
            )
            self.require(
                expected_backup_results is not None
                and cutover_report.get("backup_results")
                == expected_backup_results,
                path,
                "oracle.cutover_report.backup_results",
                "must map exactly each required and completed backup to completed",
            )

        variant = data.get("variant")
        fresh_start_allowed = variant in {"valid", "missing", "partial"}
        self.require(
            oracle.get("fresh_native_start_allowed") is fresh_start_allowed
            and oracle.get("cutover_blocked") is (not fresh_start_allowed),
            path,
            "oracle",
            "fresh-start and cutover-blocked flags do not match the variant",
        )
        if not fresh_start_allowed:
            unchanged = oracle.get("source_files_unchanged")
            self.require(
                isinstance(unchanged, dict)
                and {
                    source: value.get("synthetic_sha256")
                    for source, value in unchanged.items()
                    if isinstance(value, dict)
                }
                == source_hashes,
                path,
                "oracle.source_files_unchanged",
                "blocked source hashes must remain unchanged after backup",
            )

        retry = oracle.get("second_identical_invocation")
        if retry is not None:
            self.require(
                isinstance(retry, dict)
                and retry.get("cutover_report_outcome") == "unchanged"
                and retry.get("additional_backups_created") is False
                and retry.get("das_invoked") is False,
                path,
                "oracle.second_identical_invocation",
                "repeated assessment must be idempotent and keep DAS untouched",
            )

    def validate_focused_fixtures(self) -> None:
        paths = sorted((ROOT / "focused").glob("*.yml"))
        found_topics: set[str] = set()
        topic_values = set(
            self.schema.get("focused_fixture", {}).get("topic_values", [])
        )
        for path in paths:
            data = self.documents.get(path)
            if data is None:
                continue
            required = self.schema.get("focused_fixture", {}).get(
                "required_top_level", []
            )
            if not self.require_keys(data, required, path, "top level"):
                continue
            self.require(
                data.get("fixture_family")
                == self.schema.get("focused_fixture", {}).get(
                    "fixture_family_value"
                ),
                path,
                "fixture_family",
                "must equal focused_cases",
            )
            topic = data.get("topic")
            self.enum(topic, topic_values, path, "topic")
            self.require(
                topic not in found_topics,
                path,
                "topic",
                f"duplicate focused topic {topic!r}",
            )
            if isinstance(topic, str):
                found_topics.add(topic)
                self.require(
                    path.stem.replace("-", "_") == topic,
                    path,
                    "topic",
                    "must match the filename",
                )
                self.validate_focused_topic(path, data, topic)
            self.require(
                isinstance(data.get("description"), str)
                and bool(data["description"].strip()),
                path,
                "description",
                "must be a non-empty string",
            )
            self.reject_sensitive_focused_keys(path, data)
        self.require(
            found_topics == topic_values,
            ROOT / "focused",
            "topics",
            f"expected exactly {sorted(topic_values)!r}, "
            f"found {sorted(found_topics)!r}",
        )

    def validate_focused_topic(
        self, path: Path, data: dict[str, Any], topic: str
    ) -> None:
        configured = (
            self.schema.get("focused_fixture", {})
            .get("case_container", {})
            .get(topic)
        )
        containers = configured if isinstance(configured, list) else [configured]
        all_cases: list[dict[str, Any]] = []
        for container_name in containers:
            if not isinstance(container_name, str):
                self.error(
                    path,
                    "case routing",
                    f"schema has no valid case container for topic {topic!r}",
                )
                continue
            cases = data.get(container_name)
            if not self.require(
                isinstance(cases, list) and bool(cases),
                path,
                container_name,
                "must be a non-empty list",
            ):
                continue
            for index, case in enumerate(cases):
                context = f"{container_name}[{index}]"
                if not self.require_keys(case, ["id", "oracle"], path, context):
                    continue
                case_id = case.get("id")
                self.require(
                    isinstance(case_id, str) and bool(case_id.strip()),
                    path,
                    f"{context}.id",
                    "must be a non-empty string",
                )
                all_cases.append(case)

        case_ids = [
            case.get("id")
            for case in all_cases
            if isinstance(case.get("id"), str)
        ]
        self.require(
            len(case_ids) == len(set(case_ids)),
            path,
            "case IDs",
            "must be unique within the focused topic",
        )
        required_ids = EXPECTED_FOCUSED_CASES.get(topic, set())
        missing_ids = sorted(required_ids - set(case_ids))
        self.require(
            not missing_ids,
            path,
            "case coverage",
            f"missing required focused case(s): {', '.join(missing_ids)}",
        )

        if topic == "operation_contract":
            self.validate_operation_contract_cases(path, all_cases)
        elif topic == "change_kinds":
            self.validate_change_kind_cases(path, all_cases)
        elif topic == "persistence":
            self.validate_persistence_cases(path, all_cases)
        elif topic == "normalization":
            self.validate_normalization_cases(path, data)
        elif topic == "legacy_boundary":
            self.validate_legacy_boundary_cases(path, all_cases)
        elif topic == "presentation":
            self.validate_presentation_cases(path, all_cases)
        elif topic == "execution_surface":
            self.validate_execution_surface_cases(path, data, all_cases)
        elif topic == "image_display":
            self.validate_image_display_cases(path, data, all_cases)

    def validate_operation_contract_cases(
        self, path: Path, cases: list[dict[str, Any]]
    ) -> None:
        for case in cases:
            context = f"case {case.get('id')!r}"
            if case.get("id") == "correlation_validation_is_bounded":
                variants = case.get("invocation_variants")
                oracle = case.get("oracle")
                boundary_recipe = (
                    variants.get("valid_utf8_boundary_recipe")
                    if isinstance(variants, dict)
                    else None
                )
                overflow_recipe = (
                    variants.get("invalid_utf8_overflow_recipe")
                    if isinstance(variants, dict)
                    else None
                )
                boundary_value = (
                    boundary_recipe.get("character")
                    * boundary_recipe.get("repeat")
                    if isinstance(boundary_recipe, dict)
                    and isinstance(boundary_recipe.get("character"), str)
                    and self.is_int(boundary_recipe.get("repeat"))
                    else ""
                )
                overflow_value = (
                    overflow_recipe.get("character")
                    * overflow_recipe.get("repeat")
                    if isinstance(overflow_recipe, dict)
                    and isinstance(overflow_recipe.get("character"), str)
                    and self.is_int(overflow_recipe.get("repeat"))
                    else ""
                )
                ascii_value = (
                    variants.get("valid_ascii", {}).get("correlation_id")
                    if isinstance(variants, dict)
                    else None
                )
                self.require(
                    isinstance(variants, dict)
                    and isinstance(ascii_value, str)
                    and bool(ascii_value)
                    and all(
                        ord(character) >= 32 and ord(character) != 127
                        for character in ascii_value
                    )
                    and len(boundary_value.encode("utf-8")) == 256
                    and len(overflow_value.encode("utf-8")) == 257
                    and variants.get("invalid_control")
                    == {"correlation_id_recipe": "prefix LF suffix"}
                    and isinstance(oracle, dict)
                    and oracle.get("maximum_utf8_bytes") == 256
                    and oracle.get("valid_ascii_accepted") is True
                    and oracle.get("boundary_accepted") is True
                    and oracle.get("overflow_reason")
                    == "invalid_correlation_id"
                    and oracle.get("control_reason")
                    == "invalid_correlation_id"
                    and oracle.get("validation_before_discovery") is True
                    and oracle.get("correlation_treated_as_non_secret")
                    is True,
                    path,
                    context,
                    "correlation validation must accept bounded non-control "
                    "UTF-8 and reject overflow/control input before discovery",
                )
                continue
            invocation = case.get("invocation")
            if not self.require(
                isinstance(invocation, dict),
                path,
                f"{context}.invocation",
                "must be a mapping",
            ):
                continue
            if invocation.get("enabled") is False:
                machine = case.get("oracle", {}).get("machine_result", {})
                expected_machine = {
                    "schema_version": 1,
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
                exact_machine_fields = self.schema.get("oracle", {}).get(
                    "machine_result_exact_v1_fields"
                )
                self.require(
                    case.get("oracle", {}).get("input_validation_attempted")
                    is False,
                    path,
                    f"{context}.oracle.input_validation_attempted",
                    "disabled operation must short-circuit before validation",
                )
                self.require(
                    machine == expected_machine
                    and list(machine) == exact_machine_fields
                    and len(exact_machine_fields) == 18,
                    path,
                    f"{context}.oracle.machine_result",
                    "disabled operation must return the exact 18-key skipped "
                    "result with explicit null lifecycle fields",
                )
                continue
            self.enum(
                invocation.get("operation"),
                self.schema.get("invocation", {}).get("operation_values", []),
                path,
                f"{context}.invocation.operation",
            )
            self.require(
                isinstance(invocation.get("check_mode"), bool),
                path,
                f"{context}.invocation.check_mode",
                "must be boolean",
            )
            observation = invocation.get("observation")
            if observation is not None:
                self.validate_observation(
                    path, f"{context}.invocation.observation", observation
                )
            oracle = case.get("oracle", {})
            if "persistence_outcome" in oracle:
                self.enum(
                    oracle["persistence_outcome"],
                    self.schema.get("oracle", {}).get(
                        "persistence_outcome_values", []
                    ),
                    path,
                    f"{context}.oracle.persistence_outcome",
                )
            if invocation.get("check_mode") is True:
                self.require(
                    oracle.get("persistence_outcome") == "not_attempted",
                    path,
                    f"{context}.oracle.persistence_outcome",
                    "check-mode observation must not attempt persistence",
                )
                machine = oracle.get("machine_result")
                expected_observation_id = (
                    observation.get("observation_id")
                    if isinstance(observation, dict)
                    else None
                )
                self.require(
                    isinstance(machine, dict)
                    and machine.get("observation") == expected_observation_id,
                    path,
                    f"{context}.oracle.machine_result.observation",
                    "check-mode machine result must reference the invoked "
                    "observation ID",
                )
            if (
                case.get("id")
                == "check_post_supplied_record_id_is_not_looked_up"
            ):
                self.require(
                    case.get("prior_state_access") == "forbidden"
                    and oracle.get("record_lookup_attempted") is False,
                    path,
                    context,
                    "check-mode post with a supplied ID must not read or "
                    "look up prior state",
                )
                self.require(
                    oracle.get("machine_result", {}).get("record_id") is None,
                    path,
                    f"{context}.oracle.machine_result.record_id",
                    "simulation must not echo an unresolved supplied record ID",
                )
            if (
                case.get("id")
                == "check_post_noncomplete_fail_after_report_is_store_free"
            ):
                machine = oracle.get("machine_result")
                self.require(
                    case.get("prior_state_access") == "forbidden"
                    and invocation.get("operation") == "post"
                    and invocation.get("check_mode") is True
                    and invocation.get("failure_policy")
                    == "fail_after_report"
                    and isinstance(observation, dict)
                    and observation.get("status") == "partial"
                    and oracle.get("between_observation_delta") is None
                    and oracle.get("run_window_delta") is None
                    and oracle.get("baseline_result") is None
                    and oracle.get("journal_status") is None
                    and oracle.get("persistence_outcome")
                    == "not_attempted"
                    and oracle.get("filesystem_side_effects") == []
                    and oracle.get("store_reads") == 0
                    and oracle.get("store_writes") == 0
                    and oracle.get("report_rendered_before_failure")
                    is True
                    and oracle.get("task_failed") is True
                    and oracle.get("failure_reason")
                    == "observation_noncomplete"
                    and oracle.get("observation_reason")
                    == "required_field_missing"
                    and oracle.get("compact_failure_envelope_present")
                    is True
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("committed_result_replayable") is False
                    and machine
                    == {
                        "operation": "post",
                        "record_id": None,
                        "observation": "obs-focused-partial-b",
                        "observation_status": "partial",
                        "simulated": True,
                        "journal_status": None,
                        "persistence_outcome": "not_attempted",
                    },
                    path,
                    context,
                    "noncomplete check-mode post with fail_after_report must "
                    "observe and render, remain fully store-free, then fail "
                    "with no replayable committed result",
                )
            if (
                case.get("id")
                == "status_noncomplete_fail_after_report_is_store_free"
            ):
                self.require(
                    case.get("prior_state_access") == "forbidden"
                    and invocation.get("operation") == "status"
                    and invocation.get("check_mode") is False
                    and invocation.get("failure_policy")
                    == "fail_after_report"
                    and invocation.get("record_id") is None
                    and isinstance(observation, dict)
                    and observation.get("status") == "unavailable"
                    and oracle.get("between_observation_delta") is None
                    and oracle.get("run_window_delta") is None
                    and oracle.get("baseline_result") is None
                    and oracle.get("record_id") is None
                    and oracle.get("journal_status") is None
                    and oracle.get("persistence_outcome")
                    == "not_attempted"
                    and oracle.get("filesystem_side_effects") == []
                    and oracle.get("store_reads") == 0
                    and oracle.get("store_writes") == 0
                    and oracle.get("simulated") is False
                    and oracle.get("report_rendered_before_failure")
                    is True
                    and oracle.get("task_failed") is True
                    and oracle.get("failure_reason")
                    == "observation_noncomplete"
                    and oracle.get("observation_reason")
                    == "docker_unavailable"
                    and oracle.get("compact_failure_envelope_present")
                    is True
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("committed_result_replayable") is False,
                    path,
                    context,
                    "noncomplete status with fail_after_report must observe "
                    "and render, remain store-free, then fail with no record, "
                    "journal, baseline, or replayable committed result",
                )
            if case.get("id") == "status_rejects_supplied_record_id":
                self.require(
                    case.get("prior_state_access") == "forbidden"
                    and invocation.get("operation") == "status"
                    and isinstance(invocation.get("record_id"), str)
                    and oracle
                    == {
                        "failure_reason": "invalid_input",
                        "persistence_outcome": "not_attempted",
                        "input_validation_attempted": True,
                        "record_lookup_attempted": False,
                        "discovery_attempted": False,
                        "filesystem_side_effects": [],
                        "failure_envelope_record_id": None,
                    },
                    path,
                    context,
                    "status must reject a supplied record ID before "
                    "discovery or state access",
                )
            if (
                case.get("id")
                == "incompatible_a_to_b_with_compatible_b_to_c"
            ):
                self.require(
                    oracle.get("between_observation_delta", {}).get("comparability")
                    == "incompatible_scope"
                    and oracle.get("run_window_delta", {}).get("comparability")
                    == "exact",
                    path,
                    context,
                    "must keep A-to-B scope incompatibility separate from "
                    "the compatible B-to-C run window",
                )
                self.require(
                    oracle.get("journal_status") == "complete"
                    and oracle.get("forbidden_journal_status")
                    == "scope_mismatch",
                    path,
                    context,
                    "journal status must derive from the B-to-C pair",
                )
            if (
                case.get("id")
                == "post_only_unavailable_commits_incomplete_both_without_deltas"
            ):
                prior = case.get("prior_state", {})
                persisted = oracle.get("persisted_record_projection")
                self.require(
                    prior
                    == {
                        "exists": True,
                        "revision": 9,
                        "instance_id": "fixture-instance",
                        "latest_complete_post": case.get(
                            "prior_state", {}
                        ).get("latest_complete_post"),
                        "journal": [],
                    }
                    and isinstance(prior.get("latest_complete_post"), dict)
                    and prior["latest_complete_post"].get("observation_id")
                    == "obs-focused-a"
                    and invocation.get("operation") == "post"
                    and invocation.get("record_id") is None
                    and invocation.get("check_mode") is False
                    and isinstance(invocation.get("observation"), dict)
                    and invocation["observation"].get("status")
                    == "unavailable"
                    and invocation["observation"].get("observation_id")
                    == "obs-focused-unavailable-c"
                    and oracle.get("generated_record_id") == "non_null"
                    and oracle.get("between_observation_delta") is None
                    and oracle.get("run_window_delta") is None
                    and oracle.get("baseline")
                    == {
                        "advanced": False,
                        "before": "obs-focused-a",
                        "after": "obs-focused-a",
                    }
                    and oracle.get("baseline_advanced") is False
                    and oracle.get("baseline_after") == "obs-focused-a"
                    and oracle.get("journal_status") == "incomplete_both"
                    and oracle.get("persistence_outcome") == "committed"
                    and persisted
                    == {
                        "pre_signature": None,
                        "pre": None,
                        "between_observation_delta": None,
                        "pre_baseline": None,
                        "post_signature_present": True,
                        "post_observation_id": (
                            "obs-focused-unavailable-c"
                        ),
                        "run_window_delta": None,
                        "post_baseline": {
                            "advanced": False,
                            "before": "obs-focused-a",
                            "after": "obs-focused-a",
                        },
                    },
                    path,
                    context,
                    "a noncomplete post-only call must commit only its post "
                    "evidence, retain null pre/pairing fields, use "
                    "incomplete_both, and leave the baseline unchanged",
                )
            if (
                case.get("id")
                == "pre_cannot_fill_retained_post_only_record"
            ):
                prior = case.get("prior_state", {})
                records = prior.get("journal", [])
                retained = (
                    records[0]
                    if isinstance(records, list) and len(records) == 1
                    else {}
                )
                self.require(
                    prior.get("revision") == 9
                    and retained.get("record_id")
                    == invocation.get("record_id")
                    == "retained-post-only-001"
                    and retained.get("status") == "incomplete_pre"
                    and retained.get("pre") is None
                    and retained.get("pre_signature") is None
                    and isinstance(retained.get("post"), dict)
                    and retained.get("post_signature_present") is True
                    and retained.get("expected_post_revision") is None
                    and invocation.get("operation") == "pre"
                    and oracle
                    == {
                        "failure_reason": "signature_conflict",
                        "persistence_outcome": "conflict",
                        "discovery_attempted": False,
                        "store_mutated": False,
                        "revision_after": 9,
                        "retained_record_unchanged": True,
                        "retroactive_pre_fill_attempted": False,
                    },
                    path,
                    context,
                    "pre must fail closed on a retained post-only record "
                    "without retroactively filling its missing phase",
                )
            if (
                case.get("id")
                == "fail_after_report_commits_renders_then_fails"
            ):
                self.require(
                    invocation.get("failure_policy") == "fail_after_report"
                    and oracle.get("persistence_outcome") == "committed"
                    and oracle.get("report_rendered_before_failure") is True
                    and oracle.get("task_failed") is True
                    and oracle.get("failure_reason")
                    == "observation_noncomplete"
                    and oracle.get("observation_reason")
                    == "docker_daemon_unreachable",
                    path,
                    context,
                    "fail_after_report must commit, render, and only then fail",
                )
                self.require(
                    oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present")
                    is True
                    and oracle.get(
                        "committed_result_replayable_with_report_policy"
                    )
                    is True,
                    path,
                    f"{context}.oracle",
                    "failed callback must stay bounded while the committed "
                    "full result remains available through report-policy replay",
                )
                prior_revision = case.get("prior_state", {}).get("revision")
                self.require(
                    self.is_int(prior_revision)
                    and oracle.get("revision_after") == prior_revision + 1,
                    path,
                    f"{context}.oracle.revision_after",
                    "committed non-complete observation must advance revision once",
                )
            if (
                case.get("id")
                == "retained_noncomplete_replay_reapplies_failure_policy"
            ):
                prior_revision = case.get("prior_state", {}).get("revision")
                self.require(
                    invocation.get("failure_policy") == "fail_after_report"
                    and oracle.get("replay_outcome") == "idempotent"
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_mutated") is False
                    and oracle.get("revision_after") == prior_revision
                    and oracle.get("persistence_outcome") == "not_attempted",
                    path,
                    context,
                    "retained replay must reuse the result without discovery "
                    "or mutation",
                )
                self.require(
                    oracle.get("report_rendered_before_failure") is True
                    and oracle.get("task_failed") is True
                    and oracle.get("failure_reason")
                    == "observation_noncomplete"
                    and oracle.get("observation_reason")
                    == "docker_daemon_unreachable",
                    path,
                    context,
                    "retained replay must reapply the caller's failure policy",
                )
                self.require(
                    oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present")
                    is True
                    and oracle.get(
                        "committed_result_replayable_with_report_policy"
                    )
                    is True,
                    path,
                    f"{context}.oracle",
                    "failed retained replay must use the compact envelope and "
                    "remain recoverable through report policy",
                )
            if (
                case.get("id")
                == "correlation_inherits_to_matching_post_and_header"
            ):
                prior = case.get("prior_state", {})
                records = prior.get("journal", [])
                record = records[0] if isinstance(records, list) and records else {}
                correlation_id = record.get("correlation_id")
                self.require(
                    prior.get("instance_id") == invocation.get("instance_id")
                    and record.get("record_id")
                    == invocation.get("record_id")
                    == oracle.get("record_lookup_key")
                    and invocation.get("correlation_id") == "omitted"
                    and isinstance(correlation_id, str)
                    and 0 < len(correlation_id.encode("utf-8")) <= 256
                    and oracle.get("correlation_id") == correlation_id
                    and oracle.get("correlation_inherited") is True
                    and oracle.get("correlation_changed") is False
                    and oracle.get("machine_result_correlation_id")
                    == correlation_id
                    and oracle.get("report_header_correlation_id")
                    == correlation_id
                    and oracle.get("journal_status") == "complete"
                    and oracle.get("persistence_outcome") == "committed",
                    path,
                    context,
                    "matching post must select by record ID, inherit an "
                    "omitted correlation, and project it consistently",
                )
            if (
                case.get("id")
                == "correlation_mismatch_conflicts_before_discovery"
            ):
                prior = case.get("prior_state", {})
                records = prior.get("journal", [])
                record = records[0] if isinstance(records, list) and records else {}
                self.require(
                    record.get("record_id")
                    == invocation.get("record_id")
                    == oracle.get("record_lookup_key")
                    and record.get("correlation_id")
                    != invocation.get("correlation_id")
                    and oracle.get("failure_reason")
                    == "signature_conflict"
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_mutated") is False
                    and oracle.get("revision_after") == prior.get("revision")
                    and oracle.get(
                        "failure_envelope_correlation_id_present"
                    )
                    is False,
                    path,
                    context,
                    "correlation mismatch must reject by retained signature "
                    "before discovery without exposing it in failure output",
                )
            if case.get("id") == "correlation_is_grouping_not_lookup":
                prior = case.get("prior_state", {})
                records = prior.get("journal", [])
                by_id = {
                    record.get("record_id"): record
                    for record in records
                    if isinstance(record, dict)
                }
                selected_id = invocation.get("record_id")
                self.require(
                    len(by_id) == 2
                    and len(
                        {
                            record.get("correlation_id")
                            for record in by_id.values()
                        }
                    )
                    == 1
                    and selected_id == oracle.get("selected_record_id")
                    and selected_id in by_id
                    and oracle.get("unselected_record_status")
                    == {"record-correlation-a": "open"}
                    and oracle.get("records_merged_by_correlation") is False
                    and oracle.get("correlation_unique_required") is False
                    and oracle.get("correlation_affects_comparison") is False
                    and oracle.get(
                        "correlation_affects_baseline_selection"
                    )
                    is False,
                    path,
                    context,
                    "shared correlation must group only; explicit record ID "
                    "still selects one independent lifecycle record",
                )

    def validate_change_kind_cases(
        self, path: Path, cases: list[dict[str, Any]]
    ) -> None:
        for case in cases:
            context = f"case {case.get('id')!r}"
            if case.get("id") == "delta_endpoint_shapes":
                self.require_keys(
                    case,
                    ["input_variants", "oracle"],
                    path,
                    context,
                )
                continue
            if (
                case.get("id")
                == "restart_evidence_comparability_matrix"
            ):
                variants = case.get("input_variants")
                oracle = case.get("oracle")
                expected_ids = {
                    "changed_start_unknown_count",
                    "equal_start_increased_count",
                    "equal_start_equal_count",
                    "unknown_start_equal_count",
                    "equal_start_unknown_count",
                    "created_finished_gaps_only",
                    "inactive_to_active_unknown_restart_channels",
                    "recreated_unknown_restart_channels",
                }
                active_states = {"running", "paused", "restarting"}
                computed: dict[str, Any] = {}
                variants_valid = (
                    isinstance(variants, dict)
                    and set(variants) == expected_ids
                )
                if variants_valid:
                    for variant_id, variant in variants.items():
                        if not isinstance(variant, dict):
                            variants_valid = False
                            continue
                        before_state = variant.get(
                            "before_runtime_state"
                        )
                        after_state = variant.get("after_runtime_state")
                        same_id = variant.get("same_container_id")
                        before_started = variant.get("before_started_at")
                        after_started = variant.get("after_started_at")
                        before_count = variant.get(
                            "before_restart_count"
                        )
                        after_count = variant.get(
                            "after_restart_count"
                        )
                        gaps = variant.get("unrelated_metadata_gaps")
                        expected_fields = {
                            "same_container_id",
                            "before_runtime_state",
                            "after_runtime_state",
                            "before_started_at",
                            "after_started_at",
                            "before_restart_count",
                            "after_restart_count",
                            "unrelated_metadata_gaps",
                        }
                        variants_valid = variants_valid and (
                            set(variant) == expected_fields
                            and isinstance(same_id, bool)
                            and before_state
                            in self.schema.get("observation", {}).get(
                                "canonical_runtime_state_values", []
                            )
                            and after_state
                            in self.schema.get("observation", {}).get(
                                "canonical_runtime_state_values", []
                            )
                            and (
                                before_started is None
                                or isinstance(before_started, str)
                            )
                            and (
                                after_started is None
                                or isinstance(after_started, str)
                            )
                            and (
                                before_count is None
                                or (
                                    self.is_int(before_count)
                                    and before_count >= 0
                                )
                            )
                            and (
                                after_count is None
                                or (
                                    self.is_int(after_count)
                                    and after_count >= 0
                                )
                            )
                            and isinstance(gaps, list)
                            and gaps
                            == sorted(
                                set(gaps),
                                key=lambda gap: gap.encode("ascii"),
                            )
                        )
                        eligible = (
                            same_id is True
                            and before_state in active_states
                            and after_state in active_states
                        )
                        if eligible:
                            start_channel = (
                                "unknown"
                                if before_started is None
                                or after_started is None
                                else "positive"
                                if before_started != after_started
                                else "negative"
                            )
                            count_channel = (
                                "unknown"
                                if before_count is None
                                or after_count is None
                                else "positive"
                                if after_count > before_count
                                else "negative"
                            )
                        else:
                            start_channel = "not_applicable"
                            count_channel = "not_applicable"
                        positive_restart = (
                            start_channel == "positive"
                            or count_channel == "positive"
                        )
                        restart_unknown = (
                            eligible
                            and not positive_restart
                            and (
                                start_channel == "unknown"
                                or count_channel == "unknown"
                            )
                        )
                        if same_id is False:
                            primary_kind = "recreated"
                        elif (
                            before_state not in active_states
                            and after_state in active_states
                        ):
                            primary_kind = "started"
                        elif positive_restart:
                            primary_kind = "restarted"
                        else:
                            primary_kind = "unchanged"
                        computed[variant_id] = {
                            "start_channel": start_channel,
                            "restart_count_channel": count_channel,
                            "comparability": (
                                "degraded"
                                if restart_unknown
                                else "exact"
                            ),
                            "primary_kind": primary_kind,
                            "kinds": [primary_kind],
                        }
                self.require(
                    variants_valid
                    and variants.get(
                        "created_finished_gaps_only", {}
                    ).get("unrelated_metadata_gaps")
                    == [
                        "fixture-api.created_at",
                        "fixture-api.finished_at",
                    ]
                    and variants.get(
                        "inactive_to_active_unknown_restart_channels",
                        {},
                    ).get("before_runtime_state")
                    == "stopped"
                    and variants.get(
                        "recreated_unknown_restart_channels", {}
                    ).get("same_container_id")
                    is False
                    and oracle == computed,
                    path,
                    context,
                    "restart evidence must use positive-wins three-valued "
                    "OR semantics, degrading only eligible unresolved "
                    "active-to-active pairs",
                )
                continue
            if not self.require_keys(
                case, ["before", "after", "oracle"], path, context
            ):
                continue
            for endpoint in ("before", "after"):
                self.validate_normalized_container_projection(
                    path, f"{context}.{endpoint}", case[endpoint]
                )
            oracle = case["oracle"]
            self.enum(
                oracle.get("comparability"),
                self.schema.get("oracle", {}).get("comparability_values", []),
                path,
                f"{context}.oracle.comparability",
            )
            kinds = oracle.get("kinds")
            self.require(
                isinstance(kinds, list) and bool(kinds),
                path,
                f"{context}.oracle.kinds",
                "must be a non-empty list",
            )
            if isinstance(kinds, list):
                for kind in kinds:
                    self.enum(
                        kind,
                        self.schema.get("oracle", {}).get(
                            "container_delta_kind_values", []
                        ),
                        path,
                        f"{context}.oracle.kinds",
                    )
                self.require(
                    oracle.get("primary_kind") in kinds,
                    path,
                    f"{context}.oracle.primary_kind",
                    "must be present in kinds",
                )
            image_facet_cases = {
                "same_container_reference_only_image_change": (True, False),
                "same_container_same_tag_new_image_id": (False, True),
            }
            expected_facets = image_facet_cases.get(case.get("id"))
            if expected_facets is not None:
                before = case.get("before", {})
                after = case.get("after", {})
                expected_reference_change, expected_content_change = (
                    expected_facets
                )
                self.require(
                    before.get("container_id") == after.get("container_id")
                    and (
                        before.get("full_image_reference")
                        != after.get("full_image_reference")
                    )
                    is expected_reference_change
                    and (before.get("image_id") != after.get("image_id"))
                    is expected_content_change,
                    path,
                    context,
                    "image-change inputs must isolate the named reference/content "
                    "facet on the same container",
                )
                self.require(
                    oracle.get("primary_kind") == "image_changed"
                    and oracle.get("kinds") == ["image_changed"]
                    and oracle.get("image_reference_changed")
                    is expected_reference_change
                    and oracle.get("image_content_changed")
                    is expected_content_change
                    and oracle.get("recreated") is False,
                    path,
                    f"{context}.oracle",
                    "image-change facets must match the case name without "
                    "claiming recreation",
                )
            if case.get("id") == "same_container_reference_only_image_change":
                before = case.get("before", {})
                after = case.get("after", {})
                before_reference = before.get("full_image_reference")
                after_reference = after.get("full_image_reference")
                before_leaf = (
                    before_reference.rsplit("/", 1)[-1]
                    if isinstance(before_reference, str)
                    else ""
                )
                after_leaf = (
                    after_reference.rsplit("/", 1)[-1]
                    if isinstance(after_reference, str)
                    else ""
                )
                before_basename, separator_before, before_tag = (
                    before_leaf.rpartition(":")
                )
                after_basename, separator_after, after_tag = (
                    after_leaf.rpartition(":")
                )
                before_repository = (
                    before_reference.rsplit("/", 1)[0]
                    if isinstance(before_reference, str)
                    and "/" in before_reference
                    else None
                )
                after_repository = (
                    after_reference.rsplit("/", 1)[0]
                    if isinstance(after_reference, str)
                    and "/" in after_reference
                    else None
                )
                self.require(
                    separator_before == ":"
                    and separator_after == ":"
                    and before_repository != after_repository
                    and before_basename == after_basename == "api"
                    and before_tag == after_tag == "v1"
                    and oracle.get("repository_basename_before")
                    == before_basename
                    and oracle.get("repository_basename_after")
                    == after_basename
                    and oracle.get("explicit_tag_before") == before_tag
                    and oracle.get("explicit_tag_after") == after_tag
                    and oracle.get("initial_compact_display_labels_equal")
                    is True
                    and before.get("image_id") == after.get("image_id")
                    and before.get("container_id") == after.get("container_id"),
                    path,
                    context,
                    "reference-only image change must preserve container and "
                    "content identity while changing repository context hidden "
                    "by the equal basename-and-tag compact labels",
                )

    def validate_persistence_cases(
        self, path: Path, cases: list[dict[str, Any]]
    ) -> None:
        instance_id_re = re.compile(
            r"\A[a-z0-9][a-z0-9_-]{0,62}\Z"
        )

        def state_root_rejection_reason(value: Any) -> str | None:
            if not isinstance(value, str):
                return "invalid_type"
            if "\0" in value:
                return "nul"
            if not value.startswith("/"):
                return "not_absolute"
            if value == "/":
                return "filesystem_root_forbidden"
            if value.endswith("/"):
                return "trailing_separator"
            if "//" in value:
                return "repeated_separator"
            components = value.split("/")[1:]
            if ".." in components:
                return "parent_component"
            if "." in components:
                return "current_component"
            return None

        def materialize_instance_id(value: Any) -> str | None:
            if isinstance(value, str):
                return value
            if not isinstance(value, dict):
                return None
            if "value" in value:
                return value.get("value")
            recipes = {
                "lowercase_a_followed_by_62_lowercase_b": "a" + ("b" * 62),
                "lowercase_a_followed_by_63_lowercase_b": "a" + ("b" * 63),
            }
            return recipes.get(value.get("recipe"))

        def instance_id_rejection_reason(value: Any) -> str | None:
            if not isinstance(value, str):
                return "invalid_type"
            if value == "":
                return "empty"
            if len(value.encode("utf-8")) > 63:
                return "too_long"
            if value == ".." or value.startswith("../") or "/../" in value:
                return "traversal_syntax"
            if any(character.isupper() for character in value):
                return "uppercase"
            if any(character.isspace() for character in value):
                return "whitespace"
            if "/" in value or "\\" in value:
                return "separator"
            if value[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
                return "invalid_first_character"
            if "." in value:
                return "dot"
            if instance_id_re.fullmatch(value) is None:
                return "invalid_character"
            return None

        def parse_octal_mode(value: Any) -> int | None:
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[0-7]{4}", value) is None
            ):
                return None
            return int(value, 8)

        def trusted_ancestor_is_safe(
            candidate: Any, effective_uid: int
        ) -> bool:
            if not isinstance(candidate, dict):
                return False
            mode = parse_octal_mode(candidate.get("mode"))
            if mode is None:
                return False
            sticky = bool(mode & 0o1000)
            if "sticky" in candidate:
                sticky = sticky and candidate.get("sticky") is True
            group_or_other_writable = bool(mode & 0o022)
            return (
                candidate.get("exists", True) is True
                and candidate.get("type") == "directory"
                and candidate.get("symlink") is False
                and candidate.get("name_and_descriptor_identity_match") is True
                and candidate.get("uid") in {0, effective_uid}
                and (
                    not group_or_other_writable
                    or (candidate.get("uid") == 0 and sticky)
                )
            )

        def role_directory_is_safe(candidate: Any, effective_uid: int) -> bool:
            return (
                isinstance(candidate, dict)
                and candidate.get("exists", True) is True
                and candidate.get("type") == "directory"
                and candidate.get("uid") == effective_uid
                and parse_octal_mode(candidate.get("mode")) == 0o700
                and candidate.get("symlink") is False
                and candidate.get("name_and_descriptor_identity_match") is True
            )

        def role_file_is_safe(candidate: Any, effective_uid: int) -> bool:
            return (
                isinstance(candidate, dict)
                and candidate.get("exists", True) is True
                and candidate.get("type") == "regular_file"
                and candidate.get("uid") == effective_uid
                and parse_octal_mode(candidate.get("mode")) == 0o600
                and candidate.get("link_count") == 1
                and candidate.get("symlink") is False
                and candidate.get("name_and_descriptor_identity_match") is True
            )

        expected_atomic_trace = [
            "acquire_exclusive_state_lock",
            "recheck_lock_name_descriptor_identity",
            "reopen_and_validate_canonical_state",
            "verify_expected_revision",
            "create_unpredictable_temporary_exclusive_nofollow",
            "write_complete_canonical_bytes",
            "fsync_temporary_file",
            "recheck_temporary_metadata_and_identity",
            "atomic_replace_state_json",
            "fsync_instance_directory",
            "report_committed",
        ]

        for case in cases:
            oracle = case.get("oracle", {})
            outcome = oracle.get("persistence_outcome")
            if (
                case.get("id")
                == "absent_namespace_creation_is_operation_bounded"
            ):
                self.require(
                    "persistence_outcome" not in oracle,
                    path,
                    f"case {case.get('id')!r}.oracle",
                    "mixed invocation variants must declare their public "
                    "persistence outcomes per variant",
                )
            else:
                self.enum(
                    outcome,
                    self.schema.get("oracle", {}).get(
                        "persistence_outcome_values", []
                    ),
                    path,
                    f"case {case.get('id')!r}.oracle.persistence_outcome",
                )
            context = f"case {case.get('id')!r}"
            failure_reporting_cases = {
                "fault_before_atomic_replace",
                "fault_after_replace_before_directory_fsync",
                "retained_record_signature_conflict",
                "recently_pruned_record_conflict",
                "record_pruned_during_discovery",
                "never_known_record",
                "required_state_exceeds_byte_cap_fails",
                "unsafe_preexisting_namespace_fails_closed",
            }
            if case.get("id") in failure_reporting_cases:
                self.require(
                    oracle.get("diagnostic_rendered_before_failure") is True
                    and oracle.get("full_report_rendered") is False
                    and oracle.get("full_machine_result_in_failed_callback")
                    is False
                    and oracle.get("compact_failure_envelope_present") is True
                    and oracle.get("task_failed") is True,
                    path,
                    f"{context}.oracle",
                    "hard failures must emit one safe diagnostic and bounded "
                    "envelope without an uncommitted full report",
                )
            if case.get("id") == "state_root_lexical_contract":
                accepted = case.get("accepted")
                rejected = case.get("rejected")
                computed_rejections = (
                    [
                        {
                            "value": item.get("value"),
                            "reason": state_root_rejection_reason(
                                item.get("value")
                            ),
                        }
                        for item in rejected
                    ]
                    if isinstance(rejected, list)
                    and all(isinstance(item, dict) for item in rejected)
                    else None
                )
                accepted_mutation_probes_pass = (
                    isinstance(accepted, list)
                    and all(isinstance(item, str) for item in accepted)
                    and all(
                        state_root_rejection_reason(item[1:])
                        == "not_absolute"
                        and state_root_rejection_reason(f"{item}/")
                        == "trailing_separator"
                        and state_root_rejection_reason(f"/{item}")
                        == "repeated_separator"
                        for item in accepted
                    )
                )
                self.require(
                    outcome == "not_attempted"
                    and isinstance(accepted, list)
                    and all(
                        state_root_rejection_reason(item) is None
                        for item in accepted
                    )
                    and computed_rejections == rejected
                    and accepted_mutation_probes_pass
                    and oracle.get("accepted_count") == len(accepted) == 2
                    and oracle.get("rejected_count") == len(rejected) == 7
                    and oracle.get("rejected_failure_reason")
                    == "invalid_input"
                    and oracle.get("filesystem_access_for_rejected") is False
                    and oracle.get("docker_discovery_for_rejected") is False,
                    path,
                    f"{context}.oracle",
                    "state_root acceptance and every rejection reason must be "
                    "recomputed from the frozen absolute lexical-path rules",
                )
            if case.get("id") == "instance_id_namespace_grammar":
                accepted = case.get("accepted")
                rejected = case.get("rejected")
                materialized_accepted = (
                    [materialize_instance_id(item) for item in accepted]
                    if isinstance(accepted, list)
                    else None
                )
                materialized_rejected = (
                    [materialize_instance_id(item) for item in rejected]
                    if isinstance(rejected, list)
                    else None
                )
                declared_recipe_lengths_match = (
                    isinstance(accepted, list)
                    and isinstance(rejected, list)
                    and all(
                        not isinstance(item, dict)
                        or "recipe" not in item
                        or (
                            isinstance(
                                materialize_instance_id(item), str
                            )
                            and item.get("utf8_bytes")
                            == len(
                                materialize_instance_id(item).encode(
                                    "utf-8"
                                )
                            )
                        )
                        for item in [*accepted, *rejected]
                        if materialize_instance_id(item) is not None
                    )
                )
                computed_rejection_reasons = (
                    [
                        instance_id_rejection_reason(materialized)
                        for materialized in materialized_rejected
                    ]
                    if isinstance(materialized_rejected, list)
                    else None
                )
                declared_rejection_reasons = (
                    [item.get("reason") for item in rejected]
                    if isinstance(rejected, list)
                    and all(isinstance(item, dict) for item in rejected)
                    else None
                )
                boundary_id = (
                    materialized_accepted[-1]
                    if isinstance(materialized_accepted, list)
                    and materialized_accepted
                    else None
                )
                instance_mutation_probes_pass = (
                    isinstance(materialized_accepted, list)
                    and all(
                        isinstance(item, str)
                        and instance_id_rejection_reason(item.upper())
                        is not None
                        and instance_id_rejection_reason(
                            f"{item[:-1]}."
                            if len(item.encode("utf-8")) == 63
                            else f"{item}."
                        )
                        == "dot"
                        for item in materialized_accepted
                    )
                    and isinstance(boundary_id, str)
                    and len(boundary_id.encode("utf-8")) == 63
                    and instance_id_rejection_reason(f"{boundary_id}b")
                    == "too_long"
                )
                self.require(
                    outcome == "not_attempted"
                    and isinstance(materialized_accepted, list)
                    and all(
                        isinstance(item, str)
                        and instance_id_re.fullmatch(item) is not None
                        and instance_id_rejection_reason(item) is None
                        for item in materialized_accepted
                    )
                    and computed_rejection_reasons
                    == declared_rejection_reasons
                    and declared_recipe_lengths_match
                    and instance_mutation_probes_pass
                    and oracle.get("grammar")
                    == "[a-z0-9][a-z0-9_-]{0,62}"
                    and oracle.get("accepted_count")
                    == len(materialized_accepted)
                    == 3
                    and isinstance(materialized_rejected, list)
                    and oracle.get("rejected_count")
                    == len(materialized_rejected)
                    == 8
                    and oracle.get("rejected_failure_reason")
                    == "invalid_input"
                    and oracle.get("filesystem_access_for_rejected") is False
                    and oracle.get("docker_discovery_for_rejected") is False,
                    path,
                    f"{context}.oracle",
                    "instance IDs and boundary recipes must independently "
                    "satisfy the exact lowercase 1-to-63-byte grammar",
                )
            if case.get("id") == "secure_posix_namespace_is_accepted":
                platform = case.get("platform_contract")
                effective_uid = case.get("effective_uid")
                state_root = case.get("state_root_input")
                instance_id = case.get("instance_id")
                policy = case.get("trusted_ancestor_policy")
                namespace = case.get("synthetic_namespace")
                traversal = (
                    namespace.get("traversal_from_root")
                    if isinstance(namespace, dict)
                    else None
                )
                role_objects = (
                    namespace.get("role_owned_objects")
                    if isinstance(namespace, dict)
                    else None
                )
                sticky = (
                    policy.get("root_owned_sticky")
                    if isinstance(policy, dict)
                    else None
                )
                sticky_probe = (
                    {
                        "exists": True,
                        "type": "directory",
                        "uid": sticky.get("uid"),
                        "mode": sticky.get("mode"),
                        "symlink": False,
                        "name_and_descriptor_identity_match": True,
                    }
                    if isinstance(sticky, dict)
                    else None
                )
                nonsticky_probe = (
                    {**sticky_probe, "mode": "0777", "sticky": False}
                    if isinstance(sticky_probe, dict)
                    else None
                )
                expected_root_path = (
                    f"{state_root}/{instance_id}"
                    if isinstance(state_root, str)
                    and isinstance(instance_id, str)
                    else None
                )
                expected_object_paths = {
                    state_root,
                    expected_root_path,
                    f"{expected_root_path}/state.json",
                    f"{expected_root_path}/state.lock",
                }

                def secure_role_object(candidate: Any) -> bool:
                    if not isinstance(candidate, dict):
                        return False
                    if candidate.get("path") in {
                        state_root,
                        expected_root_path,
                    }:
                        return role_directory_is_safe(
                            candidate, effective_uid
                        )
                    return role_file_is_safe(candidate, effective_uid)

                mutated_uid = (
                    effective_uid + 1
                    if self.is_int(effective_uid)
                    else None
                )
                role_object_mutation_probes_pass = (
                    isinstance(role_objects, list)
                    and all(isinstance(item, dict) for item in role_objects)
                    and all(
                        all(
                            not secure_role_object(mutated)
                            for mutated in (
                                {**item, "uid": mutated_uid},
                                {**item, "mode": "0777"},
                                {**item, "type": "symlink"},
                                {**item, "symlink": True},
                                {
                                    **item,
                                    "name_and_descriptor_identity_match": False,
                                },
                            )
                        )
                        and (
                            item.get("type") != "regular_file"
                            or not secure_role_object(
                                {**item, "link_count": 2}
                            )
                        )
                        for item in role_objects
                    )
                )
                expected_platform = {
                    "local_posix_filesystem": True,
                    "descriptor_relative_open": True,
                    "no_follow": True,
                    "advisory_flock": True,
                    "regular_file_fsync": True,
                    "directory_fsync": True,
                    "atomic_same_directory_replace": True,
                }
                ordinary_policy = (
                    policy.get("ordinary")
                    if isinstance(policy, dict)
                    else None
                )
                self.require(
                    outcome == "not_attempted"
                    and platform == expected_platform
                    and self.is_int(effective_uid)
                    and state_root_rejection_reason(state_root) is None
                    and instance_id_rejection_reason(instance_id) is None
                    and isinstance(ordinary_policy, dict)
                    and ordinary_policy.get("accepted_owner_uids")
                    == [0, effective_uid]
                    and ordinary_policy.get("group_or_other_writable")
                    is False
                    and isinstance(traversal, list)
                    and all(
                        trusted_ancestor_is_safe(item, effective_uid)
                        for item in traversal
                    )
                    and isinstance(role_objects, list)
                    and {item.get("path") for item in role_objects}
                    == expected_object_paths
                    and all(
                        secure_role_object(item) for item in role_objects
                    )
                    and role_object_mutation_probes_pass
                    and trusted_ancestor_is_safe(
                        sticky_probe, effective_uid
                    )
                    and not trusted_ancestor_is_safe(
                        nonsticky_probe, effective_uid
                    )
                    and sticky.get("representative_path") == "/tmp"
                    and sticky.get("accepted") is True
                    and oracle.get("namespace_accepted") is True
                    and oracle.get("canonical_path")
                    == f"{expected_root_path}/state.json"
                    and oracle.get("stable_lock_path")
                    == f"{expected_root_path}/state.lock"
                    and parse_octal_mode(oracle.get("state_root_mode"))
                    == 0o700
                    and parse_octal_mode(
                        oracle.get("instance_directory_mode")
                    )
                    == 0o700
                    and parse_octal_mode(oracle.get("regular_file_mode"))
                    == 0o600
                    and oracle.get("owner_is_effective_uid") is True
                    and oracle.get("root_owned_sticky_ancestor_accepted")
                    is True,
                    path,
                    f"{context}.oracle",
                    "the accepted POSIX namespace must independently satisfy "
                    "platform, path, owner, mode, type, link, inode, and "
                    "root-owned sticky-ancestor rules",
                )
            if (
                case.get("id")
                == "unsafe_preexisting_namespace_fails_closed"
            ):
                effective_uid = case.get("effective_uid")
                state_root = case.get("otherwise_valid_state_root")
                instance_root = f"{state_root}/fixture-mdad"
                state_path = f"{instance_root}/state.json"
                lock_path = f"{instance_root}/state.lock"
                variants = case.get("variants")
                expected_variant_ids = {
                    "symlinked_ancestor",
                    "missing_ancestor",
                    "untrusted_ancestor_owner",
                    "world_writable_nonsticky_ancestor",
                    "symlinked_state_root",
                    "wrong_state_root_owner",
                    "group_readable_state_root",
                    "wrong_instance_directory_type",
                    "wrong_instance_directory_owner",
                    "wrong_instance_directory_mode",
                    "symlinked_canonical_state",
                    "wrong_canonical_state_owner",
                    "wrong_canonical_state_mode",
                    "hardlinked_canonical_state",
                    "lock_is_directory",
                    "wrong_lock_mode",
                    "name_descriptor_inode_mismatch",
                }

                def safe_namespace_base(object_path: Any) -> dict[str, Any]:
                    if object_path == "/srv":
                        return {
                            "exists": True,
                            "type": "directory",
                            "uid": 0,
                            "mode": "0755",
                            "symlink": False,
                            "name_and_descriptor_identity_match": True,
                        }
                    if object_path in {state_root, instance_root}:
                        return {
                            "exists": True,
                            "type": "directory",
                            "uid": effective_uid,
                            "mode": "0700",
                            "symlink": False,
                            "name_and_descriptor_identity_match": True,
                        }
                    return {
                        "exists": True,
                        "type": "regular_file",
                        "uid": effective_uid,
                        "mode": "0600",
                        "link_count": 1,
                        "symlink": False,
                        "name_and_descriptor_identity_match": True,
                    }

                def apply_namespace_violation(
                    candidate: dict[str, Any], violation: Any
                ) -> dict[str, Any]:
                    mutated = dict(candidate)
                    if violation == "symlink":
                        mutated["symlink"] = True
                    elif violation == "missing":
                        mutated["exists"] = False
                    elif isinstance(violation, dict):
                        for key in (
                            "type",
                            "uid",
                            "mode",
                            "link_count",
                            "sticky",
                        ):
                            if key in violation:
                                mutated[key] = violation[key]
                        if (
                            "name_inode" in violation
                            and "descriptor_inode" in violation
                        ):
                            mutated[
                                "name_and_descriptor_identity_match"
                            ] = (
                                violation.get("name_inode")
                                == violation.get("descriptor_inode")
                            )
                    return mutated

                def unsafe_variant_rejected(variant: Any) -> bool:
                    if not isinstance(variant, dict):
                        return False
                    object_path = variant.get("object")
                    mutated = apply_namespace_violation(
                        safe_namespace_base(object_path),
                        variant.get("violation"),
                    )
                    if object_path == "/srv":
                        return not trusted_ancestor_is_safe(
                            mutated, effective_uid
                        )
                    if object_path in {state_root, instance_root}:
                        return not role_directory_is_safe(
                            mutated, effective_uid
                        )
                    if object_path in {state_path, lock_path}:
                        return not role_file_is_safe(
                            mutated, effective_uid
                        )
                    return False

                variant_by_id = (
                    {
                        variant.get("id"): variant
                        for variant in variants
                        if isinstance(variant, dict)
                    }
                    if isinstance(variants, list)
                    else {}
                )
                nonsticky_violation = (
                    variant_by_id.get(
                        "world_writable_nonsticky_ancestor", {}
                    ).get("violation")
                    if variant_by_id
                    else None
                )
                sticky_acceptance_probe = {
                    "exists": True,
                    "type": "directory",
                    "uid": 0,
                    "mode": "1777",
                    "symlink": False,
                    "name_and_descriptor_identity_match": True,
                }
                self.require(
                    outcome == "failed"
                    and self.is_int(effective_uid)
                    and state_root_rejection_reason(state_root) is None
                    and isinstance(variants, list)
                    and set(variant_by_id) == expected_variant_ids
                    and len(variants)
                    == len(variant_by_id)
                    == oracle.get("variant_count")
                    == 17
                    and all(
                        unsafe_variant_rejected(variant)
                        for variant in variants
                    )
                    and isinstance(nonsticky_violation, dict)
                    and nonsticky_violation.get("uid") == 0
                    and parse_octal_mode(
                        nonsticky_violation.get("mode")
                    )
                    == 0o777
                    and nonsticky_violation.get("sticky") is False
                    and trusted_ancestor_is_safe(
                        sticky_acceptance_probe, effective_uid
                    )
                    and unsafe_variant_rejected(
                        variant_by_id[
                            "world_writable_nonsticky_ancestor"
                        ]
                    )
                    and oracle.get("failure_reason_for_each")
                    == "unsafe_state_namespace"
                    and oracle.get("docker_discovery_for_each") is False
                    and oracle.get("canonical_state_mutated_for_each")
                    is False
                    and oracle.get("automatic_chmod_for_each") is False
                    and oracle.get("automatic_chown_for_each") is False
                    and oracle.get("automatic_unlink_for_each") is False
                    and oracle.get("task_failed_for_each") is True,
                    path,
                    f"{context}.oracle",
                    "every declared namespace mutation must independently "
                    "violate its ancestor, directory, or regular-file rule; "
                    "root-owned sticky 1777 remains the sole writable "
                    "ancestor exception",
                )
            if (
                case.get("id")
                == "absent_namespace_creation_is_operation_bounded"
            ):
                variants = case.get("variants")

                def namespace_creation_permitted(invocation: Any) -> bool:
                    if not isinstance(invocation, dict):
                        return False
                    if invocation.get("enabled", True) is False:
                        return False
                    if invocation.get("check_mode", False) is True:
                        return False
                    operation = invocation.get("operation")
                    if operation == "pre":
                        return True
                    return (
                        operation == "post"
                        and invocation.get("record_id") is None
                    )

                computed_permissions = (
                    [
                        namespace_creation_permitted(
                            variant.get("invocation")
                        )
                        for variant in variants
                    ]
                    if isinstance(variants, list)
                    and all(isinstance(item, dict) for item in variants)
                    else None
                )
                declared_permissions = (
                    [
                        variant.get("namespace_creation_permitted")
                        for variant in variants
                    ]
                    if isinstance(variants, list)
                    else None
                )
                declared_outcomes = (
                    [
                        variant.get("persistence_outcome")
                        for variant in variants
                    ]
                    if isinstance(variants, list)
                    else None
                )
                computed_outcomes = (
                    [
                        (
                            "committed"
                            if namespace_creation_permitted(
                                variant.get("invocation")
                            )
                            else "conflict"
                            if (
                                isinstance(
                                    variant.get("invocation"), dict
                                )
                                and variant["invocation"].get("operation")
                                == "post"
                                and variant["invocation"].get("record_id")
                                is not None
                            )
                            else "not_attempted"
                        )
                        for variant in variants
                    ]
                    if isinstance(variants, list)
                    and all(isinstance(item, dict) for item in variants)
                    else None
                )
                unknown_post = (
                    variants[2]
                    if isinstance(variants, list) and len(variants) > 2
                    else {}
                )
                pre_invocation = (
                    variants[0].get("invocation")
                    if isinstance(variants, list)
                    and variants
                    and isinstance(variants[0], dict)
                    else {}
                )
                post_only_invocation = (
                    variants[1].get("invocation")
                    if isinstance(variants, list)
                    and len(variants) > 1
                    and isinstance(variants[1], dict)
                    else {}
                )
                self.require(
                    case.get("initial_namespace") == "absent"
                    and computed_permissions
                    == declared_permissions
                    == [True, True, False, False, False, False]
                    and computed_outcomes
                    == declared_outcomes
                    == [
                        "committed",
                        "committed",
                        "conflict",
                        "not_attempted",
                        "not_attempted",
                        "not_attempted",
                    ]
                    and unknown_post.get("failure_reason")
                    == "unknown_record"
                    and not namespace_creation_permitted(
                        {**pre_invocation, "check_mode": True}
                    )
                    and not namespace_creation_permitted(
                        {
                            **post_only_invocation,
                            "record_id": "mutation-probe",
                        }
                    )
                    and parse_octal_mode(
                        oracle.get("new_directory_mode")
                    )
                    == 0o700
                    and parse_octal_mode(oracle.get("new_file_mode"))
                    == 0o600
                    and oracle.get("descriptor_relative_creation") is True
                    and oracle.get("exclusive_file_creation") is True
                    and oracle.get("symlink_followed") is False,
                    path,
                    f"{context}.oracle",
                    "only non-check pre and post-only calls may create an "
                    "absent namespace; supplied post IDs, status, check mode, "
                    "and disabled calls must remain creation-free",
                )
            if case.get("id") == "stable_lock_and_atomic_commit_trace":
                prior = case.get("prior_namespace")
                transaction = case.get("transaction")
                resulting = case.get("resulting_namespace")
                trace = (
                    transaction.get("trace")
                    if isinstance(transaction, dict)
                    else None
                )
                trace_mutations_rejected = (
                    isinstance(trace, list)
                    and trace == expected_atomic_trace
                    and trace[:6] + trace[7:] != expected_atomic_trace
                    and (
                        trace[:8]
                        + [trace[9], trace[8]]
                        + trace[10:]
                    )
                    != expected_atomic_trace
                    and [*trace, "report_committed"]
                    != expected_atomic_trace
                )
                self.require(
                    outcome == "committed"
                    and isinstance(prior, dict)
                    and isinstance(transaction, dict)
                    and isinstance(resulting, dict)
                    and trace_mutations_rejected
                    and transaction.get("expected_revision")
                    == prior.get("revision")
                    and transaction.get("temporary_name_preexisted")
                    is False
                    and transaction.get("replacement_state_inode")
                    == transaction.get("temporary_inode")
                    == resulting.get("state_inode")
                    and resulting.get("state_inode")
                    != prior.get("state_inode")
                    and resulting.get("lock_inode")
                    == prior.get("lock_inode")
                    and self.is_int(prior.get("revision"))
                    and resulting.get("revision")
                    == prior.get("revision") + 1
                    and resulting.get("temporary_name_present") is False
                    and oracle.get("stable_lock_inode_preserved") is True
                    and oracle.get("lock_unlinked") is False
                    and oracle.get("state_replaced_as_one_inode") is True
                    and oracle.get("mixed_store_visible") is False
                    and parse_octal_mode(
                        oracle.get("canonical_state_mode")
                    )
                    == 0o600
                    and oracle.get("canonical_state_link_count") == 1,
                    path,
                    f"{context}.oracle",
                    "the exact commit trace must preserve one lock inode, "
                    "replace state with the fsynced temporary inode, advance "
                    "one revision, and reject missing/reordered/duplicate "
                    "trace mutations",
                )
            if (
                case.get("id")
                == "preexisting_temporary_names_are_ignored"
            ):
                canonical = case.get("canonical_state")
                preexisting = case.get("preexisting_names")
                invocation_temp = case.get("invocation_temporary")

                def ignored_temp_policy(candidate: Any) -> bool:
                    return (
                        isinstance(candidate, dict)
                        and candidate.get("preexisting_names_opened") is False
                        and candidate.get("preexisting_names_unlinked")
                        is False
                        and candidate.get("preexisting_names_authoritative")
                        is False
                        and candidate.get(
                            "canonical_state_selected_by_fixed_name_only"
                        )
                        is True
                    )

                hostile_names_are_distinct = (
                    isinstance(preexisting, list)
                    and len(preexisting) == 2
                    and all(isinstance(item, dict) for item in preexisting)
                    and len(
                        {item.get("name") for item in preexisting}
                    )
                    == 2
                    and all(
                        isinstance(item.get("name"), str)
                        and item["name"].startswith(".state.json.tmp.")
                        and item["name"] not in {"state.json", "state.lock"}
                        for item in preexisting
                    )
                    and {
                        (
                            item.get("type"),
                            item.get("link_count"),
                        )
                        for item in preexisting
                    }
                    == {("symlink", None), ("regular_file", 2)}
                )
                oracle_policy_mutations_rejected = all(
                    not ignored_temp_policy({**oracle, key: value})
                    for key, value in (
                        ("preexisting_names_opened", True),
                        ("preexisting_names_unlinked", True),
                        ("preexisting_names_authoritative", True),
                        (
                            "canonical_state_selected_by_fixed_name_only",
                            False,
                        ),
                    )
                )
                self.require(
                    outcome == "not_attempted"
                    and isinstance(canonical, dict)
                    and self.is_int(canonical.get("revision"))
                    and canonical.get("valid") is True
                    and hostile_names_are_distinct
                    and isinstance(invocation_temp, dict)
                    and invocation_temp.get("name_was_unpredictable") is True
                    and invocation_temp.get("created_exclusive") is True
                    and invocation_temp.get("no_follow") is True
                    and ignored_temp_policy(oracle)
                    and oracle_policy_mutations_rejected,
                    path,
                    f"{context}.oracle",
                    "pre-existing symlink and hard-link temporary traps must "
                    "remain unopened, unlinked, and non-authoritative while "
                    "the invocation creates only its unpredictable exclusive "
                    "temporary",
                )
            if (
                case.get("id")
                == "fault_after_replace_before_directory_fsync"
            ):
                prior = case.get("prior_state")
                candidate = case.get("candidate_state")
                control = case.get("test_control")
                recovery = oracle.get("acceptable_recovery_after_restart")
                failure_task_result = oracle.get("failure_task_result")
                failure_envelope = (
                    failure_task_result.get(
                        "docker_ansible_summary_failure"
                    )
                    if isinstance(failure_task_result, dict)
                    else None
                )
                failure_result_bytes = (
                    len(
                        json.dumps(
                            failure_task_result,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
                    if isinstance(failure_task_result, dict)
                    else 0
                )
                expected_recovery = {
                    "idempotent_replay_of_revision_12",
                    "single_commit_from_revision_11",
                }
                recovery_mutations_rejected = (
                    isinstance(recovery, list)
                    and all(isinstance(item, str) for item in recovery)
                    and len(recovery) == len(set(recovery)) == 2
                    and set(recovery) == expected_recovery
                    and set(recovery[:1]) != expected_recovery
                    and set([*recovery, "duplicate_commit"])
                    != expected_recovery
                )
                self.require(
                    outcome == "failed"
                    and isinstance(prior, dict)
                    and isinstance(candidate, dict)
                    and HEX_64_RE.fullmatch(
                        str(prior.get("canonical_bytes_sha256"))
                    )
                    is not None
                    and HEX_64_RE.fullmatch(
                        str(candidate.get("canonical_bytes_sha256"))
                    )
                    is not None
                    and prior.get("canonical_bytes_sha256")
                    != candidate.get("canonical_bytes_sha256")
                    and self.is_int(prior.get("revision"))
                    and candidate.get("revision")
                    == prior.get("revision") + 1
                    and isinstance(candidate.get("record_id"), str)
                    and bool(candidate["record_id"])
                    and candidate.get("host") == "fixture-a.example.com"
                    and candidate.get("instance_id") == "fixture-mdad"
                    and candidate.get("operation") == "pre"
                    and candidate.get("observation_status") == "complete"
                    and SHA256_RE.fullmatch(
                        str(candidate.get("phase_signature"))
                    )
                    is not None
                    and isinstance(control, dict)
                    and control.get("inject_fault")
                    == "after_atomic_replace_before_directory_fsync"
                    and oracle.get("failure_reason") == "state_write_failed"
                    and oracle.get("mixed_store_visible") is False
                    and oracle.get("visible_state_immediately_after_replace")
                    == "candidate"
                    and oracle.get("crash_durability") == "indeterminate"
                    and oracle.get("successful_machine_result_returned")
                    is False
                    and oracle.get("fault_stage")
                    == "after_atomic_replace_before_directory_fsync"
                    and oracle.get("retry_record_id")
                    == candidate.get("record_id")
                    and oracle.get("retry_signature_must_match") is True
                    and isinstance(failure_task_result, dict)
                    and set(failure_task_result)
                    == {
                        "changed",
                        "failed",
                        "docker_ansible_summary_failure",
                    }
                    and failure_task_result.get("changed") is False
                    and failure_task_result.get("failed") is True
                    and isinstance(failure_envelope, dict)
                    and list(failure_envelope)
                    == EXACT_FAILURE_ENVELOPE_FIELDS
                    and failure_envelope
                    == {
                        "schema_version": 1,
                        "host": candidate.get("host"),
                        "instance_id": candidate.get("instance_id"),
                        "operation": candidate.get("operation"),
                        "record_id": candidate.get("record_id"),
                        "observation_status": candidate.get(
                            "observation_status"
                        ),
                        "failure_reason": "state_write_failed",
                        "observation_reason": None,
                        "persistence_outcome": "failed",
                        "committed_result_replayable": False,
                        "replay_guidance": (
                            "Retry with the same record_id and unchanged "
                            "phase inputs"
                        ),
                    }
                    and failure_result_bytes <= 1024
                    and recovery_mutations_rejected
                    and oracle.get("duplicate_commit_permitted") is False,
                    path,
                    f"{context}.oracle",
                    "a fault after atomic replacement must expose one whole "
                    "candidate with indeterminate crash durability and exactly "
                    "the old-state commit or new-state idempotent replay "
                    "recovery outcomes",
                )
            if case.get("id") == "delayed_pre_replay_after_completed_post":
                prior_state = case.get("prior_state", {})
                retained_record = (
                    prior_state.get("journal", [{}])[0]
                    if isinstance(prior_state.get("journal"), list)
                    and prior_state.get("journal")
                    else {}
                )
                self.require(
                    outcome == "not_attempted"
                    and oracle.get("replay_outcome") == "idempotent"
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_mutated") is False
                    and oracle.get("revision_after")
                    == prior_state.get("revision"),
                    path,
                    f"{context}.oracle",
                    "delayed pre replay must not rediscover or mutate state",
                )
                self.require(
                    oracle.get("returned_phase_observation_id")
                    == retained_record.get("pre_observation_id")
                    and oracle.get("returned_phase_baseline_advanced")
                    == retained_record.get("pre_baseline_advanced"),
                    path,
                    f"{context}.oracle",
                    "delayed pre replay must return the original pre-phase "
                    "observation and baseline outcome",
                )
                self.require(
                    oracle.get("journal_status_at_original_pre_commit")
                    == "open"
                    and retained_record.get("status") == "complete"
                    and oracle.get("machine_result_journal_status")
                    == retained_record.get("status"),
                    path,
                    f"{context}.oracle",
                    "delayed pre replay must retain the original open marker "
                    "while reporting the record's current complete status",
                )
            if case.get("id") == "lost_ack_replay_of_committed_post":
                prior_state = case.get("prior_state", {})
                original = case.get("original_commit", {})
                retry = case.get("identical_retry", {})
                retained_record = (
                    prior_state.get("journal", [{}])[0]
                    if isinstance(prior_state.get("journal"), list)
                    and prior_state.get("journal")
                    else {}
                )
                self.require(
                    original.get("persistence_outcome") == "committed"
                    and original.get("result_delivery") == "lost"
                    and original.get("baseline_advanced") is True,
                    path,
                    f"{context}.original_commit",
                    "fixture must begin with a committed post whose result was lost",
                )
                self.require(
                    retry.get("operation") == "post"
                    and retry.get("record_id")
                    == retained_record.get("record_id")
                    and retry.get("post_signature")
                    == retained_record.get("post_signature"),
                    path,
                    f"{context}.identical_retry",
                    "retry must exactly identify the retained committed post",
                )
                self.require(
                    outcome == "not_attempted"
                    and oracle.get("replay_outcome") == "idempotent"
                    and oracle.get("discovery_attempted_on_retry") is False
                    and oracle.get("store_mutated") is False
                    and oracle.get("revision_after_retry")
                    == prior_state.get("revision")
                    and oracle.get("additional_baseline_advance") is False,
                    path,
                    f"{context}.oracle",
                    "committed-post replay must not rediscover, mutate, or "
                    "advance the baseline again",
                )
                returned = oracle.get("returned_result", {})
                self.require(
                    returned.get("observation_id")
                    == prior_state.get("latest_complete_post_id")
                    and returned.get("baseline_advanced") is True
                    and returned.get("journal_status") == "complete",
                    path,
                    f"{context}.oracle.returned_result",
                    "replay must return the original committed result",
                )
            if case.get("id") == "retained_delta_preserves_endpoint_context":
                delta = case.get("retained_record", {}).get(
                    "between_observation_delta"
                )
                required = [
                    *self.schema.get("oracle", {}).get("delta_required", []),
                    *self.schema.get("oracle", {}).get(
                        "implementation_delta_context_required", []
                    ),
                ]
                if self.require_keys(
                    delta,
                    required,
                    path,
                    f"{context}.retained_record.between_observation_delta",
                ):
                    self.enum(
                        delta.get("comparability"),
                        self.schema.get("oracle", {}).get(
                            "comparability_values", []
                        ),
                        path,
                        f"{context}.retained_record."
                        "between_observation_delta.comparability",
                    )
                    self.require(
                        delta.get("comparison_schema_version") == 1,
                        path,
                        f"{context}.retained_record."
                        "between_observation_delta.comparison_schema_version",
                        "must equal 1",
                    )
                    for endpoint in ("from", "to"):
                        self.require(
                            isinstance(
                                delta.get(f"{endpoint}_observation_id"), str
                            )
                            and bool(
                                delta[f"{endpoint}_observation_id"].strip()
                            ),
                            path,
                            f"{context}.retained_record."
                            f"between_observation_delta.{endpoint}_observation_id",
                            "must retain a non-empty observation ID",
                        )
                        self.validate_timestamp(
                            delta.get(f"{endpoint}_observed_at"),
                            path,
                            f"{context}.retained_record."
                            f"between_observation_delta.{endpoint}_observed_at",
                        )
                        self.validate_scope(
                            path,
                            f"{context}.retained_record."
                            f"between_observation_delta.{endpoint}_scope",
                            delta.get(f"{endpoint}_scope"),
                        )
                    self.require(
                        isinstance(delta.get("changes"), list)
                        and isinstance(delta.get("warnings"), list),
                        path,
                        f"{context}.retained_record.between_observation_delta",
                        "must retain changes and warnings lists",
                    )
                self.require(
                    outcome == "not_attempted"
                    and oracle.get("delta_self_contained") is True
                    and oracle.get("old_baseline_lookup_required") is False
                    and oracle.get("source_time_preserved") is True
                    and oracle.get("source_scope_preserved") is True,
                    path,
                    f"{context}.oracle",
                    "retained delta must remain self-contained after its old "
                    "baseline record is pruned",
                )
            if case.get("id") == "recently_pruned_record_conflict":
                recent_ids = case.get("prior_state", {}).get(
                    "recently_pruned_record_ids"
                )
                record_id = case.get("invocation", {}).get("record_id")
                self.require(
                    isinstance(recent_ids, list)
                    and record_id in recent_ids
                    and outcome == "conflict"
                    and oracle.get("conflict_reason") == "record_pruned"
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_mutated") is False,
                    path,
                    f"{context}.oracle",
                    "a retained recent ID must reject reuse before discovery",
                )
            if case.get("id") == "record_pruned_during_discovery":
                recent_ids = case.get("concurrent_committed_state", {}).get(
                    "recently_pruned_record_ids"
                )
                loaded_record = case.get("loaded_state", {}).get("journal", [{}])[0]
                self.require(
                    isinstance(recent_ids, list)
                    and loaded_record.get("record_id") in recent_ids
                    and outcome == "conflict"
                    and oracle.get("conflict_reason") == "record_pruned"
                    and oracle.get("discovery_attempted") is True
                    and oracle.get("proposed_values_committed") is False,
                    path,
                    f"{context}.oracle",
                    "commit-time pruning is specific only while the ID remains "
                    "in the bounded reuse guard",
                )
            if (
                case.get("id")
                == "concurrent_same_phase_commit_becomes_idempotent_replay"
            ):
                loaded = case.get("loaded_state", {})
                invocation = case.get("invocation", {})
                proposed = case.get("proposed_transition", {})
                concurrent = case.get("concurrent_committed_state", {})
                loaded_records = loaded.get("journal", [])
                concurrent_records = concurrent.get("journal", [])
                loaded_record = (
                    loaded_records[0]
                    if isinstance(loaded_records, list)
                    and len(loaded_records) == 1
                    else {}
                )
                committed_record = (
                    concurrent_records[0]
                    if isinstance(concurrent_records, list)
                    and len(concurrent_records) == 1
                    else {}
                )
                self.require(
                    loaded.get("revision") == 20
                    and concurrent.get("revision") == 21
                    and loaded_record.get("record_id")
                    == committed_record.get("record_id")
                    == invocation.get("record_id")
                    == "caller-racing-same-phase-006"
                    and loaded_record.get("status") == "open"
                    and loaded_record.get("post_signature") is None
                    and committed_record.get("status") == "complete"
                    and committed_record.get("post_signature")
                    == invocation.get("phase_signature")
                    and proposed.get("observation_id")
                    != committed_record.get("post_observation_id")
                    and outcome == "not_attempted"
                    and oracle
                    == {
                        "persistence_outcome": "not_attempted",
                        "replay_outcome": "idempotent",
                        "conflict_reason": None,
                        "discovery_attempted": True,
                        "store_mutated_by_invocation": False,
                        "revision_after": 21,
                        "returned_observation_id": (
                            "obs-racing-committed-post"
                        ),
                        "returned_baseline_advanced": True,
                        "proposed_observation_returned": False,
                        "task_failed": False,
                    },
                    path,
                    f"{context}.oracle",
                    "a same-record same-signature phase committed during "
                    "discovery must take idempotent-replay precedence over "
                    "the stale revision",
                )
            if (
                case.get("id")
                == "concurrent_pre_commit_becomes_idempotent_replay"
            ):
                loaded = case.get("loaded_state", {})
                invocation = case.get("invocation", {})
                proposed = case.get("proposed_transition", {})
                concurrent = case.get("concurrent_committed_state", {})
                concurrent_records = concurrent.get("journal", [])
                committed_record = (
                    concurrent_records[0]
                    if isinstance(concurrent_records, list)
                    and len(concurrent_records) == 1
                    else {}
                )
                self.require(
                    loaded
                    == {
                        "revision": 30,
                        "journal": [],
                        "recently_pruned_record_ids": [],
                    }
                    and invocation.get("operation") == "pre"
                    and invocation.get("record_id")
                    == committed_record.get("record_id")
                    == "caller-racing-pre-007"
                    and concurrent.get("revision") == 31
                    and committed_record.get("status") == "open"
                    and committed_record.get("expected_post_revision") == 31
                    and committed_record.get("pre_signature")
                    == invocation.get("phase_signature")
                    and proposed.get("observation_id")
                    != committed_record.get("pre_observation_id")
                    and outcome == "not_attempted"
                    and oracle
                    == {
                        "persistence_outcome": "not_attempted",
                        "replay_outcome": "idempotent",
                        "conflict_reason": None,
                        "discovery_attempted": True,
                        "store_mutated_by_invocation": False,
                        "revision_after": 31,
                        "returned_observation_id": (
                            "obs-racing-committed-pre"
                        ),
                        "returned_baseline_advanced": False,
                        "returned_expected_post_revision": 31,
                        "proposed_observation_returned": False,
                        "task_failed": False,
                    },
                    path,
                    f"{context}.oracle",
                    "a same-ID same-signature pre committed during discovery "
                    "must take idempotent-replay precedence over the stale "
                    "revision and return the committed open record",
                )
            if case.get("id") == "never_known_record":
                recent_ids = case.get("prior_state", {}).get(
                    "recently_pruned_record_ids"
                )
                record_id = case.get("invocation", {}).get("record_id")
                self.require(
                    recent_ids == []
                    and record_id
                    not in case.get("prior_state", {}).get("journal", [])
                    and outcome == "conflict"
                    and oracle.get("conflict_reason") == "unknown_record"
                    and oracle.get("discovery_attempted") is False,
                    path,
                    f"{context}.oracle",
                    "a post ID in neither retained set must be unknown",
                )
            if case.get("id") == "retention_prunes_oldest_open_record":
                prior = case.get("prior_state", {})
                prior_ids = [
                    record.get("record_id") for record in prior.get("journal", [])
                ]
                appended_id = (
                    case.get("transaction", {})
                    .get("append_record", {})
                    .get("record_id")
                )
                expected_retained = [*prior_ids, appended_id][
                    -case.get("transaction", {}).get("journal_max_records", 0) :
                ]
                expected_pruned = [
                    record_id
                    for record_id in prior_ids
                    if record_id not in expected_retained
                ]
                self.require(
                    outcome == "committed"
                    and oracle.get("retained_record_ids") == expected_retained
                    and oracle.get("pruned_record_ids") == expected_pruned
                    and oracle.get("recently_pruned_record_ids_after")
                    == expected_pruned
                    and oracle.get("latest_complete_post_id")
                    == prior.get("latest_complete_post_id"),
                    path,
                    f"{context}.oracle",
                    "count pruning must evict the oldest record, append only "
                    "its ID, and retain the baseline",
                )
            if case.get("id") == "recent_id_cap_evicts_oldest":
                transaction = case.get("transaction", {})
                prior = case.get("prior_state", {})
                cap = transaction.get("journal_max_records")
                prior_recent = prior.get("recently_pruned_record_ids", [])
                pruned_id = prior.get("journal", [{}])[0].get("record_id")
                expected_recent = [*prior_recent, pruned_id][-cap:]
                self.require(
                    self.is_int(cap)
                    and cap > 0
                    and outcome == "committed"
                    and oracle.get("retained_recent_ids") == expected_recent
                    and oracle.get("evicted_recent_ids")
                    == [prior_recent[0]]
                    and oracle.get("appended_recent_id") == pruned_id
                    and oracle.get("effective_recent_id_cap") == cap
                    and oracle.get("recent_id_count_after")
                    == len(expected_recent),
                    path,
                    f"{context}.oracle",
                    "the recent-ID guard must append then evict oldest-first "
                    "under the journal-sized cap",
                )
            if case.get("id") in {
                "render_failure_after_commit",
                "presentation_capacity_failure_after_commit",
            }:
                case_id = case.get("id")
                prior_state = case.get("prior_state", {})
                transition = case.get("transition", {})
                expected_failure_reason = {
                    "render_failure_after_commit": "render_failed",
                    "presentation_capacity_failure_after_commit": (
                        "presentation_capacity_exceeded"
                    ),
                }.get(case_id)
                expected_injected_fault = {
                    "render_failure_after_commit": "human_renderer",
                    "presentation_capacity_failure_after_commit": (
                        "presentation_capacity_exceeded"
                    ),
                }.get(case_id)
                diagnostic = (
                    oracle.get("failure_diagnostic", {})
                    if case_id == "render_failure_after_commit"
                    else oracle.get("failure_envelope", {})
                )
                retained_replay = oracle.get("retained_replay", {})
                prior_revision = prior_state.get("revision")
                self.require(
                    self.is_int(prior_revision)
                    and outcome == "committed"
                    and oracle.get("task_outcome") == "failed"
                    and oracle.get("failure_reason")
                    == expected_failure_reason
                    and case.get("test_control", {}).get("inject_fault")
                    == expected_injected_fault
                    and oracle.get("revision_after")
                    == prior_revision + 1
                    and oracle.get("latest_complete_post_id")
                    == transition.get("complete_observation_id")
                    and transition.get("record_id")
                    in oracle.get("journal_contains", [])
                    and oracle.get("committed_result_recoverable") is True
                    and oracle.get("diagnostic_rendered_before_failure") is True
                    and oracle.get("full_report_rendered") is False
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present") is True,
                    path,
                    f"{context}.oracle",
                    "render or presentation-capacity failure must visibly "
                    "fail after retaining one recoverable committed "
                    "transition",
                )
                self.require(
                    diagnostic.get("host") == transition.get("host")
                    and diagnostic.get("instance_id")
                    == transition.get("instance_id")
                    and diagnostic.get("record_id")
                    == transition.get("record_id")
                    and diagnostic.get("replay_guidance")
                    == "Retry the retained record with report_mode=none",
                    path,
                    f"{context}.oracle.failure_diagnostic_or_envelope",
                    "post-commit presentation failure evidence must identify "
                    "the host, instance, record, and replay path",
                )
                if (
                    case_id
                    == "presentation_capacity_failure_after_commit"
                ):
                    self.require(
                        list(diagnostic) == EXACT_FAILURE_ENVELOPE_FIELDS
                        and diagnostic.get("schema_version") == 1
                        and diagnostic.get("operation") == "post"
                        and diagnostic.get("observation_status")
                        == "complete"
                        and diagnostic.get("failure_reason")
                        == "presentation_capacity_exceeded"
                        and diagnostic.get("observation_reason") is None
                        and diagnostic.get("persistence_outcome")
                        == "committed"
                        and diagnostic.get(
                            "committed_result_replayable"
                        )
                        is True,
                        path,
                        f"{context}.oracle.failure_envelope",
                        "presentation capacity must retain its distinct "
                        "post-commit failure reason and replayable bounded "
                        "envelope",
                    )
                self.require(
                    retained_replay
                    == {
                        "report_mode": "none",
                        "discovery_attempted": False,
                        "store_mutated": False,
                        "human_render_attempted": False,
                        "full_machine_result_returned": True,
                    },
                    path,
                    f"{context}.oracle.retained_replay",
                    "retained render recovery must return the machine result "
                    "without rediscovery, writing, or repeating the failing "
                    "renderer",
                )
            if (
                case.get("id")
                == "store_byte_cap_prunes_oldest_full_record"
            ):
                prior_components = case.get("prior_state", {}).get(
                    "exact_serialized_component_bytes", {}
                )
                transaction = case.get("transaction", {})
                journal_bytes = prior_components.get("journal", {})
                pre_prune = (
                    prior_components.get("envelope", 0)
                    + prior_components.get("latest_complete_post", 0)
                    + sum(journal_bytes.values())
                    + prior_components.get("recently_pruned_record_ids", 0)
                    + transaction.get("append_record", {}).get(
                        "exact_serialized_bytes", 0
                    )
                )
                post_prune = (
                    pre_prune
                    - journal_bytes.get("record-oldest", 0)
                    + transaction.get(
                        "replacement_recent_id_exact_serialized_bytes", 0
                    )
                )
                self.require(
                    outcome == "committed"
                    and transaction.get("fixture_layer")
                    == "internal_transition_unit"
                    and transaction.get("public_input_validation_applied")
                    is False
                    and transaction.get("public_state_max_bytes_minimum")
                    == 1048576
                    and transaction.get("state_max_bytes") == 1000
                    and pre_prune
                    == oracle.get("exact_pre_prune_candidate_bytes")
                    == 1200
                    and post_prune
                    == oracle.get("exact_post_prune_candidate_bytes")
                    == 840
                    and oracle.get("pruned_record_ids")
                    == ["record-oldest"]
                    and oracle.get("retained_record_ids")
                    == ["record-newer", "record-newest"]
                    and oracle.get("required_evidence_truncated") is False
                    and oracle.get("byte_limit_satisfied") is True
                    and post_prune <= transaction.get("state_max_bytes"),
                    path,
                    f"{context}.oracle",
                    "exact canonical byte pressure must prune the oldest full "
                    "record and retain required evidence before replacement",
                )
            if case.get("id") == "required_state_exceeds_byte_cap_fails":
                prior_state = case.get("prior_state", {})
                transaction = case.get("transaction", {})
                required_bytes = (
                    prior_state.get("exact_serialized_bytes", 0)
                    + transaction.get("append_required_record", {}).get(
                        "exact_serialized_bytes", 0
                    )
                )
                self.require(
                    outcome == "failed"
                    and transaction.get("fixture_layer")
                    == "internal_transition_unit"
                    and transaction.get("public_input_validation_applied")
                    is False
                    and transaction.get("public_state_max_bytes_minimum")
                    == 1048576
                    and transaction.get("state_max_bytes") == 1000
                    and required_bytes
                    == oracle.get("exact_required_candidate_bytes")
                    == 1100
                    and oracle.get("failure_reason")
                    == "state_size_limit_exceeded"
                    and oracle.get("prunable_record_ids") == []
                    and oracle.get("prior_store_unchanged") is True
                    and oracle.get("store_mutated") is False
                    and oracle.get("revision_after")
                    == prior_state.get("revision")
                    and oracle.get("diagnostic_rendered_before_failure") is True
                    and oracle.get("full_report_rendered") is False
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present") is True
                    and oracle.get("task_failed") is True,
                    path,
                    f"{context}.oracle",
                    "required evidence that exceeds the byte cap must fail "
                    "before replacing the authoritative store",
                )
            if case.get("id") == "canonical_complete_store_known_answer":
                store = case.get("input", {}).get("canonical_store")

                def require_exact_model_keys(
                    value: Any, model_name: str, item_context: str
                ) -> bool:
                    expected = EXACT_CORE_MODEL_FIELDS.get(model_name, [])
                    return self.require(
                        isinstance(value, dict)
                        and set(value) == set(expected)
                        and len(value) == len(expected),
                        path,
                        item_context,
                        f"must contain exactly the closed {model_name} keys",
                    )

                def validate_strict_container(
                    value: Any, item_context: str
                ) -> None:
                    if not require_exact_model_keys(
                        value, "container_observation", item_context
                    ):
                        return
                    name = value.get("name")
                    reference = value.get("full_image_reference")
                    self.require(
                        isinstance(name, str)
                        and CONTAINER_NAME_RE.fullmatch(name) is not None
                        and len(name.encode("ascii")) <= 255,
                        path,
                        f"{item_context}.name",
                        "must satisfy the exact 255-byte container-name bound",
                    )
                    self.require(
                        isinstance(reference, str)
                        and 1 <= len(reference.encode("ascii")) <= 4096
                        and PRINTABLE_ASCII_RE.fullmatch(reference) is not None
                        and not any(
                            character.isspace() for character in reference
                        ),
                        path,
                        f"{item_context}.full_image_reference",
                        "must satisfy the exact safe image-reference bound",
                    )

                def validate_strict_observation(
                    value: Any, item_context: str
                ) -> None:
                    if not require_exact_model_keys(
                        value, "observation", item_context
                    ):
                        return
                    self.validate_observation(path, item_context, value)
                    require_exact_model_keys(
                        value.get("scope"), "scope", f"{item_context}.scope"
                    )
                    self.require(
                        value.get("discovery_backend") == "docker_cli_v1",
                        path,
                        f"{item_context}.discovery_backend",
                        "canonical release state must use docker_cli_v1",
                    )
                    containers = value.get("containers")
                    if isinstance(containers, dict):
                        for name, container in containers.items():
                            validate_strict_container(
                                container,
                                f"{item_context}.containers.{name}",
                            )

                def validate_strict_delta(
                    value: Any, item_context: str
                ) -> None:
                    if not require_exact_model_keys(
                        value, "delta_result", item_context
                    ):
                        return
                    from_values = [
                        value.get("from_observation_id"),
                        value.get("from_observed_at"),
                        value.get("from_scope"),
                    ]
                    to_values = [
                        value.get("to_observation_id"),
                        value.get("to_observed_at"),
                        value.get("to_scope"),
                    ]
                    self.require(
                        all(item is None for item in from_values)
                        or all(item is not None for item in from_values),
                        path,
                        item_context,
                        "from endpoint ID, time, and scope must be null together",
                    )
                    self.require(
                        all(item is None for item in to_values)
                        or all(item is not None for item in to_values),
                        path,
                        item_context,
                        "to endpoint ID, time, and scope must be null together",
                    )
                    if value.get("from_scope") is not None:
                        require_exact_model_keys(
                            value.get("from_scope"),
                            "scope",
                            f"{item_context}.from_scope",
                        )
                    if value.get("to_scope") is not None:
                        require_exact_model_keys(
                            value.get("to_scope"),
                            "scope",
                            f"{item_context}.to_scope",
                        )
                    changes = value.get("changes")
                    self.require(
                        isinstance(changes, list)
                        and [
                            change.get("container_name")
                            for change in changes
                            if isinstance(change, dict)
                        ]
                        == sorted(
                            change.get("container_name")
                            for change in changes
                            if isinstance(change, dict)
                        ),
                        path,
                        f"{item_context}.changes",
                        "must be sorted by container name",
                    )
                    if isinstance(changes, list):
                        for change_index, change in enumerate(changes):
                            change_context = (
                                f"{item_context}.changes[{change_index}]"
                            )
                            if not require_exact_model_keys(
                                change, "container_delta", change_context
                            ):
                                continue
                            for endpoint in ("before", "after"):
                                endpoint_value = change.get(endpoint)
                                if endpoint_value is not None:
                                    validate_strict_container(
                                        endpoint_value,
                                        f"{change_context}.{endpoint}",
                                    )

                if require_exact_model_keys(
                    store, "state_store", f"{context}.input.canonical_store"
                ):
                    self.require(
                        store.get("schema_version") == 1
                        and store.get("comparison_schema_version") == 1
                        and store.get("revision") == 2
                        and store.get("instance_id") == "fixture-mdad",
                        path,
                        f"{context}.input.canonical_store",
                        "known-answer store envelope must remain frozen",
                    )
                    validate_strict_observation(
                        store.get("latest_complete_post"),
                        f"{context}.input.canonical_store.latest_complete_post",
                    )
                    journal = store.get("journal")
                    self.require(
                        isinstance(journal, list) and len(journal) == 1,
                        path,
                        f"{context}.input.canonical_store.journal",
                        "known-answer store must contain one full record",
                    )
                    if isinstance(journal, list) and len(journal) == 1:
                        record = journal[0]
                        record_context = (
                            f"{context}.input.canonical_store.journal[0]"
                        )
                        if require_exact_model_keys(
                            record, "run_record", record_context
                        ):
                            self.require(
                                record.get("pre_signature")
                                == "sha256:f09b6fbb422b755acd3aa1eb22814ed702aa91be62052df1bd9ca20bc8fb4f70"
                                and record.get("post_signature")
                                == "sha256:3194b71fe0545c49e0cef4537c0b8edcd1adb7327c2378f1883d9ea980b74557",
                                path,
                                record_context,
                                "known-answer phase signatures must remain frozen",
                            )
                            validate_strict_observation(
                                record.get("pre"), f"{record_context}.pre"
                            )
                            validate_strict_observation(
                                record.get("post"), f"{record_context}.post"
                            )
                            validate_strict_delta(
                                record.get("between_observation_delta"),
                                f"{record_context}.between_observation_delta",
                            )
                            validate_strict_delta(
                                record.get("run_window_delta"),
                                f"{record_context}.run_window_delta",
                            )
                            for phase in ("pre", "post"):
                                require_exact_model_keys(
                                    record.get(f"{phase}_baseline"),
                                    "baseline_result",
                                    f"{record_context}.{phase}_baseline",
                                )

                canonical_bytes = (
                    json.dumps(
                        store,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    + "\n"
                    if isinstance(store, dict)
                    else ""
                ).encode("utf-8")
                digest = "sha256:" + hashlib.sha256(
                    canonical_bytes
                ).hexdigest()
                try:
                    reparsed = json.loads(canonical_bytes.decode("utf-8"))
                    reencoded = (
                        json.dumps(
                            reparsed,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode("utf-8")
                except (UnicodeDecodeError, ValueError, TypeError):
                    reparsed = None
                    reencoded = b""
                self.require(
                    outcome == "not_attempted"
                    and oracle.get("canonical_encoding")
                    == "compact_sorted_utf8_json_plus_lf"
                    and len(canonical_bytes)
                    == oracle.get("exact_serialized_bytes")
                    == 4889
                    and digest
                    == oracle.get("exact_sha256")
                    == "sha256:e3c10052991d76fe4c3f5b37be15c63e8e28830cc5892cc04b16ea307c3bd6fc"
                    and reparsed == store
                    and reencoded == canonical_bytes
                    and oracle.get("schema_validated_before_hash") is True
                    and oracle.get("reparse_deep_equal") is True
                    and oracle.get("byte_for_byte_reencode_equal") is True,
                    path,
                    f"{context}.oracle",
                    "complete canonical store bytes and digest must match the "
                    "independent known answer",
                )
            if case.get("id") == "invalid_existing_store_fails_closed":
                variants = case.get("input", {}).get("variants")
                variant_by_id = (
                    {
                        variant.get("id"): variant
                        for variant in variants
                        if isinstance(variant, dict)
                    }
                    if isinstance(variants, list)
                    else {}
                )
                expected_ids = {
                    "malformed_json",
                    "noncanonical_whitespace",
                    "unknown_store_schema_version",
                    "unknown_comparison_schema_version",
                    "unknown_top_level_field",
                    "open_record_with_committed_post",
                    "absent_pre_with_retained_pre_signature",
                    "status_inconsistent_with_complete_phases",
                    "phase_signatures_stale_after_correlation_change",
                    "post_signature_stale_after_scope_change",
                    "between_delta_to_id_mismatch",
                    "between_delta_to_time_mismatch",
                    "between_delta_to_scope_mismatch",
                    "run_window_from_id_mismatch",
                    "run_window_from_time_mismatch",
                    "run_window_from_scope_mismatch",
                    "run_window_to_id_mismatch",
                    "run_window_to_time_mismatch",
                    "run_window_to_scope_mismatch",
                    "complete_post_baseline_after_mismatch",
                    "pre_baseline_advanced",
                    "pre_baseline_endpoints_mismatch",
                    "post_baseline_before_mismatch",
                    "record_created_at_not_pre_observed_at",
                    "record_updated_at_not_post_observed_at",
                    "expected_post_revision_exceeds_store_revision",
                    "present_pre_without_signature",
                    "present_post_without_signature",
                    "release_store_contains_synthetic_observation",
                }
                canonical_state_fields = set(
                    EXACT_CORE_MODEL_FIELDS["state_store"]
                )

                def compact_bytes(value: Any) -> bytes:
                    return (
                        json.dumps(
                            value,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode("utf-8")

                malformed = variant_by_id.get("malformed_json", {})
                try:
                    json.loads(malformed.get("source_bytes", ""))
                    malformed_rejected = False
                except (TypeError, ValueError):
                    malformed_rejected = True
                whitespace = variant_by_id.get(
                    "noncanonical_whitespace", {}
                )
                whitespace_value = whitespace.get("canonical_value")
                pretty_bytes = (
                    json.dumps(
                        whitespace_value,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
                whitespace_rejected = (
                    whitespace.get("source_encoding")
                    == "pretty_printed_json_plus_lf"
                    and json.loads(pretty_bytes.decode("utf-8"))
                    == whitespace_value
                    and pretty_bytes != compact_bytes(whitespace_value)
                )
                schema_variant = variant_by_id.get(
                    "unknown_store_schema_version", {}
                )
                comparison_variant = variant_by_id.get(
                    "unknown_comparison_schema_version", {}
                )
                field_variant = variant_by_id.get(
                    "unknown_top_level_field", {}
                )
                mutated_schema = json.loads(
                    json.dumps(schema_variant.get("canonical_value"))
                )
                mutated_comparison = json.loads(
                    json.dumps(comparison_variant.get("canonical_value"))
                )
                mutated_field = json.loads(
                    json.dumps(field_variant.get("canonical_value"))
                )
                if isinstance(mutated_schema, dict):
                    mutated_schema["schema_version"] = 2
                if isinstance(mutated_comparison, dict):
                    mutated_comparison["comparison_schema_version"] = 2
                if isinstance(mutated_field, dict):
                    mutated_field["unexpected"] = "rejected"
                def variant_mutations(variant: Any) -> Any:
                    if not isinstance(variant, dict):
                        return None
                    mutation = variant.get("mutation")
                    mutations = variant.get("mutations")
                    if isinstance(mutation, dict) and mutations is None:
                        return [mutation]
                    if (
                        mutation is None
                        and isinstance(mutations, list)
                        and mutations
                        and all(
                            isinstance(item, dict) for item in mutations
                        )
                    ):
                        return mutations
                    return None

                def apply_dotted_mutations(variant: Any) -> Any:
                    if not isinstance(variant, dict):
                        return None
                    value = json.loads(
                        json.dumps(variant.get("canonical_value"))
                    )
                    mutations = variant_mutations(variant)
                    if not isinstance(mutations, list):
                        return None
                    try:
                        for mutation in mutations:
                            parts = str(
                                mutation.get("path", "")
                            ).split(".")
                            cursor = value
                            for part in parts[:-1]:
                                cursor = (
                                    cursor[int(part)]
                                    if isinstance(cursor, list)
                                    else cursor[part]
                                )
                            final = parts[-1]
                            if isinstance(cursor, list):
                                cursor[int(final)] = mutation.get("value")
                            else:
                                cursor[final] = mutation.get("value")
                    except (KeyError, IndexError, TypeError, ValueError):
                        return None
                    return value

                alternate_scope = {
                    "patterns": ["other-*"],
                    "identity": self.scope_identity(["other-*"]),
                    "comparison_schema_version": 1,
                }
                expected_single_cross_field_mutations = {
                    "open_record_with_committed_post": {
                        "path": "journal.0.status",
                        "value": "open",
                    },
                    "absent_pre_with_retained_pre_signature": {
                        "path": "journal.0.pre",
                        "value": None,
                    },
                    "status_inconsistent_with_complete_phases": {
                        "path": "journal.0.status",
                        "value": "incomplete_post",
                    },
                    "phase_signatures_stale_after_correlation_change": {
                        "path": "journal.0.correlation_id",
                        "value": "deploy-other",
                    },
                    "between_delta_to_id_mismatch": {
                        "path": (
                            "journal.0.between_observation_delta."
                            "to_observation_id"
                        ),
                        "value": "obs-wrong-pre",
                    },
                    "between_delta_to_time_mismatch": {
                        "path": (
                            "journal.0.between_observation_delta."
                            "to_observed_at"
                        ),
                        "value": "2026-07-30T12:00:09Z",
                    },
                    "between_delta_to_scope_mismatch": {
                        "path": (
                            "journal.0.between_observation_delta.to_scope"
                        ),
                        "value": alternate_scope,
                    },
                    "run_window_from_id_mismatch": {
                        "path": (
                            "journal.0.run_window_delta."
                            "from_observation_id"
                        ),
                        "value": "obs-wrong-pre",
                    },
                    "run_window_from_time_mismatch": {
                        "path": (
                            "journal.0.run_window_delta.from_observed_at"
                        ),
                        "value": "2026-07-30T12:00:09Z",
                    },
                    "run_window_from_scope_mismatch": {
                        "path": "journal.0.run_window_delta.from_scope",
                        "value": alternate_scope,
                    },
                    "run_window_to_id_mismatch": {
                        "path": (
                            "journal.0.run_window_delta.to_observation_id"
                        ),
                        "value": "obs-wrong-post",
                    },
                    "run_window_to_time_mismatch": {
                        "path": (
                            "journal.0.run_window_delta.to_observed_at"
                        ),
                        "value": "2026-07-30T12:00:09Z",
                    },
                    "run_window_to_scope_mismatch": {
                        "path": "journal.0.run_window_delta.to_scope",
                        "value": alternate_scope,
                    },
                    "complete_post_baseline_after_mismatch": {
                        "path": "journal.0.post_baseline.after",
                        "value": "obs-wrong-post",
                    },
                    "pre_baseline_advanced": {
                        "path": "journal.0.pre_baseline.advanced",
                        "value": True,
                    },
                    "pre_baseline_endpoints_mismatch": {
                        "path": "journal.0.pre_baseline.after",
                        "value": "obs-not-before",
                    },
                    "post_baseline_before_mismatch": {
                        "path": "journal.0.post_baseline.before",
                        "value": "obs-not-pre-window-baseline",
                    },
                    "record_created_at_not_pre_observed_at": {
                        "path": "journal.0.created_at",
                        "value": "2026-07-30T11:59:59Z",
                    },
                    "record_updated_at_not_post_observed_at": {
                        "path": "journal.0.updated_at",
                        "value": "2026-07-30T12:00:09Z",
                    },
                    "expected_post_revision_exceeds_store_revision": {
                        "path": "journal.0.expected_post_revision",
                        "value": 3,
                    },
                    "present_pre_without_signature": {
                        "path": "journal.0.pre_signature",
                        "value": None,
                    },
                    "present_post_without_signature": {
                        "path": "journal.0.post_signature",
                        "value": None,
                    },
                    "release_store_contains_synthetic_observation": {
                        "path": "journal.0.pre.discovery_backend",
                        "value": "synthetic",
                    },
                }
                expected_multi_cross_field_mutations = {
                    "post_signature_stale_after_scope_change": [
                        {
                            "path": "journal.0.post.scope",
                            "value": alternate_scope,
                        },
                        {
                            "path": "latest_complete_post.scope",
                            "value": alternate_scope,
                        },
                        {
                            "path": (
                                "journal.0.run_window_delta.comparability"
                            ),
                            "value": "incompatible_scope",
                        },
                        {
                            "path": (
                                "journal.0.run_window_delta.to_scope"
                            ),
                            "value": alternate_scope,
                        },
                        {
                            "path": "journal.0.run_window_delta.changes",
                            "value": [],
                        },
                        {
                            "path": "journal.0.status",
                            "value": "scope_mismatch",
                        },
                    ]
                }
                expected_cross_field_mutations = {
                    case_id: [mutation]
                    for case_id, mutation in (
                        expected_single_cross_field_mutations.items()
                    )
                }
                expected_cross_field_mutations.update(
                    expected_multi_cross_field_mutations
                )

                def phase_signature_for(
                    store_value: Any,
                    record_value: Any,
                    operation: str,
                ) -> Any:
                    if not isinstance(store_value, dict) or not isinstance(
                        record_value, dict
                    ):
                        return None
                    observation = record_value.get(operation)
                    if not isinstance(observation, dict):
                        return None
                    scope = observation.get("scope")
                    patterns = (
                        scope.get("patterns")
                        if isinstance(scope, dict)
                        else None
                    )
                    if not isinstance(patterns, list):
                        return None
                    signature_object = {
                        "comparison_schema_version": store_value.get(
                            "comparison_schema_version"
                        ),
                        "correlation_id": record_value.get(
                            "correlation_id"
                        ),
                        "instance_id": store_value.get("instance_id"),
                        "operation": operation,
                        "scope": patterns,
                        "signature_schema_version": 1,
                    }
                    canonical = json.dumps(
                        signature_object,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                    return "sha256:" + hashlib.sha256(canonical).hexdigest()

                def endpoint_matches_observation(
                    delta: Any, prefix: str, observation: Any
                ) -> bool:
                    if not isinstance(delta, dict):
                        return False
                    actual = (
                        delta.get(f"{prefix}_observation_id"),
                        delta.get(f"{prefix}_observed_at"),
                        delta.get(f"{prefix}_scope"),
                    )
                    if observation is None:
                        return actual == (None, None, None)
                    if not isinstance(observation, dict):
                        return False
                    return actual == (
                        observation.get("observation_id"),
                        observation.get("observed_at"),
                        observation.get("scope"),
                    )

                def release_observation_valid(observation: Any) -> bool:
                    return (
                        isinstance(observation, dict)
                        and observation.get("discovery_backend")
                        == "docker_cli_v1"
                    )

                def expected_record_status(
                    pre: Any, post: Any
                ) -> Any:
                    if post is None:
                        return "open"
                    if not isinstance(post, dict):
                        return None
                    post_complete = post.get("status") == "complete"
                    if not isinstance(pre, dict) or (
                        pre.get("status") != "complete"
                    ):
                        return (
                            "incomplete_pre"
                            if post_complete
                            else "incomplete_both"
                        )
                    if not post_complete:
                        return "incomplete_post"
                    return (
                        "complete"
                        if pre.get("scope") == post.get("scope")
                        else "scope_mismatch"
                    )

                def store_cross_fields_valid(store_value: Any) -> bool:
                    if not isinstance(store_value, dict):
                        return False
                    revision = store_value.get("revision")
                    if (
                        not self.is_int(revision)
                        or revision < 0
                        or store_value.get("schema_version") != 1
                        or store_value.get("comparison_schema_version") != 1
                    ):
                        return False
                    latest = store_value.get("latest_complete_post")
                    if latest is not None and (
                        not release_observation_valid(latest)
                        or latest.get("status") != "complete"
                    ):
                        return False
                    journal = store_value.get("journal")
                    if not isinstance(journal, list):
                        return False
                    for record in journal:
                        if not isinstance(record, dict):
                            return False
                        pre = record.get("pre")
                        post = record.get("post")
                        between = record.get(
                            "between_observation_delta"
                        )
                        run_window = record.get("run_window_delta")
                        pre_baseline = record.get("pre_baseline")
                        post_baseline = record.get("post_baseline")
                        expected_revision = record.get(
                            "expected_post_revision"
                        )

                        if pre is None:
                            if any(
                                value is not None
                                for value in (
                                    record.get("pre_signature"),
                                    between,
                                    pre_baseline,
                                    expected_revision,
                                )
                            ):
                                return False
                        else:
                            if (
                                not release_observation_valid(pre)
                                or record.get("created_at")
                                != pre.get("observed_at")
                                or record.get("pre_signature")
                                != phase_signature_for(
                                    store_value, record, "pre"
                                )
                                or not isinstance(between, dict)
                                or not endpoint_matches_observation(
                                    between, "to", pre
                                )
                                or between.get(
                                    "comparison_schema_version"
                                )
                                != store_value.get(
                                    "comparison_schema_version"
                                )
                                or not isinstance(pre_baseline, dict)
                                or pre_baseline.get("advanced") is not False
                                or pre_baseline.get("before")
                                != pre_baseline.get("after")
                                or not self.is_int(expected_revision)
                                or expected_revision <= 0
                                or expected_revision > revision
                            ):
                                return False
                            pre_baseline_id = pre_baseline.get("before")
                            if (
                                between.get("from_observation_id")
                                != pre_baseline_id
                            ):
                                return False
                            if pre_baseline_id is None and not (
                                endpoint_matches_observation(
                                    between, "from", None
                                )
                            ):
                                return False

                        if post is None:
                            if any(
                                value is not None
                                for value in (
                                    record.get("post_signature"),
                                    run_window,
                                    post_baseline,
                                )
                            ):
                                return False
                            if (
                                not isinstance(pre, dict)
                                or record.get("updated_at")
                                != pre.get("observed_at")
                            ):
                                return False
                        else:
                            if (
                                not release_observation_valid(post)
                                or record.get("updated_at")
                                != post.get("observed_at")
                                or record.get("post_signature")
                                != phase_signature_for(
                                    store_value, record, "post"
                                )
                                or not isinstance(post_baseline, dict)
                            ):
                                return False
                            if pre is None:
                                if (
                                    run_window is not None
                                    or record.get("created_at")
                                    != post.get("observed_at")
                                    or record.get("updated_at")
                                    != post.get("observed_at")
                                ):
                                    return False
                            elif (
                                not isinstance(run_window, dict)
                                or not endpoint_matches_observation(
                                    run_window, "from", pre
                                )
                                or not endpoint_matches_observation(
                                    run_window, "to", post
                                )
                                or run_window.get(
                                    "comparison_schema_version"
                                )
                                != store_value.get(
                                    "comparison_schema_version"
                                )
                                or post_baseline.get("before")
                                != pre_baseline.get("before")
                            ):
                                return False
                            if post.get("status") == "complete":
                                if (
                                    post_baseline.get("advanced") is not True
                                    or post_baseline.get("after")
                                    != post.get("observation_id")
                                ):
                                    return False
                            elif (
                                post_baseline.get("advanced") is not False
                                or post_baseline.get("after")
                                != post_baseline.get("before")
                            ):
                                return False

                        if record.get("status") != expected_record_status(
                            pre, post
                        ):
                            return False
                    return True

                open_variant = variant_by_id.get(
                    "open_record_with_committed_post", {}
                )
                absent_pre_variant = variant_by_id.get(
                    "absent_pre_with_retained_pre_signature", {}
                )
                status_variant = variant_by_id.get(
                    "status_inconsistent_with_complete_phases", {}
                )
                mutated_open = apply_dotted_mutations(open_variant)
                mutated_absent_pre = apply_dotted_mutations(
                    absent_pre_variant
                )
                mutated_status = apply_dotted_mutations(status_variant)
                open_record = (
                    mutated_open.get("journal", [{}])[0]
                    if isinstance(mutated_open, dict)
                    else {}
                )
                absent_pre_record = (
                    mutated_absent_pre.get("journal", [{}])[0]
                    if isinstance(mutated_absent_pre, dict)
                    else {}
                )
                status_record = (
                    mutated_status.get("journal", [{}])[0]
                    if isinstance(mutated_status, dict)
                    else {}
                )
                cross_field_variant_ids = set(
                    expected_cross_field_mutations
                )
                canonical_cross_state = open_variant.get("canonical_value")
                mutated_cross_states = {
                    variant_id: apply_dotted_mutations(
                        variant_by_id.get(variant_id)
                    )
                    for variant_id in cross_field_variant_ids
                }
                cross_mutation_matrix_exact = (
                    cross_field_variant_ids
                    == expected_ids
                    - {
                        "malformed_json",
                        "noncanonical_whitespace",
                        "unknown_store_schema_version",
                        "unknown_comparison_schema_version",
                        "unknown_top_level_field",
                    }
                    and all(
                        variant_mutations(
                            variant_by_id.get(variant_id)
                        )
                        == expected_cross_field_mutations[variant_id]
                        for variant_id in cross_field_variant_ids
                    )
                    and all(
                        variant_by_id.get(variant_id, {}).get(
                            "canonical_value"
                        )
                        == canonical_cross_state
                        for variant_id in cross_field_variant_ids
                    )
                )
                scope_signature_state = mutated_cross_states.get(
                    "post_signature_stale_after_scope_change"
                )
                scope_signature_record = (
                    scope_signature_state.get("journal", [{}])[0]
                    if isinstance(scope_signature_state, dict)
                    else {}
                )
                scope_signature_post = scope_signature_record.get("post")
                scope_signature_run = scope_signature_record.get(
                    "run_window_delta"
                )
                scope_signature_companions_consistent = (
                    isinstance(scope_signature_post, dict)
                    and isinstance(scope_signature_run, dict)
                    and scope_signature_post.get("scope")
                    == alternate_scope
                    and scope_signature_state.get(
                        "latest_complete_post", {}
                    ).get("scope")
                    == alternate_scope
                    and endpoint_matches_observation(
                        scope_signature_run,
                        "from",
                        scope_signature_record.get("pre"),
                    )
                    and endpoint_matches_observation(
                        scope_signature_run,
                        "to",
                        scope_signature_post,
                    )
                    and scope_signature_run.get("comparability")
                    == "incompatible_scope"
                    and scope_signature_run.get("changes") == []
                    and scope_signature_record.get("status")
                    == expected_record_status(
                        scope_signature_record.get("pre"),
                        scope_signature_post,
                    )
                    == "scope_mismatch"
                    and scope_signature_record.get("post_signature")
                    != phase_signature_for(
                        scope_signature_state,
                        scope_signature_record,
                        "post",
                    )
                )
                cross_field_contracts = (
                    open_variant.get("mutation")
                    == {"path": "journal.0.status", "value": "open"}
                    and absent_pre_variant.get("mutation")
                    == {"path": "journal.0.pre", "value": None}
                    and status_variant.get("mutation")
                    == {
                        "path": "journal.0.status",
                        "value": "incomplete_post",
                    }
                    and open_record.get("status") == "open"
                    and isinstance(open_record.get("post"), dict)
                    and open_record.get("post_signature") is not None
                    and absent_pre_record.get("pre") is None
                    and absent_pre_record.get("pre_signature") is not None
                    and absent_pre_record.get(
                        "between_observation_delta"
                    )
                    is not None
                    and status_record.get("status") == "incomplete_post"
                    and status_record.get("pre", {}).get("status")
                    == "complete"
                    and status_record.get("post", {}).get("status")
                    == "complete"
                    and status_record.get("pre", {}).get("scope")
                    == status_record.get("post", {}).get("scope")
                    and cross_mutation_matrix_exact
                    and store_cross_fields_valid(canonical_cross_state)
                    and all(
                        not store_cross_fields_valid(mutated_state)
                        for mutated_state in mutated_cross_states.values()
                    )
                    and scope_signature_companions_consistent
                    and oracle.get(
                        "canonical_store_cross_fields_valid_before_mutation"
                    )
                    is True
                    and oracle.get(
                        "mutated_cross_field_variants_rejected"
                    )
                    is True
                )
                mutation_contracts = (
                    schema_variant.get("mutation")
                    == {"path": "schema_version", "value": 2}
                    and comparison_variant.get("mutation")
                    == {
                        "path": "comparison_schema_version",
                        "value": 2,
                    }
                    and field_variant.get("mutation")
                    == {"path": "unexpected", "value": "rejected"}
                    and isinstance(schema_variant.get("canonical_value"), dict)
                    and schema_variant["canonical_value"].get(
                        "schema_version"
                    )
                    == 1
                    and isinstance(
                        comparison_variant.get("canonical_value"), dict
                    )
                    and comparison_variant["canonical_value"].get(
                        "comparison_schema_version"
                    )
                    == 1
                    and isinstance(field_variant.get("canonical_value"), dict)
                    and set(field_variant["canonical_value"])
                    == canonical_state_fields
                    and mutated_schema.get("schema_version") == 2
                    and mutated_schema.get("schema_version") != 1
                    and mutated_comparison.get(
                        "comparison_schema_version"
                    )
                    == 2
                    and mutated_comparison.get(
                        "comparison_schema_version"
                    )
                    != 1
                    and set(mutated_field)
                    == canonical_state_fields | {"unexpected"}
                    and set(mutated_field) != canonical_state_fields
                    and cross_field_contracts
                )
                self.require(
                    set(variant_by_id) == expected_ids
                    and len(variants)
                    == len(variant_by_id)
                    == oracle.get("variant_count")
                    == 29
                    and malformed_rejected
                    and whitespace_rejected
                    and mutation_contracts
                    and oracle.get("failure_reason_for_each")
                    == "corrupt_state"
                    and oracle.get("task_failed_for_each") is True
                    and oracle.get("discovery_attempted_for_each") is False
                    and oracle.get("state_rewritten_for_each") is False
                    and oracle.get("automatic_upgrade_for_each") is False
                    and oracle.get("exception_text_returned_for_each") is False
                    and oracle.get(
                        "diagnostic_rendered_before_failure_for_each"
                    )
                    is True
                    and oracle.get("full_report_rendered_for_each") is False
                    and oracle.get(
                        "full_machine_result_in_failed_callback_for_each"
                    )
                    is False
                    and oracle.get(
                        "compact_failure_envelope_present_for_each"
                    )
                    is True
                    and oracle.get("failure_envelope_max_bytes") == 1024,
                    path,
                    f"{context}.oracle",
                    "malformed, noncanonical, unknown-version, unknown-key, "
                    "and cross-field-inconsistent stores must fail closed "
                    "before discovery without repair",
                )
            if case.get("id") == "state_lock_timeout_is_bounded":
                input_data = case.get("input", {})
                timeout = input_data.get("lock_timeout_seconds")
                probe = input_data.get("monotonic_probe_seconds")
                self.require(
                    input_data.get("operation") == "pre"
                    and timeout == 5
                    and probe == [0, timeout]
                    and input_data.get("lock_acquired") is False
                    and oracle.get("persistence_outcome") == "failed"
                    and oracle.get("failure_reason") == "state_lock_timeout"
                    and oracle.get("elapsed_seconds_max") == timeout
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("state_mutated") is False
                    and oracle.get("revision_after")
                    == input_data.get("prior_revision")
                    and oracle.get("diagnostic_rendered_before_failure")
                    is True
                    and oracle.get("full_report_rendered") is False
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present") is True
                    and oracle.get("failure_envelope_max_bytes") == 1024
                    and oracle.get("task_failed") is True,
                    path,
                    f"{context}.oracle",
                    "lock contention must stop at the fixed five-second "
                    "deadline before discovery or mutation",
                )
            if case.get("id") == "oversized_existing_store_fails_before_parse":
                input_data = case.get("input", {})
                limit = input_data.get("state_max_bytes")
                existing = input_data.get("existing_state_bytes")
                self.require(
                    limit == 16777216
                    and existing == limit + 1
                    and input_data.get(
                        "existing_state_is_regular_secure_file"
                    )
                    is True
                    and oracle.get("persistence_outcome") == "failed"
                    and oracle.get("failure_reason")
                    == "state_size_limit_exceeded"
                    and oracle.get("json_parse_attempted") is False
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("state_mutated") is False
                    and oracle.get("diagnostic_rendered_before_failure")
                    is True
                    and oracle.get("full_report_rendered") is False
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present") is True
                    and oracle.get("failure_envelope_max_bytes") == 1024
                    and oracle.get("task_failed") is True,
                    path,
                    f"{context}.oracle",
                    "an oversized existing store must be rejected from file "
                    "metadata before JSON parsing, discovery, or mutation",
                )
            if (
                case.get("id")
                == "canonical_byte_pressure_prunes_real_serialization"
            ):
                input_data = case.get("input", {})
                prior = input_data.get("prior_store")
                appended = input_data.get("append_record")
                candidate = (
                    json.loads(json.dumps(prior))
                    if isinstance(prior, dict)
                    else {}
                )
                candidate["revision"] = input_data.get(
                    "proposed_revision"
                )
                candidate.setdefault("journal", []).append(appended)

                def encode_store(value: Any) -> bytes:
                    return (
                        json.dumps(
                            value,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode("utf-8")

                pre_bytes = encode_store(candidate)
                pruned_id = candidate["journal"][0].get("record_id")
                candidate["journal"] = candidate["journal"][1:]
                candidate.setdefault(
                    "recently_pruned_record_ids", []
                ).append(pruned_id)
                post_bytes = encode_store(candidate)
                limit = input_data.get("state_max_bytes")
                self.require(
                    input_data.get("fixture_layer")
                    == "internal_transition_unit"
                    and input_data.get("public_input_validation_applied")
                    is False
                    and input_data.get(
                        "public_state_max_bytes_minimum"
                    )
                    == 1048576
                    and limit == 5000
                    and limit
                    < input_data.get("public_state_max_bytes_minimum")
                    and isinstance(prior, dict)
                    and prior.get("revision") == 2
                    and isinstance(appended, dict)
                    and set(appended)
                    == set(EXACT_CORE_MODEL_FIELDS["run_record"])
                    and input_data.get("proposed_revision") == 3
                    and len(pre_bytes)
                    == oracle.get("exact_pre_prune_candidate_bytes")
                    == 7642
                    and "sha256:"
                    + hashlib.sha256(pre_bytes).hexdigest()
                    == oracle.get("exact_pre_prune_sha256")
                    and len(post_bytes)
                    == oracle.get("exact_post_prune_candidate_bytes")
                    == 3687
                    and "sha256:"
                    + hashlib.sha256(post_bytes).hexdigest()
                    == oracle.get("exact_post_prune_sha256")
                    and len(pre_bytes) > limit >= len(post_bytes)
                    and oracle.get("pruned_record_ids") == [pruned_id]
                    and oracle.get("retained_record_ids")
                    == [appended.get("record_id")]
                    and oracle.get("recently_pruned_record_ids_after")
                    == [pruned_id]
                    and oracle.get("revision_after") == 3
                    and oracle.get(
                        "canonical_serialization_computed_by_validator"
                    )
                    is True
                    and oracle.get("required_evidence_truncated") is False
                    and oracle.get("byte_limit_satisfied") is True,
                    path,
                    f"{context}.oracle",
                    "byte-pressure pruning must be computed from full compact "
                    "canonical serialization, not authored component totals",
                )

    def validate_normalization_cases(
        self, path: Path, data: dict[str, Any]
    ) -> None:
        for index, case in enumerate(data.get("scope_cases", [])):
            case_id = case.get("id")
            context = f"scope_cases[{index}]"
            oracle = case.get("oracle", {})
            boundary_recipe = case.get("boundary_input_recipe")
            overflow_recipe = case.get("overflow_input_recipe")
            if boundary_recipe is not None or overflow_recipe is not None:
                boundary_input = self.materialize_indexed_scope_recipe(
                    boundary_recipe
                )
                overflow_input = self.materialize_indexed_scope_recipe(
                    overflow_recipe
                )
                boundary = self.normalize_scope_input(boundary_input)
                overflow = self.normalize_scope_input(overflow_input)
                expected_bounds = {
                    "scope_pattern_item_byte_bound": (
                        1,
                        256,
                        "per_pattern_bytes",
                    ),
                    "scope_pattern_count_bound": (
                        64,
                        192,
                        "normalized_pattern_count",
                    ),
                    "scope_pattern_total_byte_bound": (
                        16,
                        4096,
                        "normalized_pattern_bytes",
                    ),
                }
                expected = expected_bounds.get(case_id)
                boundary_identity = (
                    self.scope_identity(boundary)
                    if isinstance(boundary, list)
                    else None
                )
                boundary_count = (
                    len(boundary) if isinstance(boundary, list) else None
                )
                boundary_bytes = (
                    sum(len(pattern.encode("ascii")) for pattern in boundary)
                    if isinstance(boundary, list)
                    else None
                )
                self.require(
                    expected is not None
                    and isinstance(boundary_input, list)
                    and isinstance(overflow_input, list)
                    and isinstance(boundary, list)
                    and overflow is None
                    and oracle.get("boundary_validation") == "passed"
                    and oracle.get("normalized_pattern_count")
                    == boundary_count
                    == expected[0]
                    and oracle.get("normalized_total_bytes")
                    == boundary_bytes
                    == expected[1]
                    and oracle.get("identity") == boundary_identity
                    and oracle.get("overflow_validation") == "failed"
                    and oracle.get("overflow_constraint") == expected[2]
                    and oracle.get("filesystem_side_effects") == [],
                    path,
                    context,
                    "scope boundary recipe must pass exactly at the frozen "
                    "limit and reject the isolated overflow without side "
                    "effects",
                )
                if case_id == "scope_pattern_item_byte_bound":
                    self.require(
                        len(overflow_input) == 1
                        and len(overflow_input[0].encode("ascii")) == 257,
                        path,
                        f"{context}.overflow_input_recipe",
                        "must isolate the per-pattern 256-byte bound",
                    )
                elif case_id == "scope_pattern_count_bound":
                    self.require(
                        len(overflow_input) == 65
                        and max(
                            len(pattern.encode("ascii"))
                            for pattern in overflow_input
                        )
                        <= 256
                        and sum(
                            len(pattern.encode("ascii"))
                            for pattern in overflow_input
                        )
                        <= 4096,
                        path,
                        f"{context}.overflow_input_recipe",
                        "must isolate the 64-pattern count bound",
                    )
                elif case_id == "scope_pattern_total_byte_bound":
                    self.require(
                        len(overflow_input) == 17
                        and max(
                            len(pattern.encode("ascii"))
                            for pattern in overflow_input
                        )
                        <= 256
                        and sum(
                            len(pattern.encode("ascii"))
                            for pattern in overflow_input
                        )
                        == 4097,
                        path,
                        f"{context}.overflow_input_recipe",
                        "must isolate the 4096-byte normalized-list bound",
                    )
                continue

            if case_id == "invalid_scope_pattern_characters":
                variants = case.get("input_variants")
                expected_variant_names = {
                    "slash",
                    "internal_whitespace",
                    "backslash",
                    "non_ascii",
                    "control_character",
                }
                materialized: dict[str, Any] = {}
                if isinstance(variants, dict):
                    materialized = dict(variants)
                    if materialized.get("control_character") == {
                        "recipe": "prefix_lf_suffix"
                    }:
                        materialized["control_character"] = "prefix\nsuffix"
                all_rejected = (
                    set(materialized) == expected_variant_names
                    and all(
                        self.normalize_scope_input(value) is None
                        for value in materialized.values()
                    )
                )
                self.require(
                    all_rejected
                    and oracle.get("validation") == "failed"
                    and oracle.get("all_variants_rejected") is True
                    and oracle.get("rejected_constraints")
                    == {
                        "slash": "forbidden_character",
                        "internal_whitespace": "forbidden_character",
                        "backslash": "forbidden_character",
                        "non_ascii": "printable_ascii",
                        "control_character": "printable_ascii",
                    }
                    and oracle.get("filesystem_side_effects") == [],
                    path,
                    context,
                    "slash, whitespace, backslash, non-ASCII, and control "
                    "characters must all fail scope validation",
                )
                continue

            normalized = self.normalize_scope_input(case.get("input"))
            validation_failed = oracle.get("validation") == "failed"
            if validation_failed:
                self.require(
                    normalized is None,
                    path,
                    f"{context}.input",
                    "invalid scope input must not produce normalized patterns",
                )
            else:
                self.require(
                    normalized == oracle.get("patterns"),
                    path,
                    f"{context}.oracle.patterns",
                    f"expected normalized scope {normalized!r}",
                )
            if "patterns" in oracle and "identity" in oracle:
                self.validate_scope(
                    path,
                    f"{context}.oracle",
                    oracle,
                    comparison_schema_version_optional=True,
                )
            if case_id == "fnmatchcase_full_name_dialect":
                patterns = oracle.get("patterns")
                probes = oracle.get("probes")
                actual_probes = (
                    [
                        {
                            "name": probe.get("name"),
                            "matches": any(
                                fnmatch.fnmatchcase(
                                    probe.get("name"), pattern
                                )
                                for pattern in patterns
                            ),
                        }
                        for probe in probes
                    ]
                    if isinstance(patterns, list)
                    and isinstance(probes, list)
                    and all(
                        isinstance(probe, dict)
                        and isinstance(probe.get("name"), str)
                        for probe in probes
                    )
                    else None
                )
                self.require(
                    oracle.get("matcher") == "python_fnmatch_fnmatchcase"
                    and oracle.get("supported_tokens")
                    == ["*", "?", "[seq]", "[!seq]"]
                    and oracle.get("case_sensitive") is True
                    and oracle.get("full_name_match") is True
                    and probes
                    == [
                        {"name": "Fixture-Api", "matches": True},
                        {"name": "Fixture-api", "matches": True},
                        {"name": "Fixture-9pi", "matches": False},
                        {"name": "fixture-Api", "matches": False},
                        {"name": "PrefixFixture-Api", "matches": False},
                        {"name": "Fixture-Api-suffix", "matches": False},
                        {"name": "worker-a", "matches": True},
                        {"name": "worker-b", "matches": True},
                        {"name": "worker-c", "matches": False},
                        {"name": "worker-aa", "matches": False},
                        {"name": "service-api", "matches": True},
                        {"name": "xservice-api", "matches": False},
                    ]
                    and actual_probes == probes,
                    path,
                    f"{context}.oracle",
                    "fnmatchcase must apply the frozen ?, [!seq], "
                    "case-sensitive, whole-name dialect",
                )
        for index, case in enumerate(data.get("container_cases", [])):
            if (
                case.get("id")
                == "canonical_observation_bounds_and_allowlist_reject_mutations"
            ):
                context = f"container_cases[{index}]"
                boundary = case.get("boundary_recipe")
                mutations = case.get("mutation_variants")
                oracle = case.get("oracle")
                expected_mutations = [
                    "observation_unknown_key",
                    "container_unknown_key",
                    "container_name_256_bytes",
                    "image_reference_4097_bytes",
                    "image_reference_control_character",
                    "container_count_4097",
                    "unknown_discovery_backend",
                    "metadata_gaps_unsorted",
                    "metadata_gaps_duplicate",
                    "metadata_gap_unknown_path",
                    "complete_reason_nonnull",
                    "stale_gap_for_available_field",
                ]
                name_recipe = (
                    boundary.get("container_name", {})
                    if isinstance(boundary, dict)
                    else {}
                )
                reference_recipe = (
                    boundary.get("image_reference", {})
                    if isinstance(boundary, dict)
                    else {}
                )
                boundary_name = (
                    name_recipe.get("character")
                    * name_recipe.get("bytes")
                    if isinstance(name_recipe.get("character"), str)
                    and self.is_int(name_recipe.get("bytes"))
                    else ""
                )
                boundary_reference = (
                    reference_recipe.get("character")
                    * reference_recipe.get("bytes")
                    if isinstance(
                        reference_recipe.get("character"), str
                    )
                    and self.is_int(reference_recipe.get("bytes"))
                    else ""
                )
                boundary_gaps = (
                    boundary.get("metadata_gaps")
                    if isinstance(boundary, dict)
                    else None
                )
                observation_keys = (
                    boundary.get("observation_keys")
                    if isinstance(boundary, dict)
                    else None
                )
                container_keys = (
                    boundary.get("container_keys")
                    if isinstance(boundary, dict)
                    else None
                )
                rejection_probes = {
                    "observation_unknown_key": (
                        set([*(observation_keys or []), "unexpected"])
                        != set(EXACT_CORE_MODEL_FIELDS["observation"])
                    ),
                    "container_unknown_key": (
                        set([*(container_keys or []), "unexpected"])
                        != set(
                            EXACT_CORE_MODEL_FIELDS[
                                "container_observation"
                            ]
                        )
                    ),
                    "container_name_256_bytes": not (
                        len(("n" * 256).encode("ascii")) <= 255
                        and CONTAINER_NAME_RE.fullmatch("n" * 256)
                        is not None
                    ),
                    "image_reference_4097_bytes": not (
                        len(("r" * 4097).encode("ascii")) <= 4096
                    ),
                    "image_reference_control_character": not all(
                        0x21 <= byte <= 0x7E
                        for byte in b"valid\ninvalid"
                    ),
                    "container_count_4097": not (4097 <= 4096),
                    "unknown_discovery_backend": (
                        "docker_cli_v2"
                        not in {"synthetic", "docker_cli_v1"}
                    ),
                    "metadata_gaps_unsorted": (
                        [
                            "fixture-api.restart_count",
                            "fixture-api.created_at",
                        ]
                        != sorted(
                            {
                                "fixture-api.restart_count",
                                "fixture-api.created_at",
                            },
                            key=lambda gap: gap.encode("ascii"),
                        )
                    ),
                    "metadata_gaps_duplicate": (
                        len(
                            [
                                "fixture-api.created_at",
                                "fixture-api.created_at",
                            ]
                        )
                        != len({"fixture-api.created_at"})
                    ),
                    "metadata_gap_unknown_path": (
                        "not_a_model_field"
                        not in {
                            *EXACT_CORE_MODEL_FIELDS[
                                "container_observation"
                            ],
                            "container_inspect",
                        }
                    ),
                    "complete_reason_nonnull": (
                        isinstance("required_field_missing", str)
                    ),
                    "stale_gap_for_available_field": (
                        "fixture-api.created_at"
                        in {"fixture-api.created_at"}
                    ),
                }
                boundary_valid = (
                    isinstance(boundary, dict)
                    and observation_keys
                    == EXACT_CORE_MODEL_FIELDS["observation"]
                    and container_keys
                    == EXACT_CORE_MODEL_FIELDS["container_observation"]
                    and boundary.get("discovery_backend")
                    == "docker_cli_v1"
                    and len(boundary_name.encode("ascii")) == 255
                    and CONTAINER_NAME_RE.fullmatch(boundary_name)
                    is not None
                    and len(boundary_reference.encode("ascii")) == 4096
                    and all(
                        0x21 <= byte <= 0x7E
                        for byte in boundary_reference.encode("ascii")
                    )
                    and boundary.get("container_count") == 4096
                    and boundary_gaps
                    == sorted(
                        set(boundary_gaps),
                        key=lambda gap: gap.encode("ascii"),
                    )
                )
                self.require(
                    boundary_valid
                    and mutations == expected_mutations
                    and set(rejection_probes) == set(expected_mutations)
                    and all(rejection_probes.values())
                    and oracle
                    == {
                        "boundary_accepted": True,
                        "mutation_count": 12,
                        "every_mutation_rejected": True,
                        "unknown_keys_rejected": True,
                        "metadata_gap_order_and_paths_enforced": True,
                        "complete_reason_must_be_null": True,
                        "available_evidence_cannot_retain_gap": True,
                    },
                    path,
                    context,
                    "canonical observation and container allowlists, byte "
                    "bounds, catalogue cap, gap grammar, and cross-field "
                    "invariants must reject every isolated mutation",
                )
                continue
            if (
                case.get("id")
                == "invalid_optional_evidence_normalizes_to_gap"
            ):
                context = f"container_cases[{index}]"
                required_projection = case.get("required_projection")
                variants = case.get("input_variants")
                oracle = case.get("oracle")
                expected_variant_fields = {
                    "invalid_calendar_created_at": "created_at",
                    "non_utc_started_at": "started_at",
                    "malformed_finished_at": "finished_at",
                    "negative_restart_count": "restart_count",
                    "boolean_restart_count": "restart_count",
                }

                def valid_canonical_timestamp(value: Any) -> bool:
                    match = (
                        UTC_TIMESTAMP_RE.fullmatch(value)
                        if isinstance(value, str)
                        else None
                    )
                    if match is None:
                        return False
                    fraction = match.group("fraction")
                    if fraction is not None and fraction.endswith("0"):
                        return False
                    try:
                        dt.datetime.fromisoformat(
                            value.removesuffix("Z") + "+00:00"
                        )
                    except ValueError:
                        return False
                    return True

                computed_oracle: dict[str, Any] = {}
                invalid_inputs = True
                if isinstance(variants, dict):
                    for variant_id, field in expected_variant_fields.items():
                        variant = variants.get(variant_id, {})
                        raw_value = (
                            variant.get("raw_value")
                            if isinstance(variant, dict)
                            else None
                        )
                        invalid = (
                            not valid_canonical_timestamp(raw_value)
                            if field != "restart_count"
                            else not (
                                self.is_int(raw_value)
                                and raw_value >= 0
                            )
                        )
                        invalid_inputs = invalid_inputs and (
                            isinstance(variant, dict)
                            and variant.get("field") == field
                            and invalid
                        )
                        computed_oracle[variant_id] = {
                            "normalized_value": None,
                            "metadata_gaps": [
                                f"fixture-optional.{field}"
                            ],
                            "observation_status": "complete",
                            "reason_code": None,
                            "warnings": [],
                        }
                computed_oracle.update(
                    {
                        "required_evidence_preserved": True,
                        "authoritative_absence": True,
                    }
                )
                self.require(
                    isinstance(required_projection, dict)
                    and set(required_projection)
                    == {
                        "name",
                        "container_id",
                        "full_image_reference",
                        "image_id",
                        "runtime_state",
                    }
                    and required_projection.get("name")
                    == "fixture-optional"
                    and CONTAINER_ID_RE.fullmatch(
                        required_projection.get("container_id", "")
                    )
                    is not None
                    and required_projection.get(
                        "full_image_reference"
                    )
                    == "registry.example.com/team/optional:v1"
                    and SHA256_RE.fullmatch(
                        required_projection.get("image_id", "")
                    )
                    is not None
                    and required_projection.get("runtime_state")
                    == "running"
                    and isinstance(variants, dict)
                    and set(variants) == set(expected_variant_fields)
                    and invalid_inputs
                    and oracle == computed_oracle,
                    path,
                    context,
                    "invalid optional timestamps and restart counts must "
                    "normalize to field gaps while preserving complete "
                    "required evidence and an empty warning contract",
                )
                continue
            projection = case.get("safe_adapter_projection")
            self.validate_adapter_projection(
                path, f"container_cases[{index}].safe_adapter_projection", projection
            )
            if case.get("id") == "docker_zero_time_sentinels_normalize_to_null":
                oracle = case.get("oracle", {})
                self.require(
                    isinstance(projection, dict)
                    and projection.get("created_at")
                    == "2026-07-30T09:00:00.123456789Z"
                    and projection.get("started_at")
                    == "0001-01-01T00:00:00Z"
                    and projection.get("finished_at")
                    == "0001-01-01T00:00:00Z"
                    and oracle
                    == {
                        "name": "fixture-created",
                        "created_at": "2026-07-30T09:00:00.123456789Z",
                        "started_at": None,
                        "finished_at": None,
                        "metadata_gaps": [],
                        "observation_status": "complete",
                    },
                    path,
                    f"container_cases[{index}]",
                    "Docker zero start/finish sentinels must normalize to "
                    "semantic null without metadata gaps",
                )
        for index, case in enumerate(data.get("discovery_cases", [])):
            oracle = case.get("oracle")
            if not self.require(
                isinstance(oracle, dict),
                path,
                f"discovery_cases[{index}].oracle",
                "must be a mapping",
            ):
                continue
            context = f"discovery_cases[{index}]"
            self.enum(
                oracle.get("observation_status"),
                self.schema.get("observation", {}).get("status_values", []),
                path,
                f"{context}.oracle.observation_status",
            )
            if oracle.get("observation_status") != "complete":
                reason_codes = (
                    self.schema.get("focused_fixture", {})
                    .get("constraints", {})
                    .get("discovery_reason_codes", [])
                )
                self.enum(
                    oracle.get("reason_code"),
                    reason_codes,
                    path,
                    f"{context}.oracle.reason_code",
                )
                self.require(
                    oracle.get("authoritative_absence") is False,
                    path,
                    f"{context}.oracle.authoritative_absence",
                    "partial or unavailable discovery cannot assert authoritative absence",
                )
            safe_input = case.get("safe_adapter_input")
            self.require(
                isinstance(safe_input, dict),
                path,
                f"{context}.safe_adapter_input",
                "must be a mapping",
            )
            if isinstance(safe_input, dict):
                list_result = safe_input.get("list_result")
                if isinstance(list_result, dict):
                    list_status = list_result.get("status")
                    self.enum(
                        list_status,
                        {"success", "failed"},
                        path,
                        f"{context}.safe_adapter_input.list_result.status",
                    )
                    catalogue = list_result.get("catalogue")
                    if list_status == "success":
                        self.require(
                            isinstance(catalogue, list)
                            and "container_ids" not in list_result,
                            path,
                            f"{context}.safe_adapter_input.list_result",
                            "successful discovery must expose one ID/name "
                            "catalogue rather than an ID-only list",
                        )
                    if isinstance(catalogue, list):
                        catalogue_ids: list[str] = []
                        catalogue_names: list[str] = []
                        for catalogue_index, catalogue_row in enumerate(
                            catalogue
                        ):
                            row_context = (
                                f"{context}.safe_adapter_input.list_result."
                                f"catalogue[{catalogue_index}]"
                            )
                            if not self.require(
                                isinstance(catalogue_row, dict),
                                path,
                                row_context,
                                "must be a mapping",
                            ):
                                continue
                            container_id = catalogue_row.get("container_id")
                            self.require(
                                isinstance(container_id, str)
                                and CONTAINER_ID_RE.fullmatch(container_id)
                                is not None,
                                path,
                                f"{row_context}.container_id",
                                "must be a normalized 64-character "
                                "container ID",
                            )
                            if isinstance(container_id, str):
                                catalogue_ids.append(container_id)
                            catalogue_name = catalogue_row.get("name")
                            name_is_known = (
                                isinstance(catalogue_name, str)
                                and bool(catalogue_name)
                                and catalogue_name == catalogue_name.strip()
                                and not catalogue_name.startswith("/")
                            )
                            name_is_gapped = (
                                catalogue_name is None
                                and catalogue_row.get("gap")
                                == "name_unparsable"
                            )
                            self.require(
                                name_is_known or name_is_gapped,
                                path,
                                f"{row_context}.name",
                                "must be a normalized catalogue name or an "
                                "explicit name-unparsable gap",
                            )
                            if name_is_known:
                                catalogue_names.append(catalogue_name)
                        self.require(
                            len(catalogue_ids) == len(set(catalogue_ids))
                            and len(catalogue_names)
                            == len(set(catalogue_names)),
                            path,
                            f"{context}.safe_adapter_input.list_result.catalogue",
                            "catalogue IDs and known names must be unique",
                        )
                projections = safe_input.get("safe_container_projections", [])
                if isinstance(projections, list):
                    for projection_index, projection in enumerate(projections):
                        self.validate_adapter_projection(
                            path,
                            f"{context}.safe_adapter_input."
                            f"safe_container_projections[{projection_index}]",
                            projection,
                        )
                partial_projection = safe_input.get(
                    "partial_container_projection"
                )
                if partial_projection is not None:
                    self.validate_partial_adapter_projection(
                        path,
                        f"{context}.safe_adapter_input."
                        "partial_container_projection",
                        partial_projection,
                    )
                partial_projections = safe_input.get(
                    "partial_container_projections", []
                )
                self.require(
                    isinstance(partial_projections, list),
                    path,
                    f"{context}.safe_adapter_input."
                    "partial_container_projections",
                    "must be a list when present",
                )
                if isinstance(partial_projections, list):
                    for projection_index, projection in enumerate(
                        partial_projections
                    ):
                        self.validate_partial_adapter_projection(
                            path,
                            f"{context}.safe_adapter_input."
                            "partial_container_projections"
                            f"[{projection_index}]",
                            projection,
                        )
            partial_projection = case.get("partial_container_projection")
            if isinstance(partial_projection, dict):
                self.validate_partial_adapter_projection(
                    path,
                    f"{context}.partial_container_projection",
                    partial_projection,
                )
            if case.get("id") in {
                "catalogue_deadline_is_unavailable",
                "selected_inspect_deadline_is_partial",
            }:
                timeout_result = (
                    safe_input.get("list_result", {})
                    if case.get("id")
                    == "catalogue_deadline_is_unavailable"
                    else safe_input.get("timeout_result", {})
                )
                expected_status = (
                    "unavailable"
                    if case.get("id")
                    == "catalogue_deadline_is_unavailable"
                    else "partial"
                )
                expected_phase = (
                    "catalogue"
                    if expected_status == "unavailable"
                    else "container_inspect"
                )
                forbidden_process_fields = {
                    "command",
                    "arguments",
                    "stdout",
                    "stderr",
                }
                self.require(
                    case.get("discovery_timeout_seconds") == 30
                    and timeout_result.get("reason_code")
                    == "docker_command_timeout"
                    and timeout_result.get("safe_phase")
                    == expected_phase
                    and timeout_result.get("elapsed_seconds") == 30
                    and not (
                        forbidden_process_fields & set(timeout_result)
                    )
                    and oracle.get("observation_status")
                    == expected_status
                    and oracle.get("reason_code")
                    == "docker_command_timeout"
                    and oracle.get("warning")
                    == OBSERVATION_WARNING_BY_REASON[
                        "docker_command_timeout"
                    ]
                    and oracle.get("safe_phase") == expected_phase
                    and oracle.get("elapsed_seconds") == 30
                    and (
                        expected_phase == "catalogue"
                        or timeout_result.get("remaining_budget_seconds") == 0
                    )
                    and oracle.get("authoritative_absence") is False
                    and oracle.get("raw_process_fields_returned") == []
                    and oracle.get("timeout_budget_reset_per_process")
                    is False,
                    path,
                    f"{context}.oracle",
                    "one monotonic deadline must produce a safe bounded "
                    "timeout result without raw process fields",
                )
            if (
                case.get("id")
                == "monotonic_deadline_decreases_across_container_chunks"
            ):
                deadline = case.get("discovery_timeout_seconds")
                schedule = case.get("monotonic_process_schedule")
                expected_phases = [
                    ("catalogue", 1),
                    ("container_inspect", 1),
                    ("container_inspect", 2),
                    ("container_inspect", 3),
                    ("container_inspect", 4),
                ]
                schedule_valid = (
                    deadline == 30
                    and isinstance(schedule, list)
                    and len(schedule) == len(expected_phases)
                )
                applied_budgets: list[int] = []
                previous_finish = 0
                if schedule_valid:
                    for index, (step, expected_phase_chunk) in enumerate(
                        zip(schedule, expected_phases)
                    ):
                        phase, chunk = expected_phase_chunk
                        if not isinstance(step, dict):
                            schedule_valid = False
                            break
                        start = step.get("started_elapsed_seconds")
                        finish = step.get("finished_elapsed_seconds")
                        budget = step.get("timeout_budget_seconds")
                        remaining = step.get("remaining_after_seconds")
                        expected_outcome = (
                            "timeout"
                            if index == len(expected_phases) - 1
                            else "success"
                        )
                        step_valid = (
                            step.get("phase") == phase
                            and step.get("chunk") == chunk
                            and self.is_int(start)
                            and self.is_int(finish)
                            and self.is_int(budget)
                            and self.is_int(remaining)
                            and start == previous_finish
                            and start <= finish <= deadline
                            and budget == deadline - start
                            and remaining == deadline - finish
                            and step.get("outcome") == expected_outcome
                            and not (
                                {
                                    "command",
                                    "arguments",
                                    "stdout",
                                    "stderr",
                                }
                                & set(step)
                            )
                        )
                        schedule_valid = schedule_valid and step_valid
                        if not step_valid:
                            break
                        applied_budgets.append(budget)
                        previous_finish = finish
                strictly_decreasing = all(
                    later < earlier
                    for earlier, later in zip(
                        applied_budgets,
                        applied_budgets[1:],
                    )
                )
                self.require(
                    schedule_valid
                    and applied_budgets == [30, 28, 23, 16, 12]
                    and strictly_decreasing
                    and previous_finish == deadline
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "docker_command_timeout"
                    and oracle.get("warning")
                    == OBSERVATION_WARNING_BY_REASON[
                        "docker_command_timeout"
                    ]
                    and oracle.get("safe_phase") == "container_inspect"
                    and oracle.get("elapsed_seconds") == deadline
                    and oracle.get("remaining_budget_seconds") == 0
                    and oracle.get("executed_processes") == len(schedule)
                    and oracle.get("applied_budgets") == applied_budgets
                    and oracle.get("budgets_strictly_decrease") is True
                    and oracle.get(
                        "every_budget_equals_deadline_minus_start_elapsed"
                    )
                    is True
                    and oracle.get(
                        "every_remaining_equals_deadline_minus_finish_elapsed"
                    )
                    is True
                    and oracle.get("timeout_budget_reset_per_process") is False
                    and oracle.get("child_terminated_and_reaped") is True
                    and oracle.get("authoritative_absence") is False
                    and oracle.get("raw_process_fields_returned") == [],
                    path,
                    f"{context}.oracle",
                    "the concrete catalogue/container schedule must "
                    "consume one strictly decreasing monotonic deadline",
                )
            if (
                case.get("id")
                == "failed_inspect_chunk_is_atomic_and_stops_later_chunks"
            ):
                catalogue = safe_input.get("list_result", {}).get(
                    "catalogue"
                )
                plan = safe_input.get("inspect_chunk_plan")
                expected_names = [
                    "fixture-a",
                    "fixture-b",
                    "fixture-c",
                    "fixture-d",
                ]
                expected_reasons = {
                    "generic_nonzero": "docker_daemon_unauthorized",
                    "exact_no_such_object": "required_field_missing",
                    "malformed_protocol": "docker_protocol_error",
                    "output_cap": "docker_output_limit_exceeded",
                    "timeout": "docker_command_timeout",
                }
                self.require(
                    isinstance(catalogue, list)
                    and [row.get("name") for row in catalogue]
                    == expected_names
                    and all(
                        isinstance(row.get("container_id"), str)
                        and CONTAINER_ID_RE.fullmatch(
                            row["container_id"]
                        )
                        is not None
                        for row in catalogue
                    )
                    and isinstance(plan, list)
                    and len(plan) == 3
                    and plan[0]
                    == {
                        "chunk": 1,
                        "selected_names": ["fixture-a"],
                        "outcome": "success",
                        "accepted_names": ["fixture-a"],
                    }
                    and plan[1].get("chunk") == 2
                    and plan[1].get("selected_names")
                    == ["fixture-b", "fixture-c"]
                    and plan[1].get("parseable_stdout_prefix_names")
                    == ["fixture-b"]
                    and set(plan[1].get("failure_variants", {}))
                    == set(expected_reasons)
                    and plan[1]["failure_variants"]["generic_nonzero"]
                    == {
                        "returncode": 1,
                        "stderr_classifier": "permission_denied",
                    }
                    and plan[1]["failure_variants"][
                        "exact_no_such_object"
                    ]
                    == {
                        "returncode": 1,
                        "stderr_classifier": "exact_no_such_object",
                    }
                    and plan[1]["failure_variants"][
                        "malformed_protocol"
                    ]
                    == {
                        "returncode": 0,
                        "parser_failure": "invalid_json",
                    }
                    and plan[1]["failure_variants"]["output_cap"]
                    == {
                        "status": "failed",
                        "stdout_byte_limit_exceeded": True,
                    }
                    and plan[1]["failure_variants"]["timeout"]
                    == {
                        "status": "timed_out",
                        "child_terminated_and_reaped": True,
                    }
                    and plan[2]
                    == {
                        "chunk": 3,
                        "selected_names": ["fixture-d"],
                        "outcome": "not_started",
                    }
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "docker_daemon_unauthorized"
                    and oracle.get("failure_variant_reasons")
                    == expected_reasons
                    and oracle.get("retained_container_names")
                    == ["fixture-a"]
                    and oracle.get("discarded_current_chunk_names")
                    == ["fixture-b", "fixture-c"]
                    and oracle.get("unstarted_chunk_names")
                    == ["fixture-d"]
                    and oracle.get("metadata_gaps")
                    == [
                        "fixture-b.container_inspect",
                        "fixture-c.container_inspect",
                        "fixture-d.container_inspect",
                    ]
                    and oracle.get("invoked_inspect_chunks") == [1, 2]
                    and oracle.get("unstarted_inspect_chunks") == [3]
                    and oracle.get(
                        "current_chunk_stdout_prefix_accepted"
                    )
                    is False
                    and oracle.get(
                        "same_chunk_atomicity_for_all_failure_variants"
                    )
                    is True
                    and oracle.get(
                        "later_chunks_started_after_failure"
                    )
                    is False
                    and oracle.get("authoritative_absence") is False
                    and oracle.get("raw_process_fields_returned") == [],
                    path,
                    f"{context}.oracle",
                    "every failed inspect variant must atomically discard "
                    "the current chunk, retain only prior chunks, stop later "
                    "chunks, and mark all unresolved selected names",
                )
            if case.get("id") == "complete_empty_catalogue":
                catalogue = safe_input.get("list_result", {}).get(
                    "catalogue"
                )
                self.require(
                    catalogue == []
                    and oracle.get("observation_status") == "complete"
                    and oracle.get("containers") == {}
                    and oracle.get("container_inspect_calls") == 0,
                    path,
                    f"{context}.oracle",
                    "a successful empty ID/name catalogue must be "
                    "authoritative with zero inspect work",
                )
            if (
                case.get("id")
                == "selected_container_inspect_failure_is_partial"
            ):
                catalogue = safe_input.get("list_result", {}).get(
                    "catalogue", []
                )
                projection = safe_input.get(
                    "partial_container_projection", {}
                )
                self.require(
                    len(catalogue) == 1
                    and catalogue[0].get("name") == "fixture-api"
                    and projection.get("container_id")
                    == catalogue[0].get("container_id")
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "required_field_missing"
                    and oracle.get("catalogue_container_count") == 1
                    and oracle.get("selected_container_inspect_count") == 1,
                    path,
                    f"{context}.oracle",
                    "a selected container inspection gap must retain "
                    "catalogue identity and make the observation partial",
                )
            if case.get("id") == "malformed_catalogue_is_protocol_unavailable":
                self.require(
                    safe_input.get("list_result")
                    == {"status": "failed", "parser_failure": "invalid_json"}
                    and oracle.get("observation_status") == "unavailable"
                    and oracle.get("reason_code") == "docker_protocol_error"
                    and oracle.get("containers") is None
                    and oracle.get("authoritative_absence") is False
                    and oracle.get("raw_process_fields_returned") == [],
                    path,
                    f"{context}.oracle",
                    "malformed catalogue output must be unavailable protocol "
                    "failure without raw process data",
                )
            if case.get("id") == "catalogue_capacity_is_unavailable":
                list_result = safe_input.get("list_result", {})
                self.require(
                    list_result.get("status") == "failed"
                    and list_result.get("validated_row_count") == 4097
                    and list_result.get("catalogue_row_limit") == 4096
                    and oracle.get("observation_status") == "unavailable"
                    and oracle.get("reason_code")
                    == "discovery_capacity_exceeded"
                    and oracle.get("containers") is None
                    and oracle.get("authoritative_absence") is False
                    and oracle.get("raw_process_fields_returned") == [],
                    path,
                    f"{context}.oracle",
                    "catalogue capacity overflow must be unavailable without "
                    "accepting a truncated prefix",
                )
            if case.get("id") in {
                "inspect_selected_id_disappears",
                "inspect_identity_mismatch_is_partial",
                "inspect_name_mismatch_is_scope_unknown",
                "inspect_output_cap_is_partial",
            }:
                catalogue = safe_input.get("list_result", {}).get(
                    "catalogue", []
                )
                inspect_result = safe_input.get("inspect_result", {})
                expected_reason = {
                    "inspect_selected_id_disappears": "required_field_missing",
                    "inspect_identity_mismatch_is_partial": "required_field_missing",
                    "inspect_name_mismatch_is_scope_unknown": "scope_membership_unknown",
                    "inspect_output_cap_is_partial": "docker_output_limit_exceeded",
                }[case.get("id")]
                shape_valid = (
                    isinstance(catalogue, list)
                    and len(catalogue) == 1
                    and isinstance(inspect_result, dict)
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code") == expected_reason
                    and oracle.get("containers") == {}
                    and oracle.get("authoritative_absence") is False
                )
                if case.get("id") == "inspect_selected_id_disappears":
                    shape_valid = (
                        shape_valid
                        and inspect_result
                        == {"status": "success", "projections": []}
                        and oracle.get("metadata_gaps")
                        == ["fixture-api.container_inspect"]
                    )
                elif case.get("id") == "inspect_identity_mismatch_is_partial":
                    projections = inspect_result.get("projections", [])
                    shape_valid = (
                        shape_valid
                        and isinstance(projections, list)
                        and len(projections) == 1
                        and projections[0].get("container_id")
                        != catalogue[0].get("container_id")
                        and projections[0].get("name") == "/fixture-api"
                        and oracle.get("metadata_gaps")
                        == ["fixture-api.container_inspect"]
                    )
                elif case.get("id") == "inspect_name_mismatch_is_scope_unknown":
                    projections = inspect_result.get("projections", [])
                    shape_valid = (
                        shape_valid
                        and isinstance(projections, list)
                        and len(projections) == 1
                        and projections[0].get("container_id")
                        == catalogue[0].get("container_id")
                        and projections[0].get("name") == "/other-api"
                        and oracle.get("metadata_gaps")
                        == [
                            "fixture-api.container_inspect",
                            "fixture-api.name",
                        ]
                    )
                else:
                    shape_valid = (
                        shape_valid
                        and inspect_result.get("status") == "failed"
                        and inspect_result.get("stdout_bytes_observed")
                        == 2097153
                        and inspect_result.get("stdout_byte_limit")
                        == 2097152
                        and oracle.get("metadata_gaps")
                        == ["fixture-api.container_inspect"]
                        and oracle.get("raw_process_fields_returned") == []
                    )
                self.require(
                    shape_valid,
                    path,
                    f"{context}.oracle",
                    "inspect race/protocol capacity outcomes must map to the "
                    "exact partial reason without authoritative absence",
                )
            if (
                case.get("id")
                == "known_out_of_scope_catalogue_row_is_not_inspected"
            ):
                self.require(
                    oracle.get("observation_status") == "complete"
                    and oracle.get("metadata_gaps") == []
                    and oracle.get("authoritative_absence") is True
                    and "other-broken" in oracle.get("excluded_names", [])
                    and oracle.get("catalogue_container_count") == 2
                    and oracle.get("selected_container_inspect_count") == 1
                    and oracle.get("unselected_container_inspections") == 0
                    and len(
                        safe_input.get("safe_container_projections", [])
                    )
                    == 1
                    and not safe_input.get(
                        "partial_container_projections", []
                    ),
                    path,
                    f"{context}.oracle",
                    "known out-of-scope catalogue rows must be filtered "
                    "without container inspection",
                )
            if case.get("id") == "catalogue_name_missing_is_partial":
                catalogue = (
                    safe_input.get("list_result", {}).get("catalogue", [])
                    if isinstance(safe_input, dict)
                    else []
                )
                self.require(
                    len(catalogue) == 1
                    and catalogue[0].get("name") is None
                    and catalogue[0].get("gap") == "name_unparsable"
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "scope_membership_unknown"
                    and oracle.get("metadata_gaps")
                    == ["docker.catalogue"]
                    and oracle.get("catalogue_container_count") == 1
                    and oracle.get("selected_container_inspect_count") == 0,
                    path,
                    f"{context}.oracle",
                    "an unparsable catalogue name must make scope "
                    "membership partial before inspection",
                )
            if (
                case.get("id")
                == "mixed_catalogue_case_sensitive_overlapping_scope"
            ):
                self.require(
                    oracle.get("catalogue_container_count") == 4
                    and oracle.get("inspected_container_count") == 3
                    and oracle.get("selected_name_count") == 3
                    and oracle.get("unselected_container_inspections") == 0
                    and len(
                        safe_input.get("safe_container_projections", [])
                    )
                    == 3,
                    path,
                    f"{context}.oracle",
                    "overlapping scope must select once and avoid inspecting "
                    "the excluded catalogue row",
                )
            if case.get("id") == "explicit_all_selects_mixed_catalogue":
                self.require(
                    oracle.get("normalized_scope", {}).get("patterns")
                    == ["*"]
                    and oracle.get("catalogue_container_count") == 2
                    and oracle.get("inspected_container_count") == 2
                    and len(
                        safe_input.get("safe_container_projections", [])
                    )
                    == 2,
                    path,
                    f"{context}.oracle",
                    "explicit all scope must inspect every trustworthy "
                    "catalogue row",
                )
            normalized_scope = oracle.get("normalized_scope")
            if isinstance(normalized_scope, dict):
                self.validate_scope(
                    path,
                    f"{context}.oracle.normalized_scope",
                    normalized_scope,
                    comparison_schema_version_optional=True,
                )

    def validate_legacy_boundary_cases(
        self, path: Path, cases: list[dict[str, Any]]
    ) -> None:
        for case in cases:
            context = f"case {case.get('id')!r}"
            if not self.require_keys(case, ["component", "oracle"], path, context):
                continue
            component = case.get("component")
            self.enum(
                component,
                {"external_role", "mdad_cutover_adapter"},
                path,
                f"{context}.component",
            )
            oracle = case.get("oracle", {})
            case_id = case.get("id")

            if component == "external_role":
                outcome = oracle.get("persistence_outcome")
                self.enum(
                    outcome,
                    self.schema.get("oracle", {}).get(
                        "persistence_outcome_values", []
                    ),
                    path,
                    f"{context}.oracle.persistence_outcome",
                )
            if case_id == "core_role_rejects_legacy_initialize":
                self.require(
                    case.get("invocation", {}).get("operation")
                    == "legacy_initialize"
                    and oracle.get("validation") == "failed"
                    and oracle.get("reason_code") == "unknown_operation"
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_access_attempted") is False
                    and oracle.get("persistence_outcome") == "not_attempted",
                    path,
                    context,
                    "the external role must reject the removed legacy operation "
                    "before discovery or store access",
                )
            elif case_id == "canonical_store_rejects_legacy_field":
                candidate_store = case.get("candidate_store")
                self.require(
                    isinstance(candidate_store, dict)
                    and "legacy_baseline" in candidate_store
                    and oracle.get("validation") == "failed"
                    and oracle.get("reason_code") == "unknown_store_field"
                    and oracle.get("rejected_field") == "legacy_baseline"
                    and oracle.get("store_mutated") is False,
                    path,
                    context,
                    "canonical DAS state must reject the legacy_baseline field",
                )
            elif case_id == "native_observation_does_not_read_cutover_report":
                self.require(
                    case.get("invocation", {}).get("operation") == "pre"
                    and oracle.get(
                        "external_cutover_report_access_attempted"
                    )
                    is False
                    and oracle.get("legacy_values_imported") is False
                    and oracle.get("observation_source")
                    == "native_docker_discovery"
                    and oracle.get("persistence_outcome") == "committed",
                    path,
                    context,
                    "native DAS observation must ignore MDAD cutover reports",
                )
            elif (
                case_id == "first_native_post_after_cutover_establishes_baseline"
            ):
                self.require(
                    case.get("invocation", {}).get("operation") == "post"
                    and oracle.get(
                        "external_cutover_report_access_attempted"
                    )
                    is False
                    and oracle.get("baseline_source")
                    == "native_complete_post"
                    and oracle.get("baseline_advanced") is True
                    and oracle.get("journal_status") == "incomplete_pre"
                    and oracle.get("persistence_outcome") == "committed",
                    path,
                    context,
                    "first native post must establish a native-only baseline",
                )
            elif component == "mdad_cutover_adapter":
                self.require(
                    oracle.get("das_invoked") is False
                    and oracle.get("das_persistence_outcome")
                    == "not_attempted",
                    path,
                    context,
                    "MDAD boundary cases must leave DAS untouched",
                )
                allowed = case_id in {
                    "valid_legacy_assessment_writes_only_mdad_report",
                    "missing_legacy_sources_is_clean_fresh_start",
                    "explicit_source_policy_resolves_legacy_conflict",
                }
                blocked = case_id in {
                    "malformed_legacy_source_is_backed_up_and_blocks",
                    "unresolved_legacy_conflict_is_backed_up_and_blocks",
                }
                if allowed or blocked:
                    self.require(
                        oracle.get("cutover_report_outcome") == "written"
                        and oracle.get("fresh_native_start_allowed")
                        is allowed
                        and oracle.get("cutover_blocked") is blocked,
                        path,
                        context,
                        "cutover outcome does not match assessed evidence",
                    )
                    adapter_result = case.get("adapter_result")
                    self.require(
                        isinstance(adapter_result, dict)
                        and adapter_result.get("backups_complete") is True,
                        path,
                        f"{context}.adapter_result",
                        "assessment must complete backups before reporting",
                    )
                    if blocked:
                        self.require(
                            oracle.get("source_files_unchanged") is True,
                            path,
                            f"{context}.oracle.source_files_unchanged",
                            "blocked legacy sources must remain unchanged",
                        )
                if (
                    case_id
                    == "explicit_source_policy_resolves_legacy_conflict"
                ):
                    adapter_result = case.get("adapter_result")
                    self.require(
                        isinstance(adapter_result, dict)
                        and adapter_result.get("source_policy")
                        == "display_state"
                        and oracle.get("recorded_source_policy")
                        == adapter_result.get("source_policy"),
                        path,
                        context,
                        "explicit display_state policy must be recorded in "
                        "the cutover result",
                    )
                    self.require(
                        oracle.get("cutover_report_backup_results")
                        == {
                            "display_state": "completed",
                            "history": "completed",
                        }
                        and oracle.get("fresh_native_start_allowed") is True
                        and oracle.get("cutover_blocked") is False
                        and oracle.get("source_files_unchanged") is True
                        and oracle.get("das_invoked") is False
                        and oracle.get("das_persistence_outcome")
                        == "not_attempted",
                        path,
                        context,
                        "resolved conflict must preserve both backed-up sources, "
                        "allow a fresh start, and leave DAS untouched",
                    )
                if case_id == "repeated_assessment_is_idempotent":
                    self.require(
                        oracle.get("cutover_report_outcome") == "unchanged"
                        and oracle.get("additional_backups_created") is False,
                        path,
                        context,
                        "identical MDAD assessment must be idempotent",
                    )

    def validate_presentation_cases(
        self, path: Path, cases: list[dict[str, Any]]
    ) -> None:
        def render_ascii_table(
            columns: list[str],
            rows: list[list[str]],
            widths: list[int],
        ) -> list[str]:
            border = (
                "+"
                + "+".join("-" * (width + 2) for width in widths)
                + "+"
            )

            def render_row(cells: list[str]) -> str:
                if len(cells) != len(widths) or any(
                    len(cell) > width
                    for cell, width in zip(cells, widths)
                ):
                    return ""
                return (
                    "| "
                    + " | ".join(
                        cell.ljust(width)
                        for cell, width in zip(cells, widths)
                    )
                    + " |"
                )

            return [
                border,
                render_row(columns),
                border,
                *(render_row(row) for row in rows),
                border,
            ]

        def expected_change_label(change: dict[str, Any]) -> Any:
            primary_kind = change.get("primary_kind")
            reference_changed = change.get("image_reference_changed") is True
            content_changed = change.get("image_content_changed") is True
            if primary_kind == "recreated":
                if content_changed and reference_changed:
                    return "recreated+img+ref"
                if content_changed:
                    return "recreated+img"
                if reference_changed:
                    return "recreated+ref"
                return "recreated"
            if primary_kind == "image_changed":
                if content_changed and reference_changed:
                    return "img+ref changed"
                if content_changed:
                    return "img changed"
                if reference_changed:
                    return "ref changed"
                return primary_kind
            if primary_kind == "state_changed":
                return "state changed"
            return primary_kind

        def report_counts_are_exact(
            table: Any,
            counts: Any,
            *,
            primary_kinds: list[Any] | None = None,
        ) -> bool:
            if not isinstance(table, dict) or not isinstance(counts, dict):
                return False
            rows = table.get("rows")
            if not isinstance(rows, list) or not all(
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
                for value in counts.values()
            ):
                return False
            kind = table.get("kind")
            if kind == "run_window":
                if not isinstance(primary_kinds, list) or len(
                    primary_kinds
                ) != len(rows):
                    return False
                observed_counts = {
                    primary_kind: primary_kinds.count(primary_kind)
                    for primary_kind in PRIMARY_KIND_PRECEDENCE_ORDER
                    if primary_kinds.count(primary_kind) > 0
                }
                expected = {**observed_counts, "total": len(rows)}
                return counts == expected
            if kind not in {"current", "known_endpoint"}:
                return False
            required_fields = (
                "container_id",
                "full_image_reference",
                "image_id",
                "runtime_state",
            )
            rows_with_gaps = 0
            for row in rows:
                current = (
                    row.get("machine_current")
                    if isinstance(row, dict)
                    else None
                )
                if not isinstance(current, dict) or any(
                    current.get(field) is None for field in required_fields
                ):
                    rows_with_gaps += 1
            expected = {
                "authoritative_changes": 0,
                "known_rows": len(rows),
                "rows_with_required_gaps": rows_with_gaps,
            }
            return set(counts) == set(ENDPOINT_COUNT_FIELDS) and counts == expected

        for case in cases:
            case_id = case.get("id")
            context = f"case {case_id!r}"
            oracle = case.get("oracle")
            if not self.require(
                isinstance(oracle, dict) and bool(oracle),
                path,
                f"{context}.oracle",
                "must be a non-empty mapping",
            ):
                continue

            if case_id == "lifecycle_messages_are_distinct":
                variants = case.get("input_variants")
                messages = oracle.get("minimum_messages")
                expected_messages = {
                    "no_baseline": ["No previous complete observation"],
                    "no_observed_difference": [
                        "No observed run-window difference"
                    ],
                    "incompatible_scope": [
                        "Scopes are incompatible",
                        "No additions or removals inferred",
                    ],
                    "observation_partial": ["Observation partial"],
                    "observation_unavailable": ["Docker unavailable"],
                    "incomplete_run_pair": [
                        "Run-window comparison unavailable"
                    ],
                    "persistence_conflict": [
                        "Concurrent writer conflict",
                        "Store unchanged",
                    ],
                }
                self.require(
                    isinstance(variants, dict)
                    and set(variants) == set(expected_messages)
                    and messages == expected_messages,
                    path,
                    context,
                    "lifecycle states must retain distinct semantic messages",
                )
                forbidden = oracle.get(
                    "causal_attribution_phrases_forbidden"
                )
                self.validate_string_list(
                    forbidden,
                    path,
                    f"{context}.oracle.causal_attribution_phrases_forbidden",
                )
                rendered_messages = " ".join(
                    message
                    for values in expected_messages.values()
                    for message in values
                ).lower()
                self.require(
                    isinstance(forbidden, list)
                    and all(
                        phrase.lower() not in rendered_messages
                        for phrase in forbidden
                    ),
                    path,
                    context,
                    "semantic summaries must not claim deployment causality",
                )
            elif case_id == "machine_values_are_never_presentation_truncated":
                input_data = case.get("input")
                presentation = case.get("presentation")
                if not self.require(
                    isinstance(input_data, dict)
                    and isinstance(presentation, dict),
                    path,
                    context,
                    "input and presentation must be mappings",
                ):
                    continue
                self.require(
                    oracle.get("machine_container_name")
                    == input_data.get("container_name")
                    and oracle.get("machine_full_image_reference")
                    == input_data.get("full_image_reference")
                    and oracle.get("machine_image_id")
                    == input_data.get("image_id")
                    and oracle.get("machine_values_truncated") is False
                    and oracle.get("human_report_readable") is True,
                    path,
                    context,
                    "presentation shortening must not alter canonical machine values",
                )
                self.require(
                    presentation.get("configured_max_width") == 32
                    and "report_width" not in presentation
                    and presentation.get("truncation_allowed") is True,
                    path,
                    f"{context}.presentation",
                    "32 is a cell-renderer width, not the public report width",
                )
                self.require(
                    isinstance(input_data.get("image_id"), str)
                    and SHA256_RE.fullmatch(input_data["image_id"])
                    is not None,
                    path,
                    f"{context}.input.image_id",
                    "must be a normalized sha256 image ID",
                )
            elif case_id == "host_blocks_identify_independent_results":
                hosts = case.get("input", {}).get("hosts")
                self.require(
                    isinstance(hosts, list)
                    and len(hosts) >= 2
                    and len(hosts) == len(set(hosts))
                    and all(
                        isinstance(host, str) and bool(host.strip())
                        for host in hosts
                    ),
                    path,
                    f"{context}.input.hosts",
                    "must contain distinct non-empty host names",
                )
                self.require(
                    oracle.get("one_host_identifiable_block_per_result")
                    is True
                    and oracle.get("atomic_multi_host_claim") is False
                    and oracle.get(
                        "callback_interleaving_must_not_change_machine_results"
                    )
                    is True,
                    path,
                    context,
                    "host output must be independently identifiable without "
                    "claiming cross-host atomicity",
                )
            elif (
                case_id
                == "warning_normalization_is_exact_bounded_and_sorted"
            ):
                input_data = case.get("input")
                sources = (
                    input_data.get("warning_sources")
                    if isinstance(input_data, dict)
                    else None
                )
                invalid_variants = (
                    input_data.get("invalid_variants")
                    if isinstance(input_data, dict)
                    else None
                )
                if not self.require(
                    input_data.get("fixture_layer")
                    == "internal_warning_normalizer_unit"
                    and input_data.get(
                        "role_generated_templates_applied"
                    )
                    is False
                    and isinstance(sources, dict)
                    and set(sources)
                    == {"observation", "delta", "persistence"}
                    and all(
                        isinstance(warnings, list)
                        and all(
                            isinstance(warning, str)
                            for warning in warnings
                        )
                        for warnings in sources.values()
                    )
                    and isinstance(invalid_variants, dict),
                    path,
                    f"{context}.input",
                    "warning sources and invalid variants must be concrete "
                    "mappings",
                ):
                    continue

                source_warnings = [
                    warning
                    for warnings in sources.values()
                    for warning in warnings
                ]
                normalized_warnings = sorted(
                    set(source_warnings),
                    key=lambda warning: warning.encode("ascii"),
                )
                source_layers_normalized = all(
                    warnings
                    == sorted(
                        set(warnings),
                        key=lambda warning: warning.encode("ascii"),
                    )
                    for warnings in sources.values()
                )

                def serialized_warning_bytes(warnings: list[str]) -> int:
                    return len(
                        json.dumps(
                            warnings,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            allow_nan=False,
                        ).encode("utf-8")
                    )

                def warning_list_is_valid(warnings: list[str]) -> bool:
                    return (
                        len(warnings) <= 64
                        and all(
                            bool(warning.strip())
                            and PRINTABLE_ASCII_RE.fullmatch(warning)
                            is not None
                            and len(warning.encode("ascii")) <= 256
                            for warning in warnings
                        )
                        and serialized_warning_bytes(warnings) <= 8192
                    )

                expected_variant_recipes = {
                    "non_printable": {"recipe": "prefix_lf_suffix"},
                    "overlong_item": {
                        "recipe": "repeated_ascii",
                        "character": "x",
                        "bytes": 257,
                    },
                    "too_many_items": {
                        "recipe": "indexed_warnings",
                        "count": 65,
                    },
                    "total_serialized_bytes": {
                        "recipe": "indexed_fixed_width_warnings",
                        "count": 33,
                        "item_bytes": 250,
                    },
                }
                invalid_candidates = {
                    "non_printable": ["prefix\nsuffix"],
                    "overlong_item": ["x" * 257],
                    "too_many_items": [
                        f"warning-{index:02d}" for index in range(65)
                    ],
                    "total_serialized_bytes": [
                        f"{index:02d}" + ("x" * 248)
                        for index in range(33)
                    ],
                }
                expected_constraints = {
                    "non_printable": "printable_ascii",
                    "overlong_item": "per_item_bytes",
                    "too_many_items": "entry_count",
                    "total_serialized_bytes": "serialized_utf8_bytes",
                }
                isolated_invalid_constraints = (
                    PRINTABLE_ASCII_RE.fullmatch(
                        invalid_candidates["non_printable"][0]
                    )
                    is None
                    and len(
                        invalid_candidates["overlong_item"][0].encode(
                            "ascii"
                        )
                    )
                    == 257
                    and len(invalid_candidates["too_many_items"]) == 65
                    and all(
                        len(warning.encode("ascii")) <= 256
                        for warning in invalid_candidates["too_many_items"]
                    )
                    and serialized_warning_bytes(
                        invalid_candidates["too_many_items"]
                    )
                    <= 8192
                    and len(
                        invalid_candidates["total_serialized_bytes"]
                    )
                    == 33
                    and all(
                        len(warning.encode("ascii")) == 250
                        for warning in invalid_candidates[
                            "total_serialized_bytes"
                        ]
                    )
                    and serialized_warning_bytes(
                        invalid_candidates["total_serialized_bytes"]
                    )
                    > 8192
                )
                self.require(
                    invalid_variants == expected_variant_recipes
                    and normalized_warnings
                    == oracle.get("normalized_warnings")
                    == [
                        "Beta warning",
                        "alpha warning",
                        "duplicate warning",
                        "zeta warning",
                    ]
                    and source_layers_normalized
                    and warning_list_is_valid(normalized_warnings)
                    and serialized_warning_bytes(normalized_warnings) == 67
                    and all(
                        not warning_list_is_valid(candidate)
                        for candidate in invalid_candidates.values()
                    )
                    and isolated_invalid_constraints
                    and oracle.get("exact_string_deduplication") is True
                    and oracle.get("ordering") == "ascii_byte"
                    and oracle.get("printable_ascii_only") is True
                    and oracle.get("per_item_max_bytes") == 256
                    and oracle.get("maximum_entries") == 64
                    and oracle.get("maximum_serialized_utf8_bytes")
                    == 8192
                    and oracle.get("serialized_form")
                    == "compact_json_utf8"
                    and oracle.get("invalid_input_policy") == "reject_model"
                    and oracle.get("silent_truncation_allowed") is False
                    and oracle.get("invalid_variant_constraints")
                    == expected_constraints,
                    path,
                    context,
                    "warning normalization must deduplicate exact strings, "
                    "sort by ASCII bytes, preserve all valid diagnostics, "
                    "and reject rather than truncate every isolated bound "
                    "violation",
                )
            elif case_id == "warning_generation_aggregates_metadata_gaps":
                input_data = case.get("input")
                recipe = (
                    input_data.get("metadata_gap_recipe")
                    if isinstance(input_data, dict)
                    else None
                )
                if not self.require(
                    isinstance(input_data, dict)
                    and isinstance(recipe, dict)
                    and isinstance(recipe.get("container_prefix"), str)
                    and self.is_int(recipe.get("container_count"))
                    and isinstance(recipe.get("field"), str),
                    path,
                    f"{context}.input",
                    "must provide an exact maximum-catalogue metadata-gap "
                    "recipe",
                ):
                    continue
                metadata_gaps = [
                    f"{recipe['container_prefix']}{index:04d}."
                    f"{recipe['field']}"
                    for index in range(recipe["container_count"])
                ]
                warning = OBSERVATION_WARNING_BY_REASON.get(
                    input_data.get("reason_code")
                )
                warnings = [warning] if isinstance(warning, str) else []
                serialized = json.dumps(
                    warnings,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                self.require(
                    input_data.get("reason_code")
                    == "required_field_missing"
                    and recipe
                    == {
                        "container_prefix": "fixture-",
                        "container_count": 4096,
                        "field": "full_image_reference",
                    }
                    and len(metadata_gaps)
                    == oracle.get("exact_metadata_gap_count")
                    == 4096
                    and metadata_gaps
                    == sorted(
                        set(metadata_gaps),
                        key=lambda gap: gap.encode("ascii"),
                    )
                    and all(
                        CONTAINER_NAME_RE.fullmatch(
                            gap.rsplit(".", 1)[0]
                        )
                        is not None
                        for gap in metadata_gaps
                    )
                    and warnings
                    == oracle.get("exact_warnings")
                    == [
                        "Required container evidence is missing; inspect "
                        "metadata_gaps"
                    ]
                    and len(warnings)
                    == oracle.get("exact_warning_count")
                    == 1
                    and len(warning.encode("ascii"))
                    == oracle.get("exact_warning_item_bytes")
                    == 61
                    and len(serialized)
                    == oracle.get("exact_serialized_warning_bytes")
                    == 65
                    and len(warnings) <= 64
                    and len(serialized) <= 8192
                    and all(
                        gap.rsplit(".", 1)[0] not in warning
                        for gap in metadata_gaps
                    )
                    and oracle.get(
                        "observed_identifiers_interpolated"
                    )
                    is False
                    and oracle.get(
                        "metadata_gaps_retain_exact_detail"
                    )
                    is True,
                    path,
                    context,
                    "4096 distinct metadata gaps must aggregate to one fixed "
                    "identifier-free warning while preserving every exact "
                    "machine-readable gap",
                )
            elif (
                case_id
                == "comparable_post_includes_changed_and_unchanged_rows"
            ):
                input_data = case.get("input")
                if not self.require(
                    isinstance(input_data, dict),
                    path,
                    f"{context}.input",
                    "must be a mapping",
                ):
                    continue
                machine_result = input_data.get("machine_result")
                report_model = oracle.get("exact_report_model")
                rendered = oracle.get("exact_ascii_rendered_block")
                if not self.require(
                    isinstance(machine_result, dict)
                    and isinstance(report_model, dict)
                    and isinstance(rendered, str)
                    and bool(rendered),
                    path,
                    context,
                    "must bind a canonical machine result to an exact report "
                    "model and non-empty ASCII golden block",
                ):
                    continue

                exact_v1_fields = (
                    self.schema.get("oracle", {}).get(
                        "machine_result_exact_v1_fields"
                    )
                )
                normative_v1_fields = [
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
                ]
                self.require(
                    exact_v1_fields == normative_v1_fields
                    and len(set(exact_v1_fields)) == 18
                    and set(machine_result) == set(exact_v1_fields),
                    path,
                    f"{context}.input.machine_result",
                    "successful v1 public output must expose exactly the "
                    "18 normative keys, including explicit null fields and "
                    "no unknown keys",
                )

                observation = machine_result.get("observation")
                machine_delta = machine_result.get("run_window_delta")
                between_delta = machine_result.get(
                    "between_observation_delta"
                )
                baseline = machine_result.get("baseline")
                model_table = report_model.get("primary_table")
                machine_changes = (
                    machine_delta.get("changes")
                    if isinstance(machine_delta, dict)
                    else None
                )
                model_rows = (
                    model_table.get("rows")
                    if isinstance(model_table, dict)
                    else None
                )
                if not self.require(
                    isinstance(observation, dict)
                    and isinstance(machine_changes, list)
                    and bool(machine_changes)
                    and all(
                        isinstance(change, dict)
                        and isinstance(change.get("before"), dict)
                        and isinstance(change.get("after"), dict)
                        and isinstance(
                            change["before"].get("full_image_reference"), str
                        )
                        and isinstance(
                            change["after"].get("full_image_reference"), str
                        )
                        and isinstance(
                            change["before"].get("runtime_state"), str
                        )
                        and isinstance(
                            change["after"].get("runtime_state"), str
                        )
                        for change in machine_changes
                    )
                    and isinstance(model_rows, list)
                    and all(
                        isinstance(row, dict)
                        and isinstance(row.get("cells"), dict)
                        for row in model_rows
                    ),
                    path,
                    context,
                    "machine delta and model rows must be concrete lists",
                ):
                    continue
                self.validate_observation(
                    path,
                    f"{context}.input.machine_result.observation",
                    observation,
                )
                def has_exact_model_keys(
                    value: Any, model_name: str
                ) -> bool:
                    expected = EXACT_REPORT_MODEL_FIELDS.get(model_name)
                    if expected is None:
                        expected = EXACT_CORE_MODEL_FIELDS.get(
                            model_name, []
                        )
                    return (
                        isinstance(value, dict)
                        and set(value) == set(expected)
                        and len(value) == len(expected)
                    )

                exact_nested_shape = (
                    has_exact_model_keys(observation, "observation")
                    and has_exact_model_keys(
                        observation.get("scope"), "scope"
                    )
                    and observation.get("discovery_backend")
                    == "docker_cli_v1"
                    and all(
                        has_exact_model_keys(
                            container, "container_observation"
                        )
                        for container in observation.get(
                            "containers", {}
                        ).values()
                    )
                    and has_exact_model_keys(
                        between_delta, "delta_result"
                    )
                    and has_exact_model_keys(
                        machine_delta, "delta_result"
                    )
                    and all(
                        has_exact_model_keys(change, "container_delta")
                        and (
                            change.get("before") is None
                            or has_exact_model_keys(
                                change.get("before"),
                                "container_observation",
                            )
                        )
                        and (
                            change.get("after") is None
                            or has_exact_model_keys(
                                change.get("after"),
                                "container_observation",
                            )
                        )
                        for delta in (between_delta, machine_delta)
                        for change in delta.get("changes", [])
                    )
                    and all(
                        endpoint_scope is None
                        or has_exact_model_keys(endpoint_scope, "scope")
                        for delta in (between_delta, machine_delta)
                        for endpoint_scope in (
                            delta.get("from_scope"),
                            delta.get("to_scope"),
                        )
                    )
                    and has_exact_model_keys(
                        machine_result.get("baseline"),
                        "baseline_result",
                    )
                )
                self.require(
                    exact_nested_shape,
                    path,
                    f"{context}.input.machine_result",
                    "the successful public-result golden must recursively use "
                    "every exact v1 nested key and docker_cli_v1 evidence",
                )
                nested_warning_lists = [
                    (
                        observation.get("warnings", [])
                        if isinstance(observation, dict)
                        else []
                    ),
                    (
                        between_delta.get("warnings", [])
                        if isinstance(between_delta, dict)
                        else []
                    ),
                    (
                        machine_delta.get("warnings", [])
                        if isinstance(machine_delta, dict)
                        else []
                    ),
                ]
                expected_result_warnings = sorted(
                    {
                        warning
                        for warning_list in nested_warning_lists
                        for warning in warning_list
                    },
                    key=lambda warning: warning.encode("ascii"),
                )

                change_names = [
                    change.get("container_name") for change in machine_changes
                ]
                model_names = [
                    row.get("container_name") for row in model_rows
                ]
                observed = [
                    change.get("primary_kind") for change in machine_changes
                ]
                model_is_exact = (
                    len(model_rows) == len(machine_changes)
                    and all(
                        model_rows[index].get("container_name")
                        == change.get("container_name")
                        and model_rows[index].get("machine_before")
                        == change.get("before")
                        and model_rows[index].get("machine_after")
                        == change.get("after")
                        and model_rows[index].get("cells", {}).get(
                            "container"
                        )
                        == change.get("container_name")
                        and model_rows[index].get("cells", {}).get("change")
                        == expected_change_label(change)
                        for index, change in enumerate(machine_changes)
                    )
                )
                expected_counts: dict[str, int] = {
                    "total": len(machine_changes)
                }
                for change_kind in observed:
                    if isinstance(change_kind, str):
                        expected_counts[change_kind] = (
                            expected_counts.get(change_kind, 0) + 1
                        )
                expected_header = {
                    "host": input_data.get("host"),
                    "instance_id": machine_result.get("instance_id"),
                    "operation": machine_result.get("operation"),
                    "correlation_id": machine_result.get("correlation_id"),
                    "observed_at": observation.get("observed_at"),
                    "observation_status": observation.get("status"),
                    "simulated": machine_result.get("simulated"),
                    "replay_outcome": machine_result.get("replay_outcome"),
                }
                self.require(
                    input_data.get("operation") == "post"
                    and input_data.get("observation_status") == "complete"
                    and machine_result.get("schema_version") == 1
                    and machine_result.get("operation")
                    == input_data.get("operation")
                    and machine_result.get("instance_id")
                    == input_data.get("instance_id")
                    and machine_result.get("observation_status")
                    == input_data.get("observation_status")
                    and observation.get("status")
                    == input_data.get("observation_status")
                    and machine_result.get("scope_identity")
                    == observation.get("scope", {}).get("identity")
                    and isinstance(baseline, dict)
                    and machine_result.get("baseline_advanced")
                    is baseline.get("advanced")
                    and machine_result.get("correlation_id") is None
                    and machine_result.get("replay_outcome") is None
                    and machine_result.get("simulated") is False
                    and machine_result.get("skipped") is False
                    and machine_result.get("warnings")
                    == expected_result_warnings
                    and isinstance(between_delta, dict)
                    and between_delta.get("comparability")
                    == "exact"
                    and machine_delta.get("comparability") == "exact"
                    and change_names == model_names
                    and model_is_exact
                    and "unchanged" in observed
                    and any(value != "unchanged" for value in observed),
                    path,
                    f"{context}.input",
                    "canonical and presentation layers must preserve the same "
                    "changed-first, unchanged-inclusive delta",
                )
                self.require(
                    oracle.get("presentation_schema_version") == 1
                    and oracle.get("primary_table_kind") == "run_window"
                    and oracle.get("columns")
                    == ["CONTAINER", "BEFORE", "AFTER", "CHANGE"]
                    and oracle.get("row_names") == model_names
                    and oracle.get("unchanged_rows_included") is True
                    and oracle.get("table_blocks") == 1
                    and oracle.get("between_observation_outcome")
                    == "no_observed_difference"
                    and oracle.get(
                        "between_observation_summary_omitted"
                    )
                    is True
                    and oracle.get("causal_attribution") is False,
                    path,
                    f"{context}.oracle",
                    "comparable post output must render the complete run-window table",
                )
                self.require(
                    has_exact_model_keys(report_model, "report_model")
                    and has_exact_model_keys(
                        report_model.get("header"), "report_header"
                    )
                    and has_exact_model_keys(
                        model_table, "report_table"
                    )
                    and all(
                        has_exact_model_keys(row, "run_window_row")
                        and has_exact_model_keys(
                            row.get("cells"), "run_window_cells"
                        )
                        for row in model_rows
                    )
                    and report_model.get("presentation_schema_version") == 1
                    and report_model.get("header") == expected_header
                    and model_table.get("kind") == "run_window"
                    and model_table.get("columns")
                    == ["CONTAINER", "BEFORE", "AFTER", "CHANGE"]
                    and report_model.get("between_observation_summary") is None
                    and report_model.get("run_window_notice") is None
                    and report_model.get("counts") == expected_counts
                    and report_counts_are_exact(
                        model_table,
                        report_model.get("counts"),
                        primary_kinds=observed,
                    )
                    and report_model.get("warnings")
                    == machine_result.get("warnings")
                    and report_model.get("baseline_outcome")
                    == machine_result.get("baseline")
                    and report_model.get("journal_status")
                    == machine_result.get("journal_status")
                    and report_model.get("persistence_outcome")
                    == machine_result.get("persistence_outcome"),
                    path,
                    f"{context}.oracle.exact_report_model",
                    "report model metadata must be a lossless projection of "
                    "the committed canonical result",
                )

                model_cell_rows = [
                    [
                        row.get("cells", {}).get("container"),
                        row.get("cells", {}).get("before"),
                        row.get("cells", {}).get("after"),
                        row.get("cells", {}).get("change"),
                    ]
                    for row in model_rows
                ]
                expected_cell_rows = [
                    [
                        change.get("container_name"),
                        (
                            change.get("before", {})
                            .get("full_image_reference", "")
                            .rsplit("/", 1)[-1]
                            + " / "
                            + str(
                                change.get("before", {}).get(
                                    "runtime_state"
                                )
                            )
                        ),
                        (
                            change.get("after", {})
                            .get("full_image_reference", "")
                            .rsplit("/", 1)[-1]
                            + " / "
                            + str(
                                change.get("after", {}).get(
                                    "runtime_state"
                                )
                            )
                        ),
                        expected_change_label(change),
                    ]
                    for change in machine_changes
                ]
                rendered_lines = rendered.splitlines()
                report_width = input_data.get("report_width")
                renderer_projection = oracle.get("renderer_projection")
                container_labels = (
                    renderer_projection.get("exact_container_labels")
                    if isinstance(renderer_projection, dict)
                    else None
                )
                expected_container_labels = {
                    "fixture-api": "fixture-api",
                    "fixture-cache": "fixture-cache",
                }
                rendered_cell_rows = [
                    [
                        expected_container_labels.get(row[0], row[0]),
                        row[1],
                        row[2],
                        row[3],
                    ]
                    for row in model_cell_rows
                ]
                expected_footer = [
                    "Counts: image_changed=1, unchanged=1, total=2",
                    "Baseline: advanced "
                    "(obs-presentation-a -> obs-presentation-c)",
                    "Journal: complete | Persistence: committed",
                    "Warnings: none",
                ]
                expected_rendered_lines = [
                    "DAS v1 | host=fixture-a.example.com | "
                    "instance=fixture-mdad | operation=post",
                    "Observed 2026-07-30T12:00:02Z | status=complete",
                    *render_ascii_table(
                        ["CONTAINER", "BEFORE", "AFTER", "CHANGE"],
                        rendered_cell_rows,
                        [34, 28, 28, 17],
                    ),
                    *expected_footer,
                ]
                parsed_table_rows: list[list[str]] = []
                border_positions: list[int] = []
                rendered_shape_valid = len(rendered_lines) == 12
                if rendered_shape_valid:
                    border_positions = [
                        index
                        for index, character in enumerate(rendered_lines[2])
                        if character == "+"
                    ]
                    parsed_table_rows = [
                        [
                            cell.strip()
                            for cell in line[1:-1].split("|")
                        ]
                        for line in rendered_lines[3:7]
                        if line.startswith("|") and line.endswith("|")
                    ]
                aligned_table = (
                    rendered_shape_valid
                    and len(parsed_table_rows) == 3
                    and all(
                        len(rendered_lines[index]) == len(rendered_lines[2])
                        for index in range(2, 8)
                    )
                    and all(
                        [
                            position
                            for position, character in enumerate(
                                rendered_lines[index]
                            )
                            if character == "|"
                        ]
                        == border_positions
                        for index in (3, 5, 6)
                    )
                    and rendered_lines[2]
                    == rendered_lines[4]
                    == rendered_lines[7]
                )
                self.require(
                    rendered_shape_valid
                    and rendered_lines == expected_rendered_lines
                    and rendered_lines[:2]
                    == [
                        "DAS v1 | host=fixture-a.example.com | "
                        "instance=fixture-mdad | operation=post",
                        "Observed 2026-07-30T12:00:02Z | status=complete",
                    ]
                    and len(parsed_table_rows) == 3
                    and parsed_table_rows[0]
                    == ["CONTAINER", "BEFORE", "AFTER", "CHANGE"]
                    and model_cell_rows == expected_cell_rows
                    and parsed_table_rows[1:] == rendered_cell_rows
                    and renderer_projection
                    == {
                        "column_content_widths": [34, 28, 28, 17],
                        "separator_positions": [0, 37, 68, 99, 119],
                        "image_label_width": 15,
                        "exact_container_labels": expected_container_labels,
                        "opaque_markers": [],
                        "legend_entries": [],
                    }
                    and container_labels == expected_container_labels
                    and "<c" not in rendered
                    and "<i" not in rendered
                    and rendered_lines[-4:] == expected_footer
                    and aligned_table
                    and self.is_int(report_width)
                    and report_width == 120
                    and border_positions == [0, 37, 68, 99, 119]
                    and all(
                        len(rendered_lines[index]) == report_width
                        for index in range(2, 8)
                    )
                    and max(len(line) for line in rendered_lines)
                    <= report_width
                    and "\x1b" not in rendered
                    and "\\n" not in rendered
                    and all(
                        character == "\n"
                        or 32 <= ord(character) <= 126
                        for character in rendered
                    ),
                    path,
                    f"{context}.oracle.exact_ascii_rendered_block",
                    "ASCII golden bytes must exactly encode the report-model "
                    "header, rows, counts, persistence, and alignment",
                )
            elif case_id == "complete_all_removals_still_render_rows":
                input_data = case.get("input", {})
                before_names = input_data.get("before_names")
                changes = input_data.get("changes")
                self.require(
                    input_data.get("operation") == "post"
                    and input_data.get("observation_status") == "complete"
                    and isinstance(before_names, list)
                    and bool(before_names)
                    and input_data.get("after_names") == []
                    and isinstance(changes, dict)
                    and set(changes) == set(before_names)
                    and set(changes.values()) == {"removed"},
                    path,
                    f"{context}.input",
                    "complete removal input must identify every removed row",
                )
                self.require(
                    oracle.get("primary_table_kind") == "run_window"
                    and oracle.get("row_names") == before_names
                    and oracle.get("after_marker") == "<absent>"
                    and oracle.get("removed_row_count") == len(before_names)
                    and oracle.get(
                        "generic_no_match_replacement_forbidden"
                    )
                    is True
                    and oracle.get("table_blocks") == 1,
                    path,
                    f"{context}.oracle",
                    "complete removals must remain explicit table rows",
                )
            elif case_id == "complete_empty_renders_explicit_zero_row_table":
                input_data = case.get("input", {})
                messages = oracle.get("minimum_messages")
                self.require(
                    input_data.get("operation") == "status"
                    and input_data.get("observation_status") == "complete"
                    and input_data.get("current_names") == []
                    and input_data.get(
                        "complete_run_window_endpoint_names"
                    )
                    == {"before": [], "after": []}
                    and oracle.get("primary_table_kind") == "current"
                    and oracle.get("row_count") == 0
                    and oracle.get("empty_catalogue_authoritative") is True
                    and messages
                    == ["No containers observed in complete scope"]
                    and oracle.get("exact_empty_table_messages")
                    == {
                        "current": (
                            "No containers observed in complete scope"
                        ),
                        "run_window": (
                            "No containers observed in either complete "
                            "run-window endpoint"
                        ),
                        "known_endpoint": None,
                    }
                    and oracle.get("table_blocks") == 1,
                    path,
                    context,
                    "complete empty status must render an authoritative zero-row table",
                )
            elif (
                case_id
                == "incomplete_endpoint_shows_known_state_without_absence"
            ):
                input_data = case.get("input")
                if not self.require(
                    isinstance(input_data, dict),
                    path,
                    f"{context}.input",
                    "must be a mapping",
                ):
                    continue
                machine_result = input_data.get("machine_result")
                exact_rows = oracle.get("exact_known_rows")
                report_model = oracle.get("exact_report_model")
                if not self.require(
                    isinstance(machine_result, dict)
                    and isinstance(exact_rows, list)
                    and isinstance(report_model, dict)
                    and all(
                        isinstance(row, dict)
                        and isinstance(row.get("cells"), dict)
                        for row in exact_rows
                    ),
                    path,
                    context,
                    "partial presentation must bind a canonical result to "
                    "concrete known-endpoint rows",
                ):
                    continue
                observation = machine_result.get("observation")
                delta = machine_result.get("run_window_delta")
                containers = (
                    observation.get("containers")
                    if isinstance(observation, dict)
                    else None
                )
                if not self.require(
                    isinstance(observation, dict)
                    and isinstance(delta, dict)
                    and isinstance(containers, dict),
                    path,
                    f"{context}.input.machine_result",
                    "partial result must contain an observation, suppressed "
                    "delta, and known container mapping",
                ):
                    continue
                self.validate_observation(
                    path,
                    f"{context}.input.machine_result.observation",
                    observation,
                )
                messages = oracle.get("minimum_messages")
                known_names = input_data.get("known_post_names")
                gap_names = input_data.get(
                    "names_missing_required_evidence"
                )
                row_names = [
                    row.get("container_name") for row in exact_rows
                ]
                exact_row_order = oracle.get("exact_row_order")
                missing_cell = oracle.get("missing_evidence_cell")
                worker = containers.get("fixture-worker")
                expected_baseline = machine_result.get("baseline")
                report_table = report_model.get("primary_table")
                report_header = report_model.get("header")
                expected_report_warnings = sorted(
                    {
                        *observation.get("warnings", []),
                        REPORT_PRESENTATION_WARNING_BY_STATUS["partial"],
                    },
                    key=lambda warning: warning.encode("ascii"),
                )
                def has_model_keys(value: Any, model_name: str) -> bool:
                    exact_fields = EXACT_REPORT_MODEL_FIELDS.get(
                        model_name, []
                    )
                    return (
                        isinstance(value, dict)
                        and set(value) == set(exact_fields)
                        and len(value) == len(exact_fields)
                    )

                self.require(
                    input_data.get("operation") == "post"
                    and input_data.get("pre_status") == "complete"
                    and input_data.get("post_status") == "partial"
                    and machine_result.get("schema_version") == 1
                    and machine_result.get("operation") == "post"
                    and machine_result.get("instance_id")
                    == input_data.get("instance_id")
                    and machine_result.get("observation_status") == "partial"
                    and observation.get("status") == "partial"
                    and isinstance(known_names, list)
                    and known_names == sorted(containers)
                    and isinstance(gap_names, list)
                    and gap_names == ["fixture-worker"]
                    and observation.get("metadata_gaps")
                    == ["fixture-worker.full_image_reference"]
                    and isinstance(worker, dict)
                    and worker.get("full_image_reference") is None
                    and delta.get("comparability") == "incomplete"
                    and delta.get("changes") == []
                    and delta.get("warnings") == []
                    and oracle.get("primary_table_kind")
                    == "known_endpoint"
                    and oracle.get("authoritative_comparison_rows") == 0
                    and oracle.get("absent_markers_inferred") is False
                    and oracle.get("exact_columns")
                    == ["CONTAINER", "IMAGE", "STATE"]
                    and row_names
                    == exact_row_order
                    == known_names
                    and exact_rows
                    == [
                        {
                            "container_name": "fixture-api",
                            "machine_current": containers.get("fixture-api"),
                            "cells": {
                                "container": "fixture-api",
                                "image": "api:v2",
                                "state": "running",
                            },
                        },
                        {
                            "container_name": "fixture-worker",
                            "machine_current": containers.get("fixture-worker"),
                            "cells": {
                                "container": "fixture-worker",
                                "image": "<unknown>",
                                "state": "stopped",
                            },
                        },
                    ]
                    and missing_cell
                    == {
                        "container_name": "fixture-worker",
                        "column": "IMAGE",
                        "rendered_marker": "<unknown>",
                    }
                    and oracle.get("endpoint_not_observed_token_used")
                    is False
                    and oracle.get("comparison_rows_synthesized") is False
                    and oracle.get("counts")
                    == {
                        "known_rows": len(containers),
                        "rows_with_required_gaps": len(gap_names),
                        "authoritative_changes": 0,
                    }
                    and oracle.get("baseline_outcome")
                    == expected_baseline
                    and oracle.get("journal_status")
                    == machine_result.get("journal_status")
                    and oracle.get("persistence_outcome")
                    == machine_result.get("persistence_outcome")
                    and has_model_keys(report_model, "report_model")
                    and has_model_keys(report_header, "report_header")
                    and report_header
                    == {
                        "host": input_data.get("host"),
                        "instance_id": input_data.get("instance_id"),
                        "operation": input_data.get("operation"),
                        "observed_at": observation.get("observed_at"),
                        "observation_status": observation.get("status"),
                        "correlation_id": None,
                        "simulated": machine_result.get("simulated"),
                        "replay_outcome": machine_result.get(
                            "replay_outcome"
                        ),
                    }
                    and has_model_keys(report_table, "report_table")
                    and report_table.get("kind") == "known_endpoint"
                    and report_table.get("columns")
                    == ["CONTAINER", "IMAGE", "STATE"]
                    and report_table.get("rows") == exact_rows
                    and all(
                        has_model_keys(row, "endpoint_row")
                        and has_model_keys(
                            row.get("cells"), "endpoint_cells"
                        )
                        for row in exact_rows
                    )
                    and report_model.get(
                        "between_observation_summary"
                    )
                    is None
                    and has_model_keys(
                        report_model.get("run_window_notice"),
                        "report_notice",
                    )
                    and report_model.get("run_window_notice")
                    == {
                        "comparability": "incomplete",
                        "message": "Run-window comparison unavailable",
                    }
                    and report_model.get("counts")
                    == oracle.get("counts")
                    and report_counts_are_exact(
                        report_table,
                        report_model.get("counts"),
                    )
                    and report_model.get("warnings")
                    == expected_report_warnings
                    and report_model.get("warnings")
                    == sorted(
                        set(report_model.get("warnings", [])),
                        key=lambda warning: warning.encode("ascii"),
                    )
                    and report_model.get("baseline_outcome")
                    == expected_baseline
                    and report_model.get("journal_status")
                    == machine_result.get("journal_status")
                    and report_model.get("persistence_outcome")
                    == machine_result.get("persistence_outcome")
                    and messages
                    == [
                        "Observation partial: known rows only; absence is not "
                        "authoritative.",
                    ]
                    and oracle.get("table_blocks") == 1,
                    path,
                    context,
                    "partial endpoints must project only known canonical state, "
                    "mark missing evidence, and infer no absence or delta",
                )
                projection = oracle.get("renderer_projection")
                golden = oracle.get("exact_ascii_rendered_block")
                widths = [34, 46, 10]
                expected_lines = [
                    "DAS v1 | host=fixture-partial.example.com | "
                    "instance=fixture-mdad | operation=post",
                    "Observed 2026-07-30T12:10:02Z | status=partial",
                    *render_ascii_table(
                        ["CONTAINER", "IMAGE", "STATE"],
                        [
                            ["fixture-api", "api:v2", "running"],
                            ["fixture-worker", "<unknown>", "stopped"],
                        ],
                        widths,
                    ),
                    "Run-window comparison unavailable",
                    "Counts: authoritative_changes=0, known_rows=2, "
                    "rows_with_required_gaps=1",
                    "Baseline: unchanged "
                    "(obs-presentation-partial-a -> "
                    "obs-presentation-partial-a)",
                    "Journal: incomplete_post | Persistence: committed",
                    "Warnings: Observation partial: known rows only; absence "
                    "is not authoritative.",
                    "  Required container evidence is missing; inspect "
                    "metadata_gaps",
                ]
                self.require(
                    input_data.get("report_width") == 100
                    and projection
                    == {
                        "column_content_widths": widths,
                        "separator_positions": [0, 37, 86, 99],
                    }
                    and isinstance(golden, str)
                    and golden.splitlines() == expected_lines
                    and all(len(line) <= 100 for line in expected_lines)
                    and all(
                        len(line) == 100
                        for line in expected_lines[2:8]
                    ),
                    path,
                    f"{context}.oracle.exact_ascii_rendered_block",
                    "partial output must have exact 100-column known-endpoint "
                    "geometry and preserve its safe warning",
                )
            elif case_id == "between_observation_summary_is_exact":
                input_data = case.get("input", {})
                delta = input_data.get("between_observation_delta")
                summary = oracle.get("exact_between_observation_summary")
                if not self.require(
                    isinstance(delta, dict) and isinstance(summary, dict),
                    path,
                    context,
                    "between-observation summary requires a canonical delta "
                    "and an exact non-null notice",
                ):
                    continue
                expected_delta_fields = EXACT_CORE_MODEL_FIELDS[
                    "delta_result"
                ]
                expected_notice_fields = EXACT_REPORT_MODEL_FIELDS[
                    "report_notice"
                ]
                changes = delta.get("changes")
                summary_variants = input_data.get("summary_variants")
                summary_kind_label_inputs = input_data.get(
                    "summary_kind_label_inputs"
                )
                expected_kind_label_inputs = {
                    "image_reference_only": {
                        "primary_kind": "image_changed",
                        "image_reference_changed": True,
                        "image_content_changed": False,
                    },
                    "image_content_only": {
                        "primary_kind": "image_changed",
                        "image_reference_changed": False,
                        "image_content_changed": True,
                    },
                    "image_reference_and_content": {
                        "primary_kind": "image_changed",
                        "image_reference_changed": True,
                        "image_content_changed": True,
                    },
                    "recreated_without_image_change": {
                        "primary_kind": "recreated",
                        "image_reference_changed": False,
                        "image_content_changed": False,
                    },
                    "recreated_reference_only": {
                        "primary_kind": "recreated",
                        "image_reference_changed": True,
                        "image_content_changed": False,
                    },
                    "recreated_content_only": {
                        "primary_kind": "recreated",
                        "image_reference_changed": False,
                        "image_content_changed": True,
                    },
                    "recreated_reference_and_content": {
                        "primary_kind": "recreated",
                        "image_reference_changed": True,
                        "image_content_changed": True,
                    },
                }
                computed_kind_labels = (
                    {
                        variant_id: expected_change_label(change)
                        for variant_id, change in (
                            summary_kind_label_inputs.items()
                        )
                    }
                    if isinstance(summary_kind_label_inputs, dict)
                    else {}
                )
                summary_label_order = [
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
                ]
                multi_label_changes = input_data.get(
                    "multi_label_summary_changes"
                )
                multi_labels = (
                    [
                        expected_change_label(change)
                        for change in multi_label_changes
                    ]
                    if isinstance(multi_label_changes, list)
                    and all(
                        isinstance(change, dict)
                        for change in multi_label_changes
                    )
                    else []
                )
                ordered_multi_labels = [
                    label
                    for label in summary_label_order
                    if label in set(multi_labels)
                    and label != "unchanged"
                ]
                multi_label_summary = (
                    f"Before run window: {len(multi_labels)} observed "
                    f"differences ({', '.join(ordered_multi_labels)})"
                )
                expected_summary_matrix = {
                    "exact_no_change": None,
                    "degraded_no_change": {
                        "comparability": "degraded",
                        "message": (
                            "Before run window: no observed difference; "
                            "restart evidence incomplete"
                        ),
                    },
                    "degraded_material": {
                        "comparability": "degraded",
                        "message": (
                            "Before run window: 1 observed difference "
                            "(ref changed); restart evidence incomplete"
                        ),
                    },
                    "no_baseline": {
                        "comparability": "no_baseline",
                        "message": (
                            "Before run window: no previous complete "
                            "observation"
                        ),
                    },
                    "incomplete": {
                        "comparability": "incomplete",
                        "message": (
                            "Before run window: comparison unavailable "
                            "because one or both endpoints are incomplete"
                        ),
                    },
                    "incompatible_scope": {
                        "comparability": "incompatible_scope",
                        "message": (
                            "Before run window: scopes are incompatible; no "
                            "additions or removals inferred"
                        ),
                    },
                }
                self.require(
                    set(delta) == set(expected_delta_fields)
                    and delta.get("comparability") == "exact"
                    and delta.get("comparison_schema_version") == 1
                    and isinstance(changes, list)
                    and len(changes) == 1
                    and changes[0].get("primary_kind") == "image_changed"
                    and changes[0].get("kinds") == ["image_changed"]
                    and changes[0].get("image_reference_changed") is True
                    and changes[0].get("image_content_changed") is False
                    and expected_change_label(changes[0]) == "ref changed"
                    and set(summary) == set(expected_notice_fields)
                    and summary
                    == {
                        "comparability": "exact",
                        "message": "Before run window: 1 observed difference "
                        "(ref changed)",
                    }
                    and oracle.get("exact_rendered_line")
                    == summary.get("message")
                    and oracle.get("run_window_notice") is None
                    and oracle.get("causal_attribution") is False,
                    path,
                    context,
                    "a non-null A-to-B summary must have an exact closed "
                    "shape, stable wording, and no causal attribution",
                )
                self.require(
                    summary_variants
                    == {
                        "exact_no_change": {
                            "comparability": "exact",
                            "material_primary_kinds": [],
                            "material_human_kind_labels": [],
                        },
                        "degraded_no_change": {
                            "comparability": "degraded",
                            "material_primary_kinds": [],
                            "material_human_kind_labels": [],
                        },
                        "degraded_material": {
                            "comparability": "degraded",
                            "material_primary_kinds": ["image_changed"],
                            "material_human_kind_labels": ["ref changed"],
                        },
                        "no_baseline": {
                            "comparability": "no_baseline",
                            "material_primary_kinds": [],
                            "material_human_kind_labels": [],
                        },
                        "incomplete": {
                            "comparability": "incomplete",
                            "material_primary_kinds": [],
                            "material_human_kind_labels": [],
                        },
                        "incompatible_scope": {
                            "comparability": "incompatible_scope",
                            "material_primary_kinds": [],
                            "material_human_kind_labels": [],
                        },
                    }
                    and summary_kind_label_inputs
                    == expected_kind_label_inputs
                    and oracle.get("exact_summary_kind_labels")
                    == computed_kind_labels
                    == {
                        "image_reference_only": "ref changed",
                        "image_content_only": "img changed",
                        "image_reference_and_content": "img+ref changed",
                        "recreated_without_image_change": "recreated",
                        "recreated_reference_only": "recreated+ref",
                        "recreated_content_only": "recreated+img",
                        "recreated_reference_and_content": (
                            "recreated+img+ref"
                        ),
                    }
                    and oracle.get("exact_summary_label_order")
                    == summary_label_order
                    and multi_labels
                    == [
                        "ref changed",
                        "recreated+img+ref",
                        "img changed",
                        "recreated",
                        "img+ref changed",
                        "recreated+ref",
                        "recreated+img",
                    ]
                    and len(set(multi_labels)) == len(multi_labels) == 7
                    and ordered_multi_labels
                    == [
                        "recreated",
                        "recreated+img",
                        "recreated+ref",
                        "recreated+img+ref",
                        "img changed",
                        "ref changed",
                        "img+ref changed",
                    ]
                    and oracle.get("exact_multi_label_summary")
                    == multi_label_summary
                    == "Before run window: 7 observed differences "
                    "(recreated, recreated+img, recreated+ref, "
                    "recreated+img+ref, img changed, ref changed, "
                    "img+ref changed)"
                    and oracle.get("exact_summary_matrix")
                    == expected_summary_matrix
                    and all(
                        notice is None
                        or set(notice) == set(expected_notice_fields)
                        for notice in expected_summary_matrix.values()
                    ),
                    path,
                    f"{context}.oracle.exact_summary_matrix",
                    "every between-observation comparability must map to one "
                    "exact summary or deliberate null",
                )
            elif case_id == "degraded_run_window_notice_is_exact":
                input_data = case.get("input", {})
                delta = input_data.get("run_window_delta")
                changes = (
                    delta.get("changes")
                    if isinstance(delta, dict)
                    else None
                )
                notice = oracle.get("exact_run_window_notice")
                self.require(
                    input_data.get("operation") == "post"
                    and input_data.get("observation_status") == "complete"
                    and isinstance(delta, dict)
                    and delta.get("comparability") == "degraded"
                    and delta.get("warnings") == []
                    and changes
                    == [
                        {
                            "container_name": "fixture-api",
                            "primary_kind": "unchanged",
                            "kinds": ["unchanged"],
                        }
                    ]
                    and oracle.get("primary_table_kind") == "run_window"
                    and oracle.get("run_window_table_retained") is True
                    and notice
                    == {
                        "comparability": "degraded",
                        "message": (
                            "Run-window comparison degraded: restart "
                            "evidence incomplete"
                        ),
                    }
                    and set(notice)
                    == set(
                        EXACT_REPORT_MODEL_FIELDS["report_notice"]
                    )
                    and oracle.get("exact_rendered_line")
                    == notice.get("message")
                    and oracle.get("restarted_inferred") is False
                    and oracle.get("unchanged_row_retained") is True,
                    path,
                    context,
                    "degraded B-to-C evidence must retain its authoritative "
                    "table while rendering one exact restart-certainty "
                    "notice",
                )
            elif case_id == "unavailable_endpoint_renders_no_invented_rows":
                input_data = case.get("input")
                report_model = oracle.get("exact_report_model")
                if not self.require(
                    isinstance(input_data, dict)
                    and isinstance(report_model, dict),
                    path,
                    context,
                    "unavailable presentation requires canonical input and "
                    "an exact report model",
                ):
                    continue
                machine_result = input_data.get("machine_result")
                observation = (
                    machine_result.get("observation")
                    if isinstance(machine_result, dict)
                    else None
                )
                delta = (
                    machine_result.get("run_window_delta")
                    if isinstance(machine_result, dict)
                    else None
                )
                model_table = report_model.get("primary_table")
                if not self.require(
                    isinstance(machine_result, dict)
                    and isinstance(observation, dict)
                    and isinstance(delta, dict)
                    and isinstance(model_table, dict),
                    path,
                    context,
                    "unavailable fixture layers must all be mappings",
                ):
                    continue
                self.validate_observation(
                    path,
                    f"{context}.input.machine_result.observation",
                    observation,
                )
                def has_model_keys(value: Any, model_name: str) -> bool:
                    exact_fields = EXACT_REPORT_MODEL_FIELDS.get(
                        model_name, []
                    )
                    return (
                        isinstance(value, dict)
                        and set(value) == set(exact_fields)
                        and len(value) == len(exact_fields)
                    )

                expected_header = {
                    "host": input_data.get("host"),
                    "instance_id": machine_result.get("instance_id"),
                    "operation": machine_result.get("operation"),
                    "correlation_id": machine_result.get("correlation_id"),
                    "observed_at": observation.get("observed_at"),
                    "observation_status": observation.get("status"),
                    "simulated": machine_result.get("simulated"),
                    "replay_outcome": machine_result.get("replay_outcome"),
                }
                expected_report_warnings = sorted(
                    {
                        *observation.get("warnings", []),
                        REPORT_PRESENTATION_WARNING_BY_STATUS[
                            "unavailable"
                        ],
                    },
                    key=lambda warning: warning.encode("ascii"),
                )
                self.require(
                    input_data.get("operation") == "post"
                    and input_data.get("post_status") == "unavailable"
                    and machine_result.get("schema_version") == 1
                    and machine_result.get("operation") == "post"
                    and machine_result.get("instance_id")
                    == input_data.get("instance_id")
                    and machine_result.get("observation_status")
                    == "unavailable"
                    and observation.get("status") == "unavailable"
                    and observation.get("containers") is None
                    and observation.get("metadata_gaps")
                    == ["docker.catalogue"]
                    and observation.get("warnings")
                    == ["Docker daemon was unreachable"]
                    and delta.get("comparability") == "incomplete"
                    and delta.get("changes") == []
                    and has_model_keys(report_model, "report_model")
                    and has_model_keys(
                        report_model.get("header"), "report_header"
                    )
                    and has_model_keys(model_table, "report_table")
                    and has_model_keys(
                        report_model.get("run_window_notice"),
                        "report_notice",
                    )
                    and report_model.get("presentation_schema_version") == 1
                    and report_model.get("header") == expected_header
                    and model_table
                    == {
                        "kind": "known_endpoint",
                        "columns": ["CONTAINER", "IMAGE", "STATE"],
                        "rows": [],
                    }
                    and report_model.get("between_observation_summary") is None
                    and report_model.get("run_window_notice")
                    == {
                        "comparability": "incomplete",
                        "message": "Run-window comparison unavailable",
                    }
                    and report_model.get("counts")
                    == {
                        "known_rows": 0,
                        "rows_with_required_gaps": 0,
                        "authoritative_changes": 0,
                    }
                    and report_counts_are_exact(
                        model_table,
                        report_model.get("counts"),
                    )
                    and report_model.get("warnings")
                    == expected_report_warnings
                    and report_model.get("warnings")
                    == sorted(
                        set(report_model.get("warnings", [])),
                        key=lambda warning: warning.encode("ascii"),
                    )
                    and report_model.get("baseline_outcome")
                    == machine_result.get("baseline")
                    and report_model.get("journal_status")
                    == machine_result.get("journal_status")
                    and report_model.get("persistence_outcome")
                    == machine_result.get("persistence_outcome")
                    and oracle.get("absence_markers_inferred") is False
                    and oracle.get(
                        "before_endpoint_rows_recast_as_removed"
                    )
                    is False
                    and oracle.get("after_endpoint_rows_invented") is False
                    and oracle.get("table_blocks") == 1,
                    path,
                    context,
                    "unavailable observations must render an empty known-endpoint "
                    "model without inventing or recasting container rows",
                )
                projection = oracle.get("renderer_projection")
                golden = oracle.get("exact_ascii_rendered_block")
                widths = [34, 46, 10]
                expected_lines = [
                    "DAS v1 | host=fixture-unavailable.example.com | "
                    "instance=fixture-mdad | operation=post",
                    "Observed 2026-07-30T12:20:02Z | status=unavailable",
                    *render_ascii_table(
                        ["CONTAINER", "IMAGE", "STATE"],
                        [],
                        widths,
                    ),
                    "Run-window comparison unavailable",
                    "Counts: authoritative_changes=0, known_rows=0, "
                    "rows_with_required_gaps=0",
                    "Baseline: unchanged "
                    "(obs-presentation-unavailable-a -> "
                    "obs-presentation-unavailable-a)",
                    "Journal: incomplete_post | Persistence: committed",
                    "Warnings: Docker daemon was unreachable",
                    "  Observation unavailable: no container state observed; "
                    "absence is not authoritative.",
                ]
                self.require(
                    input_data.get("report_width") == 100
                    and projection
                    == {
                        "column_content_widths": widths,
                        "separator_positions": [0, 37, 86, 99],
                    }
                    and isinstance(golden, str)
                    and golden.splitlines() == expected_lines
                    and all(len(line) <= 100 for line in expected_lines)
                    and all(
                        len(line) == 100
                        for line in expected_lines[2:6]
                    ),
                    path,
                    f"{context}.oracle.exact_ascii_rendered_block",
                    "unavailable output must have exact empty-table geometry "
                    "without invented rows and retain its safe reason",
                )
            elif case_id == "status_uses_current_state_columns":
                input_data = case.get("input", {})
                current_names = input_data.get("current_names")
                self.require(
                    input_data.get("operation") == "status"
                    and input_data.get("observation_status") == "complete"
                    and isinstance(current_names, list)
                    and oracle.get("primary_table_kind") == "current"
                    and oracle.get("columns")
                    == ["CONTAINER", "IMAGE", "STATE"]
                    and oracle.get("before_column_present") is False
                    and oracle.get("after_column_present") is False
                    and oracle.get("current_row_count") == len(current_names)
                    and oracle.get("table_blocks") == 1,
                    path,
                    context,
                    "status must use current-state columns only",
                )
            elif case_id == "baseline_null_endpoint_rendering_is_exact":
                variants = case.get("input", {}).get("variants")
                exact_lines = oracle.get("exact_lines")
                expected_variants = {
                    "not_applicable": None,
                    "uninitialized_pre": {
                        "advanced": False,
                        "before": None,
                        "after": None,
                    },
                    "first_complete_post": {
                        "advanced": True,
                        "before": None,
                        "after": "obs-first-complete-post",
                    },
                }

                def baseline_endpoint(value: Any) -> str:
                    return "<none>" if value is None else value

                computed_lines: dict[str, str] = {}
                if isinstance(variants, dict):
                    for variant_id, baseline in variants.items():
                        if baseline is None:
                            computed_lines[variant_id] = (
                                "Baseline: not applicable"
                            )
                            continue
                        if not isinstance(baseline, dict):
                            continue
                        disposition = (
                            "advanced"
                            if baseline.get("advanced") is True
                            else "unchanged"
                        )
                        computed_lines[variant_id] = (
                            f"Baseline: {disposition} "
                            f"({baseline_endpoint(baseline.get('before'))} -> "
                            f"{baseline_endpoint(baseline.get('after'))})"
                        )

                self.require(
                    variants == expected_variants
                    and exact_lines
                    == computed_lines
                    == {
                        "not_applicable": "Baseline: not applicable",
                        "uninitialized_pre": (
                            "Baseline: unchanged (<none> -> <none>)"
                        ),
                        "first_complete_post": (
                            "Baseline: advanced "
                            "(<none> -> obs-first-complete-post)"
                        ),
                    }
                    and oracle.get("null_endpoint_token") == "<none>"
                    and oracle.get(
                        "implementation_language_null_tokens_forbidden"
                    )
                    is True
                    and all(
                        "None" not in line
                        and " null" not in line
                        and "( ->" not in line
                        and "-> )" not in line
                        for line in computed_lines.values()
                    ),
                    path,
                    context,
                    "baseline null objects and null endpoint IDs must have "
                    "distinct language-independent exact renderings",
                )
            elif case_id == "table_selection_and_footer_matrix_is_exact":
                variants = case.get("input", {}).get("variants")
                projections = oracle.get("exact_projections")
                expected_variants = {
                    "each_complete_pre": {
                        "operation": "pre",
                        "report_mode": "each",
                        "observed_at": "2026-07-30T12:40:00Z",
                        "observation_status": "complete",
                        "pairing_state": "pre",
                        "run_window_comparability": None,
                        "simulated": False,
                        "replay_outcome": None,
                        "known_rows": 1,
                        "rows_with_required_gaps": 0,
                        "baseline_outcome": {
                            "advanced": False,
                            "before": "obs-matrix-a",
                            "after": "obs-matrix-a",
                        },
                        "journal_status": "open",
                        "persistence_outcome": "committed",
                        "warnings": [],
                    },
                    "complete_status": {
                        "operation": "status",
                        "report_mode": "final",
                        "observed_at": "2026-07-30T12:40:01Z",
                        "observation_status": "complete",
                        "pairing_state": "status",
                        "run_window_comparability": None,
                        "simulated": False,
                        "replay_outcome": None,
                        "known_rows": 1,
                        "rows_with_required_gaps": 0,
                        "baseline_outcome": None,
                        "journal_status": None,
                        "persistence_outcome": "not_attempted",
                        "warnings": [],
                    },
                    "scope_mismatched_post": {
                        "operation": "post",
                        "report_mode": "final",
                        "observed_at": "2026-07-30T12:40:02Z",
                        "observation_status": "complete",
                        "pairing_state": "matched_post",
                        "run_window_comparability": "incompatible_scope",
                        "simulated": False,
                        "replay_outcome": None,
                        "known_rows": 1,
                        "rows_with_required_gaps": 0,
                        "baseline_outcome": {
                            "advanced": True,
                            "before": "obs-matrix-a",
                            "after": "obs-matrix-c",
                        },
                        "journal_status": "scope_mismatch",
                        "persistence_outcome": "committed",
                        "warnings": [],
                    },
                    "post_only_complete": {
                        "operation": "post",
                        "report_mode": "final",
                        "observed_at": "2026-07-30T12:40:03Z",
                        "observation_status": "complete",
                        "pairing_state": "post_only",
                        "run_window_comparability": None,
                        "simulated": False,
                        "replay_outcome": None,
                        "known_rows": 1,
                        "rows_with_required_gaps": 0,
                        "baseline_outcome": {
                            "advanced": True,
                            "before": "obs-matrix-a",
                            "after": "obs-matrix-post-only",
                        },
                        "journal_status": "incomplete_pre",
                        "persistence_outcome": "committed",
                        "warnings": [],
                    },
                    "check_post_complete": {
                        "operation": "post",
                        "report_mode": "final",
                        "observed_at": "2026-07-30T12:40:04Z",
                        "observation_status": "complete",
                        "pairing_state": "simulation",
                        "run_window_comparability": None,
                        "simulated": True,
                        "replay_outcome": None,
                        "known_rows": 1,
                        "rows_with_required_gaps": 0,
                        "baseline_outcome": None,
                        "journal_status": None,
                        "persistence_outcome": "not_attempted",
                        "warnings": [],
                    },
                }
                computed_projections: dict[str, Any] = {}
                if isinstance(variants, dict):
                    for variant_id, variant in variants.items():
                        if not isinstance(variant, dict):
                            continue
                        comparability = variant.get(
                            "run_window_comparability"
                        )
                        status = variant.get("observation_status")
                        table_kind = (
                            "run_window"
                            if variant.get("operation") == "post"
                            and comparability in {"exact", "degraded"}
                            else "current"
                            if status == "complete"
                            else "known_endpoint"
                        )
                        counts = {
                            "authoritative_changes": 0,
                            "known_rows": variant.get("known_rows"),
                            "rows_with_required_gaps": variant.get(
                                "rows_with_required_gaps"
                            ),
                        }
                        pairing_state = variant.get("pairing_state")
                        notice = (
                            {
                                "comparability": "incompatible_scope",
                                "message": (
                                    "Scopes are incompatible; no additions or "
                                    "removals inferred"
                                ),
                            }
                            if comparability == "incompatible_scope"
                            else {
                                "comparability": "incomplete",
                                "message": (
                                    "Run-window comparison unavailable"
                                ),
                            }
                            if comparability == "incomplete"
                            else {
                                "comparability": "incomplete",
                                "message": (
                                    "Run-window comparison unavailable: no "
                                    "pre-observation was recorded"
                                ),
                            }
                            if pairing_state == "post_only"
                            else {
                                "comparability": "incomplete",
                                "message": (
                                    "Run-window comparison unavailable: "
                                    "check-mode simulation does not read "
                                    "retained state"
                                ),
                            }
                            if pairing_state == "simulation"
                            else None
                        )
                        observed_line = (
                            f"Observed {variant.get('observed_at')} | "
                            f"status={status}"
                        )
                        if variant.get("simulated") is True:
                            observed_line += " | mode=simulation"
                        if variant.get("replay_outcome") == "idempotent":
                            observed_line += " | replay=idempotent"
                        baseline = variant.get("baseline_outcome")
                        if baseline is None:
                            baseline_line = "Baseline: not applicable"
                        else:
                            disposition = (
                                "advanced"
                                if baseline.get("advanced") is True
                                else "unchanged"
                            )
                            baseline_line = (
                                f"Baseline: {disposition} "
                                f"({baseline.get('before')} -> "
                                f"{baseline.get('after')})"
                            )
                        journal = variant.get("journal_status")
                        journal_text = (
                            journal
                            if journal is not None
                            else "not applicable"
                        )
                        warnings = variant.get("warnings")
                        warning_line = (
                            "Warnings: none"
                            if warnings == []
                            else "Warnings: " + " | ".join(warnings)
                        )
                        computed_projections[variant_id] = {
                            "primary_table_kind": table_kind,
                            "exact_columns": [
                                "CONTAINER",
                                "IMAGE",
                                "STATE",
                            ],
                            "exact_observed_line": observed_line,
                            "counts": counts,
                            "run_window_notice": notice,
                            "exact_footer_lines": [
                                "Counts: authoritative_changes=0, "
                                f"known_rows={counts['known_rows']}, "
                                "rows_with_required_gaps="
                                f"{counts['rows_with_required_gaps']}",
                                baseline_line,
                                f"Journal: {journal_text} | Persistence: "
                                f"{variant.get('persistence_outcome')}",
                                warning_line,
                            ],
                        }
                self.require(
                    variants == expected_variants
                    and projections == computed_projections
                    and isinstance(projections, dict)
                    and all(
                        projection.get("primary_table_kind") == "current"
                        and projection.get("exact_columns")
                        == ["CONTAINER", "IMAGE", "STATE"]
                        and isinstance(
                            projection.get("exact_observed_line"), str
                        )
                        and set(projection.get("counts", {}))
                        == set(ENDPOINT_COUNT_FIELDS)
                        and (
                            projection.get("run_window_notice") is None
                            or (
                                set(projection["run_window_notice"])
                                == set(
                                    EXACT_REPORT_MODEL_FIELDS[
                                        "report_notice"
                                    ]
                                )
                            )
                        )
                        and len(projection.get("exact_footer_lines", [])) == 4
                        for projection in projections.values()
                    ),
                    path,
                    context,
                    "pre-each, status, scope-mismatch, post-only, and check "
                    "results must use their exact endpoint table, header, "
                    "notice, count, and footer projections",
                )
            elif case_id == "header_truthfulness_annotations_are_exact":
                input_data = case.get("input", {})
                variants = input_data.get("variants")
                headers = oracle.get("exact_headers")
                lines = oracle.get("exact_observed_lines")
                shared = {
                    "host": input_data.get("host"),
                    "instance_id": input_data.get("instance_id"),
                    "operation": input_data.get("operation"),
                    "observed_at": input_data.get("observed_at"),
                    "observation_status": input_data.get(
                        "observation_status"
                    ),
                    "correlation_id": input_data.get("correlation_id"),
                }
                computed_headers: dict[str, Any] = {}
                computed_lines: dict[str, str] = {}
                if isinstance(variants, dict):
                    for variant_id, variant in variants.items():
                        if not isinstance(variant, dict):
                            continue
                        computed_headers[variant_id] = {
                            **shared,
                            "simulated": variant.get("simulated"),
                            "replay_outcome": variant.get(
                                "replay_outcome"
                            ),
                        }
                        line = (
                            f"Observed {shared['observed_at']} | "
                            f"status={shared['observation_status']}"
                        )
                        if variant.get("simulated") is True:
                            line += " | mode=simulation"
                        if variant.get("replay_outcome") == "idempotent":
                            line += " | replay=idempotent"
                        computed_lines[variant_id] = line
                self.require(
                    variants
                    == {
                        "normal": {
                            "simulated": False,
                            "replay_outcome": None,
                        },
                        "simulation": {
                            "simulated": True,
                            "replay_outcome": None,
                        },
                        "retained_replay": {
                            "simulated": False,
                            "replay_outcome": "idempotent",
                        },
                    }
                    and headers == computed_headers
                    and lines == computed_lines
                    and all(
                        set(header)
                        == set(
                            EXACT_REPORT_MODEL_FIELDS["report_header"]
                        )
                        for header in headers.values()
                    ),
                    path,
                    context,
                    "normal, simulation, and retained-replay headers must "
                    "render their execution provenance exactly",
                )
            elif case_id == "semantic_missing_tokens_are_distinct":
                tokens = oracle.get("rendered_tokens")
                expected_tokens = {
                    "absent": "<absent>",
                    "endpoint_not_observed": "<not observed>",
                    "field_unknown": "<unknown>",
                    "no_explicit_tag": "<no explicit tag>",
                }
                self.require(
                    tokens == expected_tokens
                    and len(set(tokens.values())) == len(tokens)
                    and oracle.get("tokens_are_pairwise_distinct") is True
                    and oracle.get("blank_cell_forbidden") is True
                    and oracle.get("hyphen_only_cell_forbidden") is True,
                    path,
                    context,
                    "missing-state tokens must be explicit and pairwise distinct",
                )
            elif case_id == "visible_escape_is_exact_utf8_byte_projection":
                input_data = case.get("input", {})
                value = input_data.get("value")
                reserved = set(b"\\|~#<>")
                escaped = (
                    "".join(
                        chr(byte)
                        if 0x20 <= byte <= 0x7E and byte not in reserved
                        else f"\\x{byte:02x}"
                        for byte in value.encode("utf-8")
                    )
                    if isinstance(value, str)
                    else None
                )
                self.require(
                    value == "A\\|~#<> é\nZ"
                    and escaped
                    == oracle.get("exact_escaped_value")
                    == (
                        "A\\x5c\\x7c\\x7e\\x23\\x3c\\x3e "
                        "\\xc3\\xa9\\x0aZ"
                    )
                    and oracle.get("hex_case") == "lowercase"
                    and oracle.get("reserved_ascii_bytes")
                    == ["\\", "|", "~", "#", "<", ">"]
                    and oracle.get(
                        "printable_unreserved_ascii_preserved"
                    )
                    is True
                    and oracle.get("utf8_encoded_before_escaping") is True
                    and oracle.get("round_trip_claimed") is False,
                    path,
                    context,
                    "visible escaping must operate on UTF-8 bytes and escape "
                    "every reserved or non-printable byte with lowercase hex",
                )
            elif (
                case_id
                == "container_shortening_and_collision_are_exact"
            ):
                input_data = case.get("input", {})
                single = input_data.get("single", {})
                collision = input_data.get("collision_group", {})
                single_oracle = oracle.get("single", {})
                collision_oracle = oracle.get("collision_group", {})

                def shorten(value: str, width: int) -> tuple[str, int, int]:
                    left = max(1, (2 * (width - 1)) // 5)
                    right = width - 1 - left
                    return (
                        value[:left] + "~" + value[-right:],
                        left,
                        right,
                    )

                single_label, single_left, single_right = shorten(
                    single.get("name", ""), single.get("width", 0)
                )
                names = collision.get("names", [])
                initial_labels = [
                    shorten(name, collision.get("width", 0))[0]
                    for name in names
                ]
                reduced_width = collision_oracle.get(
                    "reduced_readable_width"
                )
                reduced_labels = [
                    shorten(name, reduced_width)[0]
                    for name in names
                ]
                exact_labels = {
                    name: (
                        f"{reduced_label}#"
                        f"{hashlib.sha256(name.encode('ascii')).hexdigest()[:4]}"
                    )
                    for name, reduced_label in zip(names, reduced_labels)
                }
                self.require(
                    single.get("width") == 26
                    and isinstance(single.get("name"), str)
                    and CONTAINER_NAME_RE.fullmatch(single["name"])
                    is not None
                    and single_left
                    == single_oracle.get("left_characters")
                    == 10
                    and single_right
                    == single_oracle.get("right_characters")
                    == 15
                    and single_label
                    == single_oracle.get("exact_label")
                    == "fixture-se~name-0123456789"
                    and collision.get("width") == 16
                    and isinstance(names, list)
                    and len(names) == 2
                    and all(
                        isinstance(name, str)
                        and CONTAINER_NAME_RE.fullmatch(name) is not None
                        for name in names
                    )
                    and len(set(names)) == 2
                    and len(set(initial_labels)) == 1
                    and initial_labels[0]
                    == collision_oracle.get("initial_exact_label")
                    == "abcdef~mmon-tail"
                    and collision_oracle.get("hash_algorithm") == "sha256"
                    and collision_oracle.get("hash_input")
                    == "ascii_full_normalized_container_name"
                    and collision_oracle.get("hash_prefix_length") == 4
                    and reduced_width == 11
                    and len(set(reduced_labels)) == 1
                    and reduced_labels[0]
                    == collision_oracle.get("reduced_exact_label")
                    == "abcd~n-tail"
                    and collision_oracle.get("exact_labels")
                    == exact_labels
                    and all(
                        len(label) == collision.get("width")
                        for label in exact_labels.values()
                    )
                    and collision.get("permuted_order") == list(reversed(names))
                    and collision_oracle.get(
                        "stable_under_input_permutation"
                    )
                    is True
                    and oracle.get("split_rule")
                    == "tail_weighted_two_fifths_three_fifths"
                    and oracle.get("elision_marker") == "~"
                    and oracle.get("full_machine_names_truncated") is False,
                    path,
                    context,
                    "container shortening and collision hashes must follow "
                    "the exact tail-weighted, report-order-invariant rule",
                )
            elif case_id == "change_vocabulary_is_closed_and_bounded":
                input_data = case.get("input")
                changes = (
                    input_data.get("changes")
                    if isinstance(input_data, dict)
                    else None
                )
                computed_labels = (
                    {
                        change.get("id"): expected_change_label(change)
                        for change in changes
                    }
                    if isinstance(changes, list)
                    and all(isinstance(change, dict) for change in changes)
                    else {}
                )
                kinds_valid = (
                    isinstance(changes, list)
                    and bool(changes)
                    and all(
                        isinstance(change.get("id"), str)
                        and isinstance(change.get("kinds"), list)
                        and change.get("primary_kind")
                        in change.get("kinds", [])
                        for change in changes
                    )
                )
                labels = oracle.get("exact_labels")
                self.require(
                    kinds_valid
                    and labels == computed_labels
                    and len(labels) == 14
                    and max(len(label) for label in labels.values()) == 17
                    and oracle.get("maximum_label_width") == 17
                    and oracle.get("vocabulary_exhaustive_for_v1") is True
                    and oracle.get("runtime_secondary_suffixes_appended")
                    is False
                    and oracle.get("complete_machine_kinds_preserved") is True
                    and labels.get(
                        "recreated_both_with_runtime_secondary"
                    )
                    == "recreated+img+ref"
                    and labels.get("image_both_with_runtime_secondary")
                    == "img+ref changed",
                    path,
                    context,
                    "CHANGE labels must be an exhaustive <=17-character "
                    "projection while retaining secondary kinds only in the "
                    "machine result",
                )
            elif case_id in {
                "same_tag_new_image_id_projects_distinct_row",
                "repository_change_equal_image_id_projects_distinct_row",
                "tag_digest_change_equal_image_id_projects_distinct_row",
            }:
                input_data = case.get("input")
                if not self.require(
                    isinstance(input_data, dict),
                    path,
                    f"{context}.input",
                    "must be a mapping",
                ):
                    continue
                canonical_result = input_data.get("canonical_result")
                canonical_delta = (
                    canonical_result.get("run_window_delta")
                    if isinstance(canonical_result, dict)
                    else None
                )
                changes = (
                    canonical_delta.get("changes")
                    if isinstance(canonical_delta, dict)
                    else None
                )
                canonical_change = oracle.get("canonical_change")
                report_row = oracle.get("exact_report_model_row")
                logical_row = oracle.get("exact_rendered_logical_row")
                if not self.require(
                    isinstance(canonical_result, dict)
                    and isinstance(canonical_delta, dict)
                    and isinstance(changes, list)
                    and len(changes) == 1
                    and isinstance(changes[0], dict)
                    and isinstance(canonical_change, dict)
                    and isinstance(report_row, dict)
                    and isinstance(report_row.get("cells"), dict)
                    and isinstance(logical_row, str)
                    and bool(logical_row),
                    path,
                    context,
                    "end-to-end image presentation case must contain one "
                    "canonical change, one exact model row, and one logical row",
                ):
                    continue
                change = changes[0]
                before = change.get("before")
                after = change.get("after")
                cells = report_row.get("cells")
                if not self.require(
                    isinstance(before, dict)
                    and isinstance(after, dict)
                    and isinstance(cells, dict),
                    path,
                    context,
                    "canonical endpoints and rendered cells must be mappings",
                ):
                    continue
                before_reference = before.get("full_image_reference")
                after_reference = after.get("full_image_reference")
                before_image_id = before.get("image_id")
                after_image_id = after.get("image_id")
                before_image_prefix = (
                    before_image_id[7:14]
                    if isinstance(before_image_id, str)
                    else ""
                )
                after_image_prefix = (
                    after_image_id[7:14]
                    if isinstance(after_image_id, str)
                    else ""
                )
                reference_changed = before_reference != after_reference
                content_changed = before_image_id != after_image_id
                expected_canonical_change = {
                    "primary_kind": change.get("primary_kind"),
                    "kinds": change.get("kinds"),
                    "image_reference_changed": reference_changed,
                    "image_content_changed": content_changed,
                }
                expected_presentation = {
                    "same_tag_new_image_id_projects_distinct_row": {
                        "cells": {
                            "container": "fixture-api",
                            "before": "api:stable@1111111 / running",
                            "after": "api:stable@2222222 / running",
                            "change": "img changed",
                        },
                        "logical_row": (
                            "fixture-api | api:stable@1111111 / running | "
                            "api:stable@2222222 / running | img changed"
                        ),
                    },
                    "repository_change_equal_image_id_projects_distinct_row": {
                        "cells": {
                            "container": "fixture-api",
                            "before": "r1.example/team/api:v1 / running",
                            "after": "r2.example/other/api:v1 / running",
                            "change": "ref changed",
                        },
                        "logical_row": (
                            "fixture-api | "
                            "r1.example/team/api:v1 / running | "
                            "r2.example/other/api:v1 / running | "
                            "ref changed"
                        ),
                    },
                    (
                        "tag_digest_change_equal_image_id_projects_distinct_row"
                    ): {
                        "cells": {
                            "container": "fixture-api",
                            "before": (
                                "api:v2@sha256:aaaaaaaaaaaa / running"
                            ),
                            "after": (
                                "api:v2@sha256:bbbbbbbbbbbb / running"
                            ),
                            "change": "ref changed",
                        },
                        "logical_row": (
                            "fixture-api | "
                            "api:v2@sha256:aaaaaaaaaaaa / running | "
                            "api:v2@sha256:bbbbbbbbbbbb / running | "
                            "ref changed"
                        ),
                    },
                }[case_id]
                expected_report_row = {
                    "container_name": change.get("container_name"),
                    "machine_before": before,
                    "machine_after": after,
                    "cells": expected_presentation["cells"],
                }
                expected_logical_row = expected_presentation["logical_row"]
                valid_references = all(
                    isinstance(reference, str)
                    and bool(reference)
                    and all(33 <= ord(character) <= 126 for character in reference)
                    for reference in (before_reference, after_reference)
                )
                self.require(
                    canonical_result.get("schema_version") == 1
                    and canonical_result.get("operation") == "post"
                    and canonical_result.get("observation_status") == "complete"
                    and canonical_delta.get("comparability") == "exact"
                    and canonical_delta.get("warnings") == []
                    and change.get("primary_kind") == "image_changed"
                    and change.get("kinds") == ["image_changed"]
                    and canonical_change == expected_canonical_change
                    and change.get("image_reference_changed")
                    == reference_changed
                    and change.get("image_content_changed")
                    == content_changed
                    and valid_references
                    and isinstance(before_image_id, str)
                    and SHA256_RE.fullmatch(before_image_id) is not None
                    and isinstance(after_image_id, str)
                    and SHA256_RE.fullmatch(after_image_id) is not None
                    and set(report_row)
                    == set(EXACT_REPORT_MODEL_FIELDS["run_window_row"])
                    and len(report_row)
                    == len(EXACT_REPORT_MODEL_FIELDS["run_window_row"])
                    and set(cells)
                    == set(EXACT_REPORT_MODEL_FIELDS["run_window_cells"])
                    and len(cells)
                    == len(EXACT_REPORT_MODEL_FIELDS["run_window_cells"])
                    and report_row == expected_report_row
                    and cells == expected_presentation["cells"]
                    and cells.get("container")
                    == change.get("container_name")
                    and cells.get("change")
                    == expected_change_label(change)
                    and cells.get("before") != cells.get("after")
                    and logical_row == expected_logical_row
                    and oracle.get("endpoint_cells_visibly_distinct") is True
                    and oracle.get(
                        "projection_changed_canonical_facets"
                    )
                    is False,
                    path,
                    context,
                    "canonical image facets, untruncated machine endpoints, "
                    "distinct display cells, and logical row must agree",
                )
                if case_id == "same_tag_new_image_id_projects_distinct_row":
                    self.require(
                        isinstance(before_image_id, str)
                        and isinstance(after_image_id, str)
                        and before_reference == after_reference
                        and before_image_id != after_image_id
                        and f"@{before_image_prefix}"
                        in cells.get("before", "")
                        and f"@{after_image_prefix}"
                        in cells.get("after", ""),
                        path,
                        context,
                        "equal mutable tags with different image IDs must show "
                        "distinct image-ID evidence",
                    )
                elif (
                    case_id
                    == "repository_change_equal_image_id_projects_distinct_row"
                ):
                    self.require(
                        isinstance(before_reference, str)
                        and isinstance(after_reference, str)
                        and before_reference != after_reference
                        and before_image_id == after_image_id
                        and oracle.get("initial_endpoint_labels")
                        == ["api:v1", "api:v1"]
                        and cells.get("before")
                        == f"{before_reference} / running"
                        and cells.get("after")
                        == f"{after_reference} / running",
                        path,
                        context,
                        "colliding basename/tag labels must expand repository "
                        "context without changing canonical facets",
                    )
                else:
                    before_digest = (
                        before_reference.rsplit("@sha256:", 1)[-1]
                        if isinstance(before_reference, str)
                        else ""
                    )
                    after_digest = (
                        after_reference.rsplit("@sha256:", 1)[-1]
                        if isinstance(after_reference, str)
                        else ""
                    )
                    self.require(
                        isinstance(before_reference, str)
                        and isinstance(after_reference, str)
                        and before_reference != after_reference
                        and before_image_id == after_image_id
                        and "@sha256:" in before_reference
                        and "@sha256:" in after_reference
                        and before_digest != after_digest
                        and f"@sha256:{before_digest[:12]}"
                        in cells.get("before", "")
                        and f"@sha256:{after_digest[:12]}"
                        in cells.get("after", ""),
                        path,
                        context,
                        "tag-plus-digest changes must preserve distinct digest "
                        "evidence even when image IDs are equal",
                    )
            elif case_id == "callback_transport_is_atomic_and_unescaped":
                input_data = case.get("input", {})
                callbacks = input_data.get("callbacks")
                callback_formats = (
                    {
                        (callback.get("name"), callback.get("result_format"))
                        for callback in callbacks
                    }
                    if isinstance(callbacks, list)
                    and all(isinstance(callback, dict) for callback in callbacks)
                    else set()
                )
                hosts = input_data.get("hosts")
                host_payloads = input_data.get("host_payloads")
                captures = oracle.get("expected_contiguous_captures")
                transcript = oracle.get("transcript_invariants")
                color_bytes = oracle.get(
                    "table_bytes_by_controller_color_mode"
                )
                self.require(
                    callback_formats
                    == {
                        ("ansible.builtin.default", "yaml"),
                        ("ansible.builtin.default", "json"),
                    }
                    and isinstance(callbacks, list)
                    and len(callbacks) == 2
                    and input_data.get("color_modes") == ["off", "on"]
                    and isinstance(hosts, list)
                    and len(hosts) == len(set(hosts))
                    and len(hosts) >= 2
                    and self.is_int(input_data.get("forks"))
                    and input_data.get("forks") >= 2
                    and input_data.get("strategy") == "linear"
                    and input_data.get("verbosity") == "normal"
                    and isinstance(host_payloads, dict)
                    and set(host_payloads) == set(hosts)
                    and isinstance(captures, dict)
                    and set(captures) == set(hosts),
                    path,
                    f"{context}.input",
                    "transport coverage must span YAML/JSON, controller color "
                    "modes, concurrent hosts, and one capture per host",
                )
                payload_contract_valid = (
                    isinstance(hosts, list)
                    and isinstance(host_payloads, dict)
                    and isinstance(captures, dict)
                    and set(host_payloads) == set(hosts)
                    and set(captures) == set(hosts)
                )
                all_sentinels: list[str] = []
                all_unique_tokens: list[str] = []
                if payload_contract_valid:
                    for host in hosts:
                        payload = host_payloads.get(host)
                        capture = captures.get(host)
                        if not self.require(
                            isinstance(payload, dict)
                            and isinstance(capture, dict),
                            path,
                            f"{context}.host {host!r}",
                            "payload and expected capture must be mappings",
                        ):
                            continue
                        begin = payload.get("begin_sentinel")
                        end = payload.get("end_sentinel")
                        token = payload.get("unique_row_token")
                        block = payload.get("expected_display_block")
                        foreign_tokens = capture.get(
                            "forbidden_foreign_unique_tokens"
                        )
                        string_fields_valid = all(
                            isinstance(value, str) and bool(value)
                            for value in (begin, end, token, block)
                        )
                        if string_fields_valid:
                            all_sentinels.extend([begin, end])
                            all_unique_tokens.append(token)
                        self.require(
                            string_fields_valid
                            and capture.get("begin_sentinel") == begin
                            and capture.get(
                                "exact_payload_between_sentinels"
                            )
                            == block
                            and capture.get("end_sentinel") == end
                            and isinstance(foreign_tokens, list)
                            and len(foreign_tokens) == len(hosts) - 1
                            and token not in foreign_tokens
                            and block.splitlines()[0]
                            == f"DAS v1 | host={host} | operation=status"
                            and block.count(token) == 1
                            and all(
                                foreign_token not in block
                                for foreign_token in foreign_tokens
                            )
                            and begin not in block
                            and end not in block
                            and not block.startswith(("'", '"'))
                            and "\\n" not in block
                            and "\x1b" not in block
                            and all(
                                character == "\n"
                                or 32 <= ord(character) <= 126
                                for character in block
                            )
                            and all(
                                not line.startswith(" ")
                                for line in block.splitlines()
                            ),
                            path,
                            f"{context}.host {host!r}",
                            "capture sentinels must enclose exactly one raw, "
                            "ASCII, host-specific, non-interleaved display block",
                        )
                    self.require(
                        len(all_sentinels) == len(set(all_sentinels))
                        and len(all_unique_tokens) == len(set(all_unique_tokens)),
                        path,
                        context,
                        "host sentinels and unique row tokens must be globally "
                        "unique across the callback capture",
                    )
                self.require(
                    oracle.get("one_display_call_per_host_block") is True
                    and oracle.get("host_header_required") is True
                    and oracle.get("quoted_block_forbidden") is True
                    and oracle.get("literal_backslash_n_forbidden") is True
                    and oracle.get("indented_border_forbidden") is True
                    and oracle.get("duplicate_block_forbidden") is True
                    and oracle.get(
                        "row_interleaving_within_host_block_forbidden"
                    )
                    is True
                    and oracle.get("cross_host_atomic_snapshot_claim")
                    is False
                    and transcript
                    == {
                        "each_begin_sentinel_count": 1,
                        "each_end_sentinel_count": 1,
                        "each_exact_host_block_count": 1,
                        "host_block_bytes_contiguous": True,
                        "host_unique_token_confined_to_own_block": True,
                        "whole_host_block_order_may_vary": True,
                        "line_or_row_level_interleaving_forbidden": True,
                    }
                    and color_bytes
                    == {
                        "off": {"ansi_sequences_present": False},
                        "on": {"ansi_sequences_present": False},
                    }
                    and oracle.get(
                        "exact_table_bytes_equal_across_controller_color_modes"
                    )
                    is True
                    and oracle.get(
                        "built_in_json_result_format_is_machine_stdout_api"
                    )
                    is False
                    and oracle.get(
                        "structured_stdout_callbacks_supported_for_human_mode"
                    )
                    is False,
                    path,
                    f"{context}.oracle",
                    "callback transport must preserve contiguous per-host bytes, "
                    "allow only whole-block host reordering, and keep table bytes "
                    "ANSI-free and identical across controller color modes",
                )
            elif (
                case_id
                == "structured_stdout_callback_is_not_human_report_transport"
            ):
                input_data = case.get("input")
                none_probe = (
                    input_data.get("none_mode_probe")
                    if isinstance(input_data, dict)
                    else None
                )
                self.require(
                    isinstance(input_data, dict)
                    and input_data.get("callback") == "ansible.posix.json"
                    and input_data.get("strategy") == "linear"
                    and input_data.get("report_mode") == "final"
                    and input_data.get("raw_display_block_present") is True
                    and input_data.get("whole_stdout_valid_json") is False
                    and none_probe
                    == {
                        "deliberate_human_block_present": False,
                        "machine_valid_structured_stdout_promised": False,
                    }
                    and oracle.get("human_report_lane_supported") is False
                    and oracle.get(
                        "rejection_or_documented_incompatibility_required"
                    )
                    is True
                    and oracle.get(
                        "registered_namespaced_result_is_machine_integration_surface"
                    )
                    is True
                    and oracle.get(
                        "callback_owned_result_serialization_is_not_das_api"
                    )
                    is True
                    and oracle.get(
                        "future_explicit_structured_transport_required"
                    )
                    is True,
                    path,
                    context,
                    "structured stdout callbacks must not be advertised as "
                    "the v1 human-report or machine-result transport",
                )
            elif case_id == "failed_callback_uses_bounded_envelope":
                input_data = case.get("input", {})
                failure_results = input_data.get("failure_results")
                required_outcomes = oracle.get(
                    "required_failure_outcomes"
                )
                forbidden_keys = set(
                    oracle.get("forbidden_recursive_keys", [])
                )

                def recursive_keys(value: Any) -> set[str]:
                    if isinstance(value, dict):
                        child_keys: set[str] = set(value)
                        for child in value.values():
                            child_keys.update(recursive_keys(child))
                        return child_keys
                    if isinstance(value, list):
                        child_keys = set()
                        for child in value:
                            child_keys.update(recursive_keys(child))
                        return child_keys
                    return set()

                results_valid = (
                    isinstance(failure_results, dict)
                    and isinstance(required_outcomes, list)
                    and list(failure_results) == required_outcomes
                    and required_outcomes
                    == REQUIRED_FAILURE_CALLBACK_OUTCOMES
                )
                replayable_outcomes = {
                    "fail_after_report",
                    "render_failure_after_commit",
                    "presentation_capacity_after_commit",
                }
                replay_guidance_by_outcome = {
                    "fail_after_report": (
                        "Retry the retained record with "
                        "failure_policy=report"
                    ),
                    "post_replace_state_write_failure": (
                        "Retry with the same record_id and unchanged "
                        "phase inputs"
                    ),
                    "render_failure_after_commit": (
                        "Retry the retained record with report_mode=none"
                    ),
                    "presentation_capacity_after_commit": (
                        "Retry the retained record with report_mode=none"
                    ),
                }
                expected_failure_contracts = {
                    "fail_after_report": (
                        "observation_noncomplete",
                        "docker_command_timeout",
                        "committed",
                    ),
                    "validation_failure": (
                        "invalid_input",
                        None,
                        "not_attempted",
                    ),
                    "state_size_failure": (
                        "state_size_limit_exceeded",
                        None,
                        "failed",
                    ),
                    "corrupt_state_failure": (
                        "corrupt_state",
                        None,
                        "failed",
                    ),
                    "lock_timeout_failure": (
                        "state_lock_timeout",
                        None,
                        "failed",
                    ),
                    "revision_conflict": (
                        "revision_conflict",
                        None,
                        "conflict",
                    ),
                    "persistence_io_failure": (
                        "state_write_failed",
                        None,
                        "failed",
                    ),
                    "post_replace_state_write_failure": (
                        "state_write_failed",
                        None,
                        "failed",
                    ),
                    "render_failure_after_commit": (
                        "render_failed",
                        None,
                        "committed",
                    ),
                    "presentation_capacity_after_commit": (
                        "presentation_capacity_exceeded",
                        None,
                        "committed",
                    ),
                }
                results_valid = results_valid and (
                    list(expected_failure_contracts)
                    == REQUIRED_FAILURE_CALLBACK_OUTCOMES
                )
                if results_valid:
                    for outcome_name, task_result in failure_results.items():
                        envelope = task_result.get(
                            "docker_ansible_summary_failure"
                        )
                        encoded_size = len(
                            json.dumps(
                                task_result,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        )
                        results_valid = results_valid and (
                            task_result.get("changed") is False
                            and task_result.get("failed") is True
                            and set(task_result)
                            == {
                                "changed",
                                "failed",
                                "docker_ansible_summary_failure",
                            }
                            and isinstance(envelope, dict)
                            and list(envelope)
                            == EXACT_FAILURE_ENVELOPE_FIELDS
                            and envelope.get("schema_version") == 1
                            and encoded_size
                            <= oracle.get(
                                "maximum_serialized_task_result_bytes", 0
                            )
                            and not (
                                forbidden_keys
                                & recursive_keys(task_result)
                            )
                            and (
                                envelope.get(
                                    "committed_result_replayable"
                                )
                                is (outcome_name in replayable_outcomes)
                            )
                            and (
                                envelope.get("failure_reason"),
                                envelope.get("observation_reason"),
                                envelope.get("persistence_outcome"),
                            )
                            == expected_failure_contracts.get(outcome_name)
                            and isinstance(envelope.get("host"), str)
                            and len(envelope["host"].encode("utf-8")) <= 128
                            and PRINTABLE_ASCII_RE.fullmatch(
                                envelope["host"]
                            )
                            is not None
                            and envelope.get("operation")
                            in {None, "pre", "post", "status"}
                            and (
                                envelope.get("instance_id") is None
                                or (
                                    isinstance(
                                        envelope.get("instance_id"), str
                                    )
                                    and INSTANCE_ID_RE.fullmatch(
                                        envelope["instance_id"]
                                    )
                                    is not None
                                )
                            )
                            and (
                                envelope.get("record_id") is None
                                or (
                                    isinstance(
                                        envelope.get("record_id"), str
                                    )
                                    and RECORD_ID_RE.fullmatch(
                                        envelope["record_id"]
                                    )
                                    is not None
                                )
                            )
                            and envelope.get("observation_status")
                            in {None, "complete", "partial", "unavailable"}
                            and envelope.get("failure_reason")
                            in FAILURE_REASON_VALUES
                            and envelope.get("observation_reason")
                            in [None, *OBSERVATION_REASON_VALUES]
                            and envelope.get("persistence_outcome")
                            in {
                                "committed",
                                "conflict",
                                "failed",
                                "not_attempted",
                            }
                            and (
                                envelope.get("replay_guidance")
                                == replay_guidance_by_outcome.get(
                                    outcome_name
                                )
                            )
                        )
                host_probe = input_data.get("host_projection_probe")
                raw_recipe = (
                    host_probe.get("raw_host_recipe")
                    if isinstance(host_probe, dict)
                    else None
                )
                raw_host = (
                    raw_recipe.get("character") * raw_recipe.get("repeat")
                    if isinstance(raw_recipe, dict)
                    and isinstance(raw_recipe.get("character"), str)
                    and self.is_int(raw_recipe.get("repeat"))
                    else ""
                )
                expected_projected_host = (
                    "sha256:"
                    + hashlib.sha256(raw_host.encode("utf-8")).hexdigest()
                    if raw_host
                    else None
                )
                diagnostic_probe = input_data.get(
                    "invalid_input_diagnostic_probe"
                )
                persistence_failure_stages = input_data.get(
                    "persistence_failure_stage_by_outcome"
                )
                overlong_recipe = (
                    diagnostic_probe.get(
                        "rejected_overlong_instance_recipe"
                    )
                    if isinstance(diagnostic_probe, dict)
                    else None
                )
                rejected_instance = (
                    overlong_recipe.get("character")
                    * overlong_recipe.get("repeat")
                    if isinstance(overlong_recipe, dict)
                    and isinstance(
                        overlong_recipe.get("character"), str
                    )
                    and self.is_int(overlong_recipe.get("repeat"))
                    else ""
                )
                self.require(
                    input_data.get("callbacks")
                    == [
                        {
                            "name": "ansible.builtin.default",
                            "result_format": "yaml",
                        },
                        {
                            "name": "ansible.builtin.default",
                            "result_format": "json",
                        },
                    ]
                    and input_data.get("color_modes") == ["off", "on"]
                    and input_data.get("strategy") == "linear"
                    and isinstance(host_probe, dict)
                    and len(raw_host.encode("utf-8")) == 300
                    and host_probe.get("expected_projected_host")
                    == expected_projected_host
                    and isinstance(expected_projected_host, str)
                    and len(expected_projected_host.encode("utf-8")) == 71
                    and isinstance(diagnostic_probe, dict)
                    and diagnostic_probe.get("rejected_report_width")
                    == "not-an-integer"
                    and diagnostic_probe.get("effective_wrap_width") == 120
                    and len(rejected_instance.encode("utf-8")) == 4096
                    and diagnostic_probe.get(
                        "failure_envelope_instance_id"
                    )
                    is None
                    and diagnostic_probe.get(
                        "diagnostic_includes_input_value"
                    )
                    is False
                    and persistence_failure_stages
                    == {
                        "persistence_io_failure": "before_atomic_replace",
                        "post_replace_state_write_failure": (
                            "after_atomic_replace_before_directory_fsync"
                        ),
                    }
                    and results_valid
                    and oracle.get("maximum_serialized_task_result_bytes")
                    == 1024
                    and oracle.get("serialized_bound_scope")
                    == "compact_canonical_json_entire_task_result"
                    and oracle.get("exact_host_utf8_bytes_max") == 128
                    and oracle.get("overlong_or_non_ascii_host_projection")
                    == "sha256_full_lowercase_hex"
                    and oracle.get("replay_guidance_utf8_bytes_max") == 128
                    and oracle.get("invalid_report_width_fallback") == 120
                    and oracle.get(
                        "invalid_or_unvalidated_envelope_fields_are_null"
                    )
                    is True
                    and oracle.get("exact_namespaced_failure_key")
                    == "docker_ansible_summary_failure"
                    and oracle.get("no_log_censorship_used") is False
                    and oracle.get("object_proportional_result_dumped")
                    is False
                    and oracle.get("one_terminal_failure_event_per_case")
                    is True
                    and oracle.get(
                        "captured_callback_snapshot_required_per_format_and_color"
                    )
                    is True
                    and oracle.get(
                        "full_committed_result_recovered_by_reason_specific_replay"
                    )
                    is True,
                    path,
                    context,
                    "failure callback lanes must use one bounded namespaced "
                    "envelope with no full result, raw output, or no_log "
                    "censorship",
                )
            elif case_id == "ascii_layout_is_deterministic_and_aligned":
                input_data = case.get("input", {})
                rows = input_data.get("row_values")
                report_width = input_data.get("report_width")
                long_fields = input_data.get("long_metadata_fields")
                exact_wrapped = oracle.get(
                    "exact_wrapped_metadata_lines"
                )
                golden = oracle.get(
                    "exact_minimum_width_rendered_block"
                )

                def wrap_semantic_fields(fields: list[str]) -> list[str]:
                    wrapped: list[str] = []
                    current = fields[0]
                    for field in fields[1:]:
                        candidate = f"{current} | {field}"
                        if len(candidate) <= report_width:
                            current = candidate
                        else:
                            wrapped.append(current)
                            current = ""
                            remaining = field
                            while len(f"  {remaining}") > report_width:
                                take = report_width - 2
                                wrapped.append(f"  {remaining[:take]}")
                                remaining = remaining[take:]
                            current = f"  {remaining}"
                    wrapped.append(current)
                    return wrapped

                def wrap_warning_items(items: list[str]) -> list[str]:
                    wrapped: list[str] = []
                    for item_index, item in enumerate(items):
                        prefix = (
                            "Warnings: " if item_index == 0 else "  "
                        )
                        remaining = item
                        first = True
                        while first or remaining:
                            line_prefix = prefix if first else "  "
                            take = report_width - len(line_prefix)
                            chunk = remaining[:take]
                            wrapped.append(f"{line_prefix}{chunk}")
                            remaining = remaining[take:]
                            first = False
                    return wrapped

                wrapped_fields_valid = (
                    isinstance(long_fields, dict)
                    and isinstance(exact_wrapped, dict)
                    and set(long_fields) == {"header", "warnings"}
                    and set(exact_wrapped) == {"header", "warnings"}
                )
                if wrapped_fields_valid:
                    for field_group in ("header", "warnings"):
                        fields = long_fields.get(field_group)
                        if field_group == "warnings" and isinstance(fields, list):
                            recipe = input_data.get(
                                "overlong_warning_field"
                            )
                            if (
                                isinstance(recipe, dict)
                                and isinstance(recipe.get("prefix"), str)
                                and isinstance(
                                    recipe.get("character"), str
                                )
                                and len(recipe["character"]) == 1
                                and self.is_int(recipe.get("repeat"))
                                and recipe["repeat"] > 0
                            ):
                                fields = [
                                    *fields,
                                    recipe["prefix"]
                                    + recipe["character"] * recipe["repeat"],
                                ]
                            else:
                                wrapped_fields_valid = False
                        expected_lines = exact_wrapped.get(field_group)
                        computed_lines = (
                            wrap_warning_items(fields)
                            if field_group == "warnings"
                            and isinstance(fields, list)
                            else wrap_semantic_fields(fields)
                            if isinstance(fields, list)
                            else None
                        )
                        wrapped_fields_valid = wrapped_fields_valid and (
                            isinstance(fields, list)
                            and bool(fields)
                            and all(
                                isinstance(field, str) and bool(field)
                                for field in fields
                            )
                            and isinstance(expected_lines, list)
                            and computed_lines == expected_lines
                            and all(
                                len(line) <= report_width
                                for line in expected_lines
                            )
                        )
                widths = oracle.get("column_content_widths")
                separator_positions = oracle.get("separator_positions")
                container_labels = oracle.get("exact_container_labels")
                expected_container_labels = {
                    "fixture-api": "fixture-api",
                    "fixture-cache": "fixture-cache",
                }
                projected_rows = (
                    [
                        [
                            expected_container_labels.get(row[0], row[0]),
                            *row[1:],
                        ]
                        for row in rows
                    ]
                    if isinstance(rows, list)
                    and all(isinstance(row, list) and len(row) == 4 for row in rows)
                    else []
                )
                golden_lines = (
                    golden.splitlines() if isinstance(golden, str) else []
                )
                border = (
                    "+"
                    + "+".join("-" * (width + 2) for width in widths)
                    + "+"
                    if isinstance(widths, list)
                    and all(self.is_int(width) for width in widths)
                    else ""
                )
                exact_expected_lines = [
                    *exact_wrapped.get("header", []),
                    "Observed 2026-07-30T12:30:02Z | status=complete",
                    *render_ascii_table(
                        ["CONTAINER", "BEFORE", "AFTER", "CHANGE"],
                        projected_rows,
                        widths,
                    ),
                    "Counts: image_changed=1, started=1, total=2",
                    "Baseline: advanced (obs-layout-a -> obs-layout-c)",
                    "Journal: complete | Persistence: committed",
                    *exact_wrapped.get("warnings", []),
                ]
                parsed_rows: list[list[str]] = []
                if len(golden_lines) == 16:
                    parsed_rows = [
                        [
                            cell.strip()
                            for cell in golden_lines[index][1:-1].split("|")
                        ]
                        for index in (4, 6, 7)
                    ]
                self.require(
                    input_data.get("fixture_layer")
                    == "internal_warning_layout_unit"
                    and input_data.get("role_generated_templates_applied")
                    is False
                    and input_data.get("presentation_schema_version") == 1
                    and input_data.get("style") == "ascii"
                    and input_data.get("color") is False
                    and input_data.get("observation_status") == "complete"
                    and input_data.get("baseline_before") == "obs-layout-a"
                    and input_data.get("baseline_after") == "obs-layout-c"
                    and input_data.get("journal_status") == "complete"
                    and input_data.get("persistence_outcome") == "committed"
                    and self.is_int(report_width)
                    and 100 <= report_width <= 240
                    and report_width == 100
                    and isinstance(rows, list)
                    and bool(rows)
                    and rows
                    == [
                        [
                            "fixture-api",
                            "api:v1 / running",
                            "api:v2 / running",
                            "img+ref changed",
                        ],
                        [
                            "fixture-cache",
                            "cache:v1 / stopped",
                            "cache:v1 / running",
                            "started",
                        ],
                    ]
                    and wrapped_fields_valid,
                    path,
                    f"{context}.input",
                    "ASCII layout input must bind the minimum width, exact "
                    "rows, and deterministic semantic metadata wrapping",
                )
                self.require(
                    isinstance(golden, str)
                    and len(golden_lines) == 16
                    and golden_lines == exact_expected_lines
                    and widths == [26, 22, 22, 17]
                    and sum(widths) + 13 == report_width
                    and separator_positions == [0, 29, 54, 79, 99]
                    and container_labels == expected_container_labels
                    and oracle.get("opaque_markers") == []
                    and oracle.get("legend_entries") == []
                    and golden_lines[:2] == exact_wrapped.get("header")
                    and golden_lines[2]
                    == "Observed 2026-07-30T12:30:02Z | status=complete"
                    and golden_lines[3] == golden_lines[5] == golden_lines[8]
                    == border
                    and parsed_rows
                    == [
                        ["CONTAINER", "BEFORE", "AFTER", "CHANGE"],
                        *projected_rows,
                    ]
                    and golden_lines[9:12]
                    == [
                        "Counts: image_changed=1, started=1, total=2",
                        "Baseline: advanced "
                        "(obs-layout-a -> obs-layout-c)",
                        "Journal: complete | Persistence: committed",
                    ]
                    and golden_lines[12:16]
                    == exact_wrapped.get("warnings")
                    and all(
                        len(line) <= report_width
                        for line in golden.splitlines()
                    )
                    and all(
                        len(golden_lines[index]) == report_width
                        for index in range(3, 9)
                    )
                    and [
                        index
                        for index, character in enumerate(golden_lines[3])
                        if character == "+"
                    ]
                    == separator_positions
                    and all(
                        [
                            index
                            for index, character in enumerate(golden_lines[row])
                            if character == "|"
                        ]
                        == separator_positions
                        for row in (4, 6, 7)
                    )
                    and oracle.get("one_physical_line_per_row") is True
                    and oracle.get("separator_positions_equal") is True
                    and oracle.get("maximum_line_width") == report_width
                    and oracle.get("control_characters_present") is False
                    and oracle.get("ansi_sequences_present") is False
                    and oracle.get("deterministic_ordering") is True,
                    path,
                    f"{context}.oracle",
                    "ASCII output must provide exact minimum-width bytes, "
                    "deterministic wrapped metadata, and bounded aligned lines",
                )

    def validate_execution_surface_cases(
        self,
        path: Path,
        data: dict[str, Any],
        cases: list[dict[str, Any]],
    ) -> None:
        batch_limits = data.get("batch_limits")
        if not self.require_keys(
            batch_limits,
            [
                "catalogue_includes_container_ids_and_names",
                "scope_applied_before_container_inspect",
                "container_max_items",
                "argument_byte_limit_binding",
                "default_argument_byte_limit_bytes",
                "argument_byte_limit_scope",
                "argument_terminating_nul_bytes",
                "argument_encoding",
                "default_container_id_bytes_including_nul",
            ],
            path,
            "batch_limits",
        ):
            return
        container_limit = batch_limits.get("container_max_items")
        default_byte_limit = batch_limits.get(
            "default_argument_byte_limit_bytes"
        )
        terminating_nul_bytes = batch_limits.get(
            "argument_terminating_nul_bytes"
        )
        default_container_bytes = batch_limits.get(
            "default_container_id_bytes_including_nul"
        )
        limits_valid = (
            self.is_int(container_limit)
            and container_limit > 0
            and self.is_int(default_byte_limit)
            and default_byte_limit > 0
            and terminating_nul_bytes == 1
            and self.is_int(default_container_bytes)
            and 0 < default_container_bytes <= default_byte_limit
        )
        self.require(
            limits_valid,
            path,
            "batch_limits",
            "item, complete-argv byte, NUL, and default identifier bounds "
            "must be valid positive integers",
        )
        self.require(
            batch_limits.get(
                "catalogue_includes_container_ids_and_names"
            )
            is True
            and batch_limits.get("scope_applied_before_container_inspect")
            is True
            and batch_limits.get("argument_byte_limit_binding") is True
            and batch_limits.get("argument_byte_limit_scope")
            == "complete_argv"
            and batch_limits.get("argument_encoding") == "os.fsencode",
            path,
            "batch_limits",
            "catalogue must expose ID/name scope evidence before inspect and "
            "chunk arithmetic must bind the complete encoded argv",
        )

        state_limits = data.get("state_and_deadline_limits")
        self.require(
            isinstance(state_limits, dict)
            and state_limits.get("default_state_max_bytes") == 16777216
            and state_limits.get("minimum_state_max_bytes") == 1048576
            and state_limits.get("maximum_state_max_bytes") == 268435456
            and state_limits.get(
                "exact_canonical_serialization_is_binding"
            )
            is True
            and state_limits.get("default_discovery_timeout_seconds") == 30
            and state_limits.get("minimum_discovery_timeout_seconds") == 1
            and state_limits.get("maximum_discovery_timeout_seconds") == 300
            and state_limits.get(
                "one_monotonic_deadline_for_all_processes"
            )
            is True,
            path,
            "state_and_deadline_limits",
            "must bind exact store bytes and one 1-300 second monotonic "
            "discovery deadline",
        )

        event_budget = data.get("normal_verbosity_event_budget")
        self.require(
            isinstance(event_budget, dict)
            and event_budget.get("reference_invocation")
            == "static_import_role"
            and event_budget.get("role_task_start_events") == 1
            and event_budget.get("terminal_task_result_events") == 1
            and event_budget.get("per_item_result_events") == 0
            and event_budget.get("separate_include_success_events") == 0
            and event_budget.get(
                "callback_rendered_line_count_is_portability_invariant"
            )
            is False
            and isinstance(
                event_budget.get(
                    "normal_verbosity_incidental_lines_definition"
                ),
                str,
            )
            and bool(
                event_budget[
                    "normal_verbosity_incidental_lines_definition"
                ].strip()
            ),
            path,
            "normal_verbosity_event_budget",
            "must define one task-start, one terminal result, zero item "
            "events, and callback-specific physical lines",
        )

        def bounded_chunk_count(
            count: int,
            item_limit: int,
            byte_limit: int,
            fixed_argv_bytes: int,
            identifier_bytes: int,
        ) -> int:
            if count == 0:
                return 0
            if fixed_argv_bytes + identifier_bytes > byte_limit:
                return 0
            chunks_count = 0
            items_in_chunk = 0
            bytes_in_chunk = fixed_argv_bytes
            for _ in range(count):
                if (
                    items_in_chunk >= item_limit
                    or bytes_in_chunk + identifier_bytes > byte_limit
                ):
                    chunks_count += 1
                    items_in_chunk = 0
                    bytes_in_chunk = fixed_argv_bytes
                items_in_chunk += 1
                bytes_in_chunk += identifier_bytes
            return chunks_count + (1 if items_in_chunk else 0)

        def encoded_argv_bytes(argv: list[str]) -> int:
            return sum(len(os.fsencode(argument)) + 1 for argument in argv)

        def partition_concrete_identifiers(
            fixed_argv: list[str],
            identifiers: list[str],
            item_limit: int,
            byte_limit: int,
        ) -> tuple[list[list[str]], list[int], list[str]]:
            chunks: list[list[str]] = []
            chunk_bytes: list[int] = []
            oversize: list[str] = []
            fixed_bytes = encoded_argv_bytes(fixed_argv)
            current: list[str] = []
            current_bytes = fixed_bytes
            for identifier in identifiers:
                identifier_bytes = encoded_argv_bytes([identifier])
                if fixed_bytes + identifier_bytes > byte_limit:
                    oversize.append(identifier)
                    continue
                if current and (
                    len(current) >= item_limit
                    or current_bytes + identifier_bytes > byte_limit
                ):
                    chunks.append(current)
                    chunk_bytes.append(current_bytes)
                    current = []
                    current_bytes = fixed_bytes
                current.append(identifier)
                current_bytes += identifier_bytes
            if current:
                chunks.append(current)
                chunk_bytes.append(current_bytes)
            return chunks, chunk_bytes, oversize

        for case in cases:
            case_id = case.get("id")
            context = f"case {case_id!r}"

            if case_id == "phase_signature_known_answer":
                signature_object = case.get("input", {}).get(
                    "signature_object"
                )
                oracle = case.get("oracle", {})
                expected_fields = EXACT_PHASE_SIGNATURE_FIELDS
                canonical = (
                    json.dumps(
                        signature_object,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    if isinstance(signature_object, dict)
                    else ""
                )
                digest = "sha256:" + hashlib.sha256(
                    canonical.encode("utf-8")
                ).hexdigest()
                self.require(
                    isinstance(signature_object, dict)
                    and set(signature_object) == set(expected_fields)
                    and signature_object
                    == {
                        "comparison_schema_version": 1,
                        "correlation_id": None,
                        "instance_id": "fixture-mdad",
                        "operation": "pre",
                        "scope": ["fixture-*"],
                        "signature_schema_version": 1,
                    }
                    and canonical
                    == oracle.get("canonical_json_utf8")
                    == '{"comparison_schema_version":1,"correlation_id":null,'
                    '"instance_id":"fixture-mdad","operation":"pre",'
                    '"scope":["fixture-*"],"signature_schema_version":1}'
                    and len(canonical.encode("utf-8"))
                    == oracle.get("exact_serialized_bytes")
                    == 151
                    and digest
                    == oracle.get("exact_signature")
                    == "sha256:f09b6fbb422b755acd3aa1eb22814ed702aa91be62052df1bd9ca20bc8fb4f70"
                    and oracle.get("trailing_lf") is False
                    and oracle.get("unknown_key_rejected") is True,
                    path,
                    context,
                    "phase-signature JSON bytes and SHA-256 known answer must "
                    "remain exact",
                )
                continue

            if (
                case_id
                == "phase_signature_non_ascii_correlation_known_answer"
            ):
                signature_object = case.get("input", {}).get(
                    "signature_object"
                )
                oracle = case.get("oracle", {})
                canonical = (
                    json.dumps(
                        signature_object,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    if isinstance(signature_object, dict)
                    else ""
                )
                canonical_bytes = canonical.encode("utf-8")
                escaped_ascii = (
                    json.dumps(
                        signature_object,
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    if isinstance(signature_object, dict)
                    else ""
                )
                digest = "sha256:" + hashlib.sha256(
                    canonical_bytes
                ).hexdigest()
                self.require(
                    isinstance(signature_object, dict)
                    and set(signature_object)
                    == set(EXACT_PHASE_SIGNATURE_FIELDS)
                    and signature_object
                    == {
                        "comparison_schema_version": 1,
                        "correlation_id": "deploy-ø",
                        "instance_id": "fixture-mdad",
                        "operation": "pre",
                        "scope": ["fixture-*"],
                        "signature_schema_version": 1,
                    }
                    and canonical
                    == oracle.get("canonical_json_utf8")
                    == '{"comparison_schema_version":1,'
                    '"correlation_id":"deploy-ø",'
                    '"instance_id":"fixture-mdad","operation":"pre",'
                    '"scope":["fixture-*"],"signature_schema_version":1}'
                    and canonical_bytes.hex()
                    == oracle.get("exact_utf8_hex")
                    == "7b22636f6d70617269736f6e5f736368656d615f"
                    "76657273696f6e223a312c22636f7272656c617469"
                    "6f6e5f6964223a226465706c6f792dc3b8222c2269"
                    "6e7374616e63655f6964223a22666978747572652d"
                    "6d646164222c226f7065726174696f6e223a227072"
                    "65222c2273636f7065223a5b22666978747572652d"
                    "2a225d2c227369676e61747572655f736368656d61"
                    "5f76657273696f6e223a317d"
                    and len(canonical_bytes)
                    == oracle.get("exact_serialized_bytes")
                    == 158
                    and digest
                    == oracle.get("exact_signature")
                    == "sha256:f4c35463107ed692043b5b87b0a9ffa5597042bae8ffb133ba2640227d251910"
                    and escaped_ascii != canonical
                    and oracle.get("escaped_ascii_json_differs") is True
                    and oracle.get("trailing_lf") is False,
                    path,
                    context,
                    "non-ASCII correlation must use direct canonical UTF-8 "
                    "bytes and the frozen SHA-256 known answer",
                )
                continue

            if case_id == "observed_at_opens_bounded_sampling_interval":
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                events = input_data.get("fake_event_order")
                replay_events = input_data.get("retained_replay_events")
                expected_events = [
                    {
                        "sequence": 1,
                        "kind": "utc_clock",
                        "event": "capture_observed_at",
                        "value": "2026-07-30T12:55:00Z",
                    },
                    {
                        "sequence": 2,
                        "kind": "monotonic_clock",
                        "event": "start_discovery_deadline",
                        "value": 1000.0,
                    },
                    {
                        "sequence": 3,
                        "kind": "docker_process",
                        "event": "start_catalogue",
                    },
                    {
                        "sequence": 4,
                        "kind": "docker_process",
                        "event": "finish_catalogue",
                    },
                    {
                        "sequence": 5,
                        "kind": "docker_process",
                        "event": "start_inspect_chunk",
                        "chunk": 1,
                    },
                    {
                        "sequence": 6,
                        "kind": "docker_process",
                        "event": "finish_inspect_chunk",
                        "chunk": 1,
                    },
                    {
                        "sequence": 7,
                        "kind": "observer",
                        "event": "finalize_observation",
                    },
                ]
                self.require(
                    input_data.get("discovery_timeout_seconds") == 30
                    and events == expected_events
                    and [
                        event.get("sequence")
                        for event in events
                        if isinstance(event, dict)
                    ]
                    == list(range(1, 8))
                    and [
                        event.get("event")
                        for event in events[:3]
                        if isinstance(event, dict)
                    ]
                    == [
                        "capture_observed_at",
                        "start_discovery_deadline",
                        "start_catalogue",
                    ]
                    and replay_events == []
                    and oracle.get("observed_at")
                    == events[0].get("value")
                    == "2026-07-30T12:55:00Z"
                    and oracle.get("observed_at_capture_count") == 1
                    and oracle.get("sampling_interval_opens_at")
                    == "capture_observed_at"
                    and oracle.get("sampling_interval_closes_at")
                    == "finalize_observation"
                    and oracle.get("deadline_origin_after_observed_at")
                    is True
                    and oracle.get(
                        "catalogue_immediately_after_deadline_origin"
                    )
                    is True
                    and oracle.get("maximum_interval_seconds") == 30
                    and oracle.get("atomic_docker_snapshot_claimed") is False
                    and oracle.get("public_interval_end_field_present")
                    is False
                    and oracle.get(
                        "replay_retains_committed_observed_at"
                    )
                    is True
                    and oracle.get("replay_clock_reads") == 0
                    and oracle.get("replay_docker_processes") == 0,
                    path,
                    context,
                    "observed_at must open one deadline-bounded sequential "
                    "sampling interval before catalogue, while replay keeps "
                    "the retained timestamp without clock or Docker work",
                )
                continue

            if (
                case_id
                == "production_docker_argv_projection_and_caps_are_exact"
            ):
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                catalogue_argv = input_data.get("catalogue_argv")
                inspect_fixed_argv = input_data.get("inspect_fixed_argv")
                recipe = input_data.get("container_id_recipe", {})
                identifiers = [
                    f"{index:064x}"
                    for index in range(recipe.get("count", 0))
                ]
                inspect_argv = (
                    [*inspect_fixed_argv, *identifiers]
                    if isinstance(inspect_fixed_argv, list)
                    else []
                )
                self.require(
                    input_data.get("docker_executable") == "/usr/bin/docker"
                    and isinstance(catalogue_argv, list)
                    and catalogue_argv
                    == [
                        "/usr/bin/docker",
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--format",
                        '{"id":{{json .ID}},"name":{{json .Names}}}',
                    ]
                    and isinstance(inspect_fixed_argv, list)
                    and inspect_fixed_argv
                    == [
                        "/usr/bin/docker",
                        "container",
                        "inspect",
                        "--format",
                        '{"container_id":{{json .Id}},'
                        '"created_at":{{json .Created}},'
                        '"finished_at":{{json .State.FinishedAt}},'
                        '"full_image_reference":{{json .Config.Image}},'
                        '"image_id":{{json .Image}},'
                        '"name":{{json .Name}},'
                        '"restart_count":{{json .RestartCount}},'
                        '"runtime_state":{{json .State.Status}},'
                        '"started_at":{{json .State.StartedAt}}}',
                    ]
                    and recipe
                    == {
                        "count": 100,
                        "encoding": "lowercase_hex_zero_padded",
                        "encoded_characters_each": 64,
                    }
                    and all(
                        CONTAINER_ID_RE.fullmatch(identifier) is not None
                        for identifier in identifiers
                    )
                    and encoded_argv_bytes(catalogue_argv)
                    == oracle.get("catalogue_argv_bytes")
                    == 98
                    and encoded_argv_bytes(inspect_fixed_argv)
                    == oracle.get("inspect_fixed_argv_bytes")
                    == 357
                    and encoded_argv_bytes([identifiers[0]])
                    == oracle.get("one_container_id_argv_bytes")
                    == 65
                    and encoded_argv_bytes(inspect_argv)
                    == oracle.get("inspect_argv_bytes_at_100_ids")
                    == 6857
                    and oracle.get("complete_argv_max_bytes") == 8192
                    and oracle.get("container_ids_per_chunk_max") == 100
                    and oracle.get("catalogue_rows_max") == 4096
                    and oracle.get("subprocess_stdout_max_bytes") == 2097152
                    and oracle.get("subprocess_stderr_max_bytes") == 65536
                    and oracle.get("logical_output_line_max_bytes") == 8192
                    and oracle.get("catalogue_exact_keys") == ["id", "name"]
                    and oracle.get("inspect_exact_keys")
                    == [
                        "container_id",
                        "created_at",
                        "finished_at",
                        "full_image_reference",
                        "image_id",
                        "name",
                        "restart_count",
                        "runtime_state",
                        "started_at",
                    ]
                    and oracle.get("argv_measurement")
                    == "sum_os_fsencode_argument_bytes_plus_one_nul_per_argument"
                    and oracle.get("shell_used") is False
                    and oracle.get("full_inspect_json_fallback") is False
                    and oracle.get("raw_process_fields_returned") is False,
                    path,
                    context,
                    "production Docker projections, argv bytes, and process "
                    "output caps must remain exact",
                )
                continue

            if (
                case_id
                == "fake_docker_transcript_projects_one_selected_container"
            ):
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                processes = input_data.get("processes")
                daemon_object = input_data.get("synthetic_daemon_object", {})
                if not self.require(
                    isinstance(processes, list)
                    and len(processes) == 2
                    and all(
                        isinstance(process, dict) for process in processes
                    ),
                    path,
                    context,
                    "fake-Docker success transcript must contain exactly one "
                    "catalogue and one selected-container inspect process",
                ):
                    continue
                catalogue, inspect = processes
                try:
                    catalogue_rows = [
                        json.loads(line)
                        for line in catalogue.get("stdout", "").splitlines()
                    ]
                    inspect_rows = [
                        json.loads(line)
                        for line in inspect.get("stdout", "").splitlines()
                    ]
                except (TypeError, ValueError):
                    catalogue_rows = []
                    inspect_rows = []
                selected = [
                    row
                    for row in catalogue_rows
                    if isinstance(row, dict)
                    and any(
                        fnmatch.fnmatchcase(row.get("name", ""), pattern)
                        for pattern in input_data.get(
                            "normalized_scope", []
                        )
                    )
                ]
                selected_ids = [row.get("id") for row in selected]
                projected = inspect_rows[0] if len(inspect_rows) == 1 else {}
                normalized = {
                    "name": projected.get("name", "").removeprefix("/"),
                    "container_id": projected.get("container_id"),
                    "full_image_reference": projected.get(
                        "full_image_reference"
                    ),
                    "image_id": projected.get("image_id"),
                    "runtime_state": projected.get("runtime_state"),
                    "created_at": projected.get("created_at"),
                    "started_at": projected.get("started_at"),
                    "finished_at": (
                        None
                        if projected.get("finished_at")
                        == "0001-01-01T00:00:00Z"
                        else projected.get("finished_at")
                    ),
                    "restart_count": projected.get("restart_count"),
                }
                canary = daemon_object.get(
                    "synthetic_unprojected_canary"
                )
                process_bytes = json.dumps(processes, sort_keys=True)
                oracle_bytes = json.dumps(oracle, sort_keys=True)
                expected_catalogue_argv = [
                    "/usr/bin/docker",
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--format",
                    '{"id":{{json .ID}},"name":{{json .Names}}}',
                ]
                expected_inspect_fixed_argv = [
                    "/usr/bin/docker",
                    "container",
                    "inspect",
                    "--format",
                    '{"container_id":{{json .Id}},'
                    '"created_at":{{json .Created}},'
                    '"finished_at":{{json .State.FinishedAt}},'
                    '"full_image_reference":{{json .Config.Image}},'
                    '"image_id":{{json .Image}},'
                    '"name":{{json .Name}},'
                    '"restart_count":{{json .RestartCount}},'
                    '"runtime_state":{{json .State.Status}},'
                    '"started_at":{{json .State.StartedAt}}}',
                ]
                expected_catalogue_stdout = (
                    '{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    'aaaaaaaaaaaaaaaa","name":"fixture-api"}\n'
                    '{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    'bbbbbbbbbbbbbbbb","name":"unrelated-api"}\n'
                )
                expected_inspect_stdout = (
                    '{"container_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    'aaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":'
                    '"2026-07-30T11:00:00Z","finished_at":'
                    '"0001-01-01T00:00:00Z","full_image_reference":'
                    '"registry.example.com/team/api:v1","image_id":'
                    '"sha256:111111111111111111111111111111111111111111111'
                    '1111111111111111111","name":"/fixture-api",'
                    '"restart_count":0,"runtime_state":"running",'
                    '"started_at":"2026-07-30T11:00:01Z"}\n'
                )
                self.require(
                    input_data.get("normalized_scope") == ["fixture-*"]
                    and catalogue.get("phase") == "catalogue"
                    and inspect.get("phase") == "inspect"
                    and catalogue.get("returncode")
                    == inspect.get("returncode")
                    == 0
                    and catalogue.get("stdout")
                    == expected_catalogue_stdout
                    and inspect.get("stdout") == expected_inspect_stdout
                    and catalogue.get("stderr")
                    == inspect.get("stderr")
                    == ""
                    and catalogue.get("monotonic_elapsed_seconds") == 0.10
                    and inspect.get("monotonic_elapsed_seconds") == 0.20
                    and catalogue.get("argv") == expected_catalogue_argv
                    and inspect.get("argv", [])[:-1]
                    == expected_inspect_fixed_argv
                    and len(catalogue_rows) == 2
                    and all(
                        set(row) == {"id", "name"}
                        for row in catalogue_rows
                    )
                    and len(selected_ids) == 1
                    and inspect.get("argv", [])[-1:] == selected_ids
                    and set(projected)
                    == {
                        "container_id",
                        "created_at",
                        "finished_at",
                        "full_image_reference",
                        "image_id",
                        "name",
                        "restart_count",
                        "runtime_state",
                        "started_at",
                    }
                    and normalized == oracle.get("normalized_container")
                    and oracle.get("docker_process_count")
                    == len(processes)
                    == 2
                    and oracle.get("catalogue_process_count") == 1
                    and oracle.get("inspect_process_count") == 1
                    and oracle.get("selected_container_ids")
                    == selected_ids
                    and oracle.get(
                        "out_of_scope_container_ids_not_inspected"
                    )
                    == [catalogue_rows[1].get("id")]
                    and oracle.get("observation_status") == "complete"
                    and oracle.get("reason_code") is None
                    and oracle.get("metadata_gaps") == []
                    and canary == "SYNTHETIC_CANARY_DO_NOT_RETURN"
                    and canary not in process_bytes
                    and canary not in oracle_bytes
                    and oracle.get("synthetic_canary_returned") is False
                    and oracle.get("raw_stdout_returned") is False
                    and oracle.get("raw_stderr_returned") is False
                    and oracle.get("shell_used") is False,
                    path,
                    context,
                    "exact fake-Docker argv/stdout transcripts must prefilter "
                    "scope, normalize only projected fields, and exclude the "
                    "synthetic unprojected canary",
                )
                continue

            if case_id == "fake_docker_no_such_object_race_is_partial":
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                process = input_data.get("process", {})
                requested_id = input_data.get("requested_container_id")
                expected_stderr = (
                    f"Error: No such object: {requested_id}\n"
                    if isinstance(requested_id, str)
                    else None
                )
                expected_fixed_argv = [
                    "/usr/bin/docker",
                    "container",
                    "inspect",
                    "--format",
                    '{"container_id":{{json .Id}},'
                    '"created_at":{{json .Created}},'
                    '"finished_at":{{json .State.FinishedAt}},'
                    '"full_image_reference":{{json .Config.Image}},'
                    '"image_id":{{json .Image}},'
                    '"name":{{json .Name}},'
                    '"restart_count":{{json .RestartCount}},'
                    '"runtime_state":{{json .State.Status}},'
                    '"started_at":{{json .State.StartedAt}}}',
                ]
                self.require(
                    isinstance(requested_id, str)
                    and CONTAINER_ID_RE.fullmatch(requested_id) is not None
                    and process.get("phase") == "inspect"
                    and process.get("argv", [])[:-1]
                    == expected_fixed_argv
                    and process.get("argv", [])[-1:] == [requested_id]
                    and process.get("returncode") == 1
                    and process.get("stdout") == ""
                    and process.get("stderr") == expected_stderr
                    and process.get("monotonic_elapsed_seconds") == 0.05
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "required_field_missing"
                    and oracle.get("metadata_gaps")
                    == ["fixture-api.container_inspect"]
                    and oracle.get("absence_authoritative") is False
                    and oracle.get("generated_warning")
                    == OBSERVATION_WARNING_BY_REASON[
                        "required_field_missing"
                    ]
                    and oracle.get("stderr_classifier")
                    == "exact_no_such_object_prefix_and_requested_id"
                    and requested_id
                    not in oracle.get("generated_warning", "")
                    and oracle.get("raw_stdout_returned") is False
                    and oracle.get("raw_stderr_returned") is False
                    and oracle.get("shell_used") is False,
                    path,
                    context,
                    "the exact Docker no-such-object race must classify as "
                    "partial missing evidence without returning raw stderr",
                )
                continue

            if (
                case_id
                == "fake_docker_success_with_bounded_stderr_is_accepted"
            ):
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                process = input_data.get("process", {})
                expected_argv = [
                    "/usr/bin/docker",
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--format",
                    '{"id":{{json .ID}},"name":{{json .Names}}}',
                ]
                stderr = process.get("stderr")
                self.require(
                    process.get("phase") == "catalogue"
                    and process.get("argv") == expected_argv
                    and process.get("returncode") == 0
                    and process.get("stdout") == ""
                    and stderr
                    == "WARNING: synthetic deprecation notice\n"
                    and isinstance(stderr, str)
                    and 0 < len(stderr.encode("utf-8")) <= 65536
                    and all(
                        len(line.encode("utf-8")) <= 8192
                        for line in stderr.splitlines()
                    )
                    and process.get("monotonic_elapsed_seconds") == 0.05
                    and oracle
                    == {
                        "observation_status": "complete",
                        "reason_code": None,
                        "containers": {},
                        "generated_warnings": [],
                        "stderr_disposition": (
                            "discarded_without_classification"
                        ),
                        "stderr_cap_still_enforced": True,
                        "raw_stdout_returned": False,
                        "raw_stderr_returned": False,
                        "shell_used": False,
                    },
                    path,
                    context,
                    "exit-zero valid stdout must remain authoritative when "
                    "bounded stderr is nonempty, without exposing or "
                    "classifying that stderr",
                )
                continue

            if case_id == "public_input_contract_is_frozen":
                public_variables = case.get("public_variables")
                internal_constants = case.get("internal_constants")
                oracle = case.get("oracle")
                exact_public_variables = {
                    "docker_ansible_summary_enabled": {
                        "presence": "defaulted",
                        "type": "boolean",
                        "default": True,
                    },
                    "docker_ansible_summary_operation": {
                        "presence": "required",
                        "type": "string",
                        "allowed_values": ["pre", "post", "status"],
                    },
                    "docker_ansible_summary_instance_id": {
                        "presence": "required",
                        "type": "string",
                        "pattern": "[a-z0-9][a-z0-9_-]{0,62}",
                    },
                    "docker_ansible_summary_scope": {
                        "presence": "required",
                        "type": "ascii_fnmatch_scalar_or_list",
                        "matcher": "python_fnmatch_fnmatchcase",
                        "max_normalized_patterns": 64,
                        "max_pattern_ascii_bytes": 256,
                        "max_normalized_ascii_bytes": 4096,
                    },
                    "docker_ansible_summary_record_id": {
                        "presence": "optional",
                        "type": "string",
                        "default": "omitted",
                        "pattern": "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                    },
                    "docker_ansible_summary_state_root": {
                        "presence": "defaulted",
                        "type": "posix_path",
                        "default": "/var/lib/docker-ansible-summary",
                        "constraints": [
                            "absolute",
                            "non_root",
                            "exact_normal_form",
                        ],
                    },
                    "docker_ansible_summary_journal_max_records": {
                        "presence": "defaulted",
                        "type": "integer",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "docker_ansible_summary_state_max_bytes": {
                        "presence": "defaulted",
                        "type": "integer",
                        "default": 16777216,
                        "minimum": 1048576,
                        "maximum": 268435456,
                    },
                    "docker_ansible_summary_correlation_id": {
                        "presence": "optional",
                        "type": "string",
                        "default": "omitted",
                        "maximum_utf8_bytes": 256,
                        "control_characters_allowed": False,
                    },
                    "docker_ansible_summary_report_mode": {
                        "presence": "defaulted",
                        "type": "string",
                        "default": "final",
                        "allowed_values": ["final", "each", "none"],
                    },
                    "docker_ansible_summary_report_width": {
                        "presence": "defaulted",
                        "type": "integer",
                        "default": 120,
                        "minimum": 100,
                        "maximum": 240,
                    },
                    "docker_ansible_summary_discovery_timeout_seconds": {
                        "presence": "defaulted",
                        "type": "integer",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 300,
                    },
                    "docker_ansible_summary_failure_policy": {
                        "presence": "defaulted",
                        "type": "string",
                        "default": "report",
                        "allowed_values": [
                            "report",
                            "fail_after_report",
                        ],
                    },
                }
                exact_internal_constants = {
                    "container_chunk_max_items": 100,
                    "complete_argv_max_bytes": 8192,
                    "state_lock_timeout_seconds": 5,
                }
                required_variables = {
                    name
                    for name, contract in exact_public_variables.items()
                    if contract.get("presence") == "required"
                }
                optional_variables = {
                    name
                    for name, contract in exact_public_variables.items()
                    if contract.get("presence") == "optional"
                }
                self.require(
                    public_variables == exact_public_variables
                    and len(public_variables) == 13
                    and all(
                        name.startswith("docker_ansible_summary_")
                        for name in public_variables
                    )
                    and required_variables
                    == {
                        "docker_ansible_summary_operation",
                        "docker_ansible_summary_instance_id",
                        "docker_ansible_summary_scope",
                    }
                    and optional_variables
                    == {
                        "docker_ansible_summary_record_id",
                        "docker_ansible_summary_correlation_id",
                    }
                    and internal_constants == exact_internal_constants
                    and internal_constants.get(
                        "container_chunk_max_items"
                    )
                    == container_limit
                    and internal_constants.get("complete_argv_max_bytes")
                    == default_byte_limit
                    and not {
                        "docker_ansible_summary_container_chunk_max_items",
                        "docker_ansible_summary_complete_argv_max_bytes",
                        "docker_ansible_summary_state_lock_timeout_seconds",
                    }
                    & set(public_variables)
                    and isinstance(oracle, dict)
                    and oracle
                    == {
                        "exact_public_variable_count": 13,
                        "strict_namespaced_allowlist": True,
                        "unknown_namespaced_variable_rejected": True,
                        "predecessor_namespace_variable_rejected": True,
                        "registered_output_name_exempt":
                            "docker_ansible_summary_result",
                        "defaults_are_documented_namespaced_defaults_only":
                            True,
                        "internal_constants_are_not_public_inputs": True,
                    },
                    path,
                    context,
                    "the public input allowlist, required/optional fields, "
                    "defaults, bounds, and three private constants must be "
                    "exactly frozen",
                )
                continue

            if case_id == "static_import_repeated_handoff_is_host_local":
                input_data = case.get("input")
                oracle = case.get("oracle")
                invocation = (
                    input_data.get("invocation")
                    if isinstance(input_data, dict)
                    else None
                )
                pre_ids = (
                    input_data.get("pre_record_ids")
                    if isinstance(input_data, dict)
                    else None
                )
                post_ids = (
                    input_data.get("post_record_ids")
                    if isinstance(input_data, dict)
                    else None
                )
                reference_role_task = (
                    input_data.get("reference_role_task")
                    if isinstance(input_data, dict)
                    else None
                )
                record_id_expression = (
                    input_data.get("post_record_id_expression")
                    if isinstance(input_data, dict)
                    else None
                )
                access_paths = (
                    oracle.get("exact_record_id_access_paths")
                    if isinstance(oracle, dict)
                    else None
                )
                self.require(
                    isinstance(invocation, dict)
                    and invocation
                    == {
                        "module": "ansible.builtin.import_role",
                        "tasks_from": "observe",
                        "allow_duplicates": True,
                        "public_parameter": "omitted",
                    }
                    and input_data.get("provisional_ansible_core_floor")
                    == "2.15.1"
                    and input_data.get("phases") == ["pre", "post"]
                    and input_data.get("hosts")
                    == [
                        "fixture-a.example.com",
                        "fixture-b.example.com",
                    ]
                    and input_data.get("registered_result_name")
                    == "docker_ansible_summary_result"
                    and reference_role_task
                    == {
                        "action_plugin_and_module":
                            "docker_ansible_summary",
                        "register": "docker_ansible_summary_result",
                        "result_projection": "direct",
                    }
                    and record_id_expression
                    == "{{ docker_ansible_summary_result.record_id }}"
                    and isinstance(pre_ids, dict)
                    and post_ids == pre_ids
                    and len(set(pre_ids.values())) == len(pre_ids)
                    and isinstance(oracle, dict)
                    and oracle.get("role_task_starts_per_phase") == 1
                    and oracle.get(
                        "separate_include_success_events_per_phase"
                    )
                    == 0
                    and oracle.get("remote_module_invocations_per_phase") == 1
                    and oracle.get(
                        "post_uses_host_local_registered_record_id"
                    )
                    is True
                    and oracle.get("cross_host_record_id_contamination")
                    is False
                    and access_paths
                    == {
                        "pre_output":
                            "docker_ansible_summary_result.record_id",
                        "post_input":
                            "docker_ansible_summary_result.record_id",
                    }
                    and oracle.get("forbidden_nested_record_id_path")
                    == (
                        "docker_ansible_summary_result."
                        "docker_ansible_summary_result.record_id"
                    )
                    and record_id_expression.strip("{} ")
                    == access_paths.get("post_input")
                    and oracle.get(
                        "documented_namespaced_defaults_public_at_candidate_floor"
                    )
                    is True
                    and oracle.get("internal_yaml_variables_present") is False
                    and oracle.get("role_vars_main_present") is False
                    and oracle.get("facts_created") == []
                    and oracle.get("quiet_reference_contract_satisfied")
                    is True,
                    path,
                    context,
                    "static import must preserve one-task execution and "
                    "host-local repeated hand-off with bounded public exposure",
                )
                continue

            if case_id == "dynamic_include_exceeds_reference_event_budget":
                input_data = case.get("input")
                oracle = case.get("oracle")
                invocation = (
                    input_data.get("invocation")
                    if isinstance(input_data, dict)
                    else None
                )
                self.require(
                    isinstance(invocation, dict)
                    and invocation
                    == {
                        "module": "ansible.builtin.include_role",
                        "tasks_from": "observe",
                        "allow_duplicates": True,
                        "public": False,
                    }
                    and input_data.get("phases") == ["pre", "post"]
                    and isinstance(oracle, dict)
                    and oracle.get("semantic_handoff_supported") is True
                    and oracle.get("visible_success_events_per_phase") == 2
                    and oracle.get(
                        "separate_include_success_events_per_phase"
                    )
                    == 1
                    and oracle.get("role_task_starts_per_phase") == 1
                    and oracle.get("quiet_reference_contract_satisfied")
                    is False
                    and oracle.get("v1_reference_invocation") is False,
                    path,
                    context,
                    "dynamic inclusion may work semantically but must remain "
                    "outside the one-visible-task reference budget",
                )
                continue

            if case_id == "enabled_missing_inputs_fails_before_module":
                input_data = case.get("input")
                oracle = case.get("oracle")
                self.require(
                    isinstance(input_data, dict)
                    and input_data
                    == {
                        "enabled": True,
                        "operation": "omitted",
                        "instance_id": "omitted",
                        "scope": "omitted",
                    }
                    and isinstance(oracle, dict)
                    and oracle.get("controller_validation_attempted") is True
                    and oracle.get("failure_reason") == "invalid_input"
                    and oracle.get("task_failed") is True
                    and oracle.get("remote_module_invocations") == 0
                    and oracle.get("controller_display_actions") == 1
                    and oracle.get("docker_processes") == 0
                    and oracle.get("filesystem_side_effects") == []
                    and oracle.get("remote_temporary_files_created") == 0,
                    path,
                    context,
                    "enabled missing inputs must emit one safe diagnostic and "
                    "fail controller-locally before module, Docker, or "
                    "filesystem work",
                )
                continue

            if case_id == "module_result_is_sanitized":
                input_data = case.get("input")
                oracle = case.get("oracle")
                exact_machine_fields = (
                    self.schema.get("oracle", {}).get(
                        "machine_result_exact_v1_fields"
                    )
                )
                exact_role_authored_keys = (
                    oracle.get("exact_role_authored_top_level_keys")
                    if isinstance(oracle, dict)
                    else None
                )
                forbidden = (
                    set(oracle.get("forbidden_returned_keys", []))
                    if isinstance(oracle, dict)
                    else set()
                )
                self.require(
                    isinstance(input_data, dict)
                    and input_data.get("enabled") is True
                    and set(input_data.get("synthetic_module_result_keys", []))
                    == {
                        "changed",
                        "invocation",
                        "stdout",
                        "stderr",
                        "observation",
                        "safe_reason",
                    }
                    and isinstance(oracle, dict)
                    and isinstance(exact_machine_fields, list)
                    and len(exact_machine_fields) == 18
                    and exact_role_authored_keys
                    == ["changed", *exact_machine_fields]
                    and len(set(exact_role_authored_keys)) == 19
                    and oracle.get("exact_machine_field_count") == 18
                    and oracle.get("changed") is False
                    and oracle.get("machine_fields_are_direct") is True
                    and oracle.get("nested_result_payload_key_present")
                    is False
                    and forbidden
                    == {
                        "invocation",
                        "stdout",
                        "stderr",
                        "docker_ansible_summary_result",
                    }
                    and set(exact_role_authored_keys).isdisjoint(forbidden)
                    and oracle.get("module_result_passthrough") is False
                    and oracle.get("public_result_built_from_allowlist")
                    is True
                    and oracle.get(
                        "framework_private_executor_decorations_outside_projection"
                    )
                    is True,
                    path,
                    context,
                    "the registered result must directly project changed:false "
                    "plus 18 allowlisted machine fields, without a nested "
                    "payload or private module/executor data",
                )
                continue

            if case_id == "argument_byte_limit_splits_before_item_limit":
                input_data = case.get("input")
                item_only = case.get("item_only_chunks")
                expected_chunks = case.get("expected_chunks")
                oracle = case.get("oracle")
                fixed_argv = (
                    input_data.get("fixed_argv")
                    if isinstance(input_data, dict)
                    else None
                )
                identifiers = (
                    input_data.get("container_identifiers")
                    if isinstance(input_data, dict)
                    else None
                )
                byte_limit = (
                    input_data.get(
                        "fixture_internal_argument_byte_limit_bytes"
                    )
                    if isinstance(input_data, dict)
                    else None
                )
                concrete_chunks: list[list[str]] = []
                complete_argv_bytes: list[int] = []
                oversize: list[str] = []
                concrete_inputs_valid = (
                    isinstance(fixed_argv, list)
                    and all(
                        isinstance(argument, str)
                        for argument in fixed_argv
                    )
                    and isinstance(identifiers, list)
                    and all(
                        isinstance(identifier, str)
                        and CONTAINER_ID_RE.fullmatch(identifier) is not None
                        for identifier in identifiers
                    )
                    and self.is_int(byte_limit)
                    and byte_limit > 0
                )
                if concrete_inputs_valid:
                    (
                        concrete_chunks,
                        complete_argv_bytes,
                        oversize,
                    ) = partition_concrete_identifiers(
                        fixed_argv,
                        identifiers,
                        container_limit,
                        byte_limit,
                    )
                expected_identifiers = [
                    f"{index:064x}" for index in range(10)
                ]
                chunk_suffixes = [
                    "".join(identifier[-1] for identifier in chunk)
                    for chunk in concrete_chunks
                ]
                item_only_chunk_count = (
                    (
                        len(identifiers)
                        + container_limit
                        - 1
                    )
                    // container_limit
                    if isinstance(identifiers, list)
                    and self.is_int(container_limit)
                    and container_limit > 0
                    else None
                )
                self.require(
                    concrete_inputs_valid
                    and fixed_argv
                    == ["/usr/bin/docker", "container", "inspect"]
                    and encoded_argv_bytes(fixed_argv) == 34
                    and identifiers == expected_identifiers
                    and len(set(identifiers)) == 10
                    and all(
                        encoded_argv_bytes([identifier]) == 65
                        for identifier in identifiers
                    )
                    and byte_limit == 229
                    and [len(chunk) for chunk in concrete_chunks]
                    == [3, 3, 3, 1]
                    and complete_argv_bytes == [229, 229, 229, 99]
                    and oversize == []
                    and item_only
                    == {"container_inspect": item_only_chunk_count}
                    == {"container_inspect": 1}
                    and expected_chunks == {"container_inspect": 4}
                    and isinstance(oracle, dict)
                    and oracle.get("chunk_order") == "stable_input_order"
                    and oracle.get(
                        "byte_accounting_includes_complete_argv_and_nuls"
                    )
                    is True
                    and oracle.get("chunk_identifier_suffixes")
                    == chunk_suffixes
                    == ["012", "345", "678", "9"]
                    and oracle.get("complete_argv_bytes_by_chunk")
                    == complete_argv_bytes
                    and oracle.get("largest_complete_argv_bytes")
                    == max(complete_argv_bytes)
                    == byte_limit
                    and oracle.get("argument_byte_limit_is_binding") is True
                    and oracle.get("chunks_differ_from_item_only") is True
                    and oracle.get("remote_module_invocations") == 1
                    and oracle.get("role_owned_task_starts") == 1
                    and oracle.get("controller_display_actions") == 1
                    and oracle.get("per_object_ansible_events") == 0
                    and oracle.get("registered_result_dumps") == 0
                    and oracle.get("censored_no_log_results") == 0
                    and oracle.get(
                        "normal_verbosity_incidental_lines"
                    )
                    == 0
                    and oracle.get("ansible_changed") is False
                    and oracle.get("human_table_blocks") == 1
                    and oracle.get(
                        "intentional_table_lines_excluded_from_noise_budget"
                    )
                    is True
                    and oracle.get("docker_processes")
                    == {
                        "container_list": 1,
                        "container_inspect": len(concrete_chunks),
                        "total": 1 + len(concrete_chunks),
                    },
                    path,
                    context,
                    "concrete os.fsencode-plus-NUL argv arithmetic must "
                    "derive four stable inspect chunks before the 100-item "
                    "limit binds",
                )
                continue

            if case_id == "oversize_identifier_is_not_invoked_or_echoed":
                input_data = case.get("input")
                chunks = case.get("expected_chunks")
                oracle = case.get("oracle")
                fixed_argv = (
                    input_data.get("fixed_argv")
                    if isinstance(input_data, dict)
                    else None
                )
                identifiers = (
                    input_data.get("container_identifiers")
                    if isinstance(input_data, dict)
                    else None
                )
                byte_limit = (
                    input_data.get(
                        "fixture_internal_argument_byte_limit_bytes"
                    )
                    if isinstance(input_data, dict)
                    else None
                )
                concrete_chunks: list[list[str]] = []
                complete_argv_bytes: list[int] = []
                oversize: list[str] = []
                concrete_inputs_valid = (
                    isinstance(fixed_argv, list)
                    and all(
                        isinstance(argument, str)
                        for argument in fixed_argv
                    )
                    and isinstance(identifiers, list)
                    and len(identifiers) == 1
                    and all(
                        isinstance(identifier, str)
                        and CONTAINER_ID_RE.fullmatch(identifier) is not None
                        for identifier in identifiers
                    )
                    and self.is_int(byte_limit)
                    and byte_limit > 0
                )
                if concrete_inputs_valid:
                    (
                        concrete_chunks,
                        complete_argv_bytes,
                        oversize,
                    ) = partition_concrete_identifiers(
                        fixed_argv,
                        identifiers,
                        container_limit,
                        byte_limit,
                    )
                identifier = (
                    identifiers[0]
                    if isinstance(identifiers, list) and identifiers
                    else None
                )
                minimum_complete_argv_bytes = (
                    encoded_argv_bytes(fixed_argv + [identifier])
                    if isinstance(fixed_argv, list)
                    and isinstance(identifier, str)
                    else None
                )
                self.require(
                    concrete_inputs_valid
                    and isinstance(input_data, dict)
                    and input_data.get("enabled") is True
                    and input_data.get("operation") == "status"
                    and input_data.get("observation_status") == "partial"
                    and input_data.get("listed_container_ids") == 1
                    and input_data.get("selected_container_ids") == 1
                    and fixed_argv
                    == ["/usr/bin/docker", "container", "inspect"]
                    and encoded_argv_bytes(fixed_argv) == 34
                    and identifiers == ["a" * 64]
                    and encoded_argv_bytes(identifiers) == 65
                    and byte_limit == 98
                    and minimum_complete_argv_bytes == 99
                    and concrete_chunks == []
                    and complete_argv_bytes == []
                    and oversize == identifiers
                    and chunks == {"container_inspect": 0}
                    and isinstance(oracle, dict)
                    and oracle.get("observation_status") == "partial"
                    and oracle.get("reason_code")
                    == "inspect_identifier_argv_too_large"
                    and oracle.get("minimum_complete_argv_bytes")
                    == minimum_complete_argv_bytes
                    and oracle.get("oversize_identifier_invoked") is False
                    and oracle.get("oversize_identifier_returned") is False
                    and identifier not in json.dumps(
                        oracle,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    and oracle.get("unbounded_fallback_used") is False
                    and oracle.get("docker_processes")
                    == {
                        "container_list": 1,
                        "container_inspect": 0,
                        "total": 1,
                    },
                    path,
                    context,
                    "one identifier that cannot fit the complete argv must "
                    "produce safe partial evidence without invocation or echo",
                )
                continue

            if (
                case_id
                == "none_mode_noncomplete_warning_matrix_is_exact"
            ):
                input_data = case.get("input", {})
                oracle = case.get("oracle", {})
                variants = input_data.get("variants")
                expected_variants = {
                    "pre_partial": {
                        "operation": "pre",
                        "observation_status": "partial",
                        "observation_reason": "required_field_missing",
                    },
                    "pre_unavailable": {
                        "operation": "pre",
                        "observation_status": "unavailable",
                        "observation_reason": "docker_unavailable",
                    },
                    "post_partial": {
                        "operation": "post",
                        "observation_status": "partial",
                        "observation_reason": "required_field_missing",
                    },
                    "post_unavailable": {
                        "operation": "post",
                        "observation_status": "unavailable",
                        "observation_reason": "docker_unavailable",
                    },
                    "status_partial": {
                        "operation": "status",
                        "observation_status": "partial",
                        "observation_reason": "required_field_missing",
                    },
                    "status_unavailable": {
                        "operation": "status",
                        "observation_status": "unavailable",
                        "observation_reason": "docker_unavailable",
                    },
                }
                expected_blocks: dict[str, str] = {}
                if isinstance(variants, dict):
                    for variant_id, variant in variants.items():
                        if not isinstance(variant, dict):
                            continue
                        expected_blocks[variant_id] = (
                            "DAS warning | "
                            f"host={input_data.get('host')} | "
                            f"instance={input_data.get('instance_id')} | "
                            f"operation={variant.get('operation')}\n"
                            f"Observation "
                            f"{variant.get('observation_status')} | "
                            f"reason={variant.get('observation_reason')} | "
                            "table suppressed in report_mode=none"
                        )
                declared_blocks = oracle.get("exact_warning_blocks")
                self.require(
                    input_data.get("report_mode") == "none"
                    and input_data.get("failure_policy") == "report"
                    and input_data.get("report_width") == 100
                    and input_data.get("host")
                    == "fixture-none.example.com"
                    and input_data.get("instance_id") == "fixture-mdad"
                    and variants == expected_variants
                    and declared_blocks == expected_blocks
                    and isinstance(declared_blocks, dict)
                    and all(
                        len(block.splitlines()) == 2
                        and all(
                            len(line) <= 100
                            for line in block.splitlines()
                        )
                        for block in declared_blocks.values()
                    )
                    and oracle.get(
                        "controller_display_actions_per_variant"
                    )
                    == 1
                    and oracle.get(
                        "compact_warning_blocks_per_variant"
                    )
                    == 1
                    and oracle.get(
                        "exact_warning_line_count_per_variant"
                    )
                    == 2
                    and oracle.get("human_table_blocks_per_variant") == 0
                    and oracle.get("catalogue_dumped") is False
                    and oracle.get("task_failed_per_variant") is False
                    and oracle.get(
                        "machine_result_present_per_variant"
                    )
                    is True
                    and oracle.get("warning_suppressed") is False
                    and oracle.get("informational_footer_suppressed")
                    is True,
                    path,
                    context,
                    "none mode with report policy must route each partial or "
                    "unavailable operation through one exact successful "
                    "two-line warning block without a table",
                )
                continue

            if not self.require_keys(
                case, ["input", "expected_chunks", "oracle"], path, context
            ):
                continue
            input_data = case.get("input")
            chunks = case.get("expected_chunks")
            oracle = case.get("oracle")
            if not (
                self.require(
                    isinstance(input_data, dict),
                    path,
                    f"{context}.input",
                    "must be a mapping",
                )
                and self.require(
                    isinstance(chunks, dict),
                    path,
                    f"{context}.expected_chunks",
                    "must be a mapping",
                )
                and self.require(
                    isinstance(oracle, dict),
                    path,
                    f"{context}.oracle",
                    "must be a mapping",
                )
            ):
                continue

            enabled = input_data.get("enabled")
            listed_count = input_data.get("listed_container_ids")
            selected_count = input_data.get("selected_container_ids")
            report_row_count = input_data.get(
                "selected_union_report_rows",
                0 if enabled is False else None,
            )
            self.require(
                isinstance(enabled, bool),
                path,
                f"{context}.input.enabled",
                "must be boolean",
            )
            counts_valid = (
                self.is_int(listed_count)
                and listed_count >= 0
                and self.is_int(selected_count)
                and 0 <= selected_count <= listed_count
                and self.is_int(report_row_count)
                and report_row_count >= 0
            )
            self.require(
                counts_valid,
                path,
                f"{context}.input",
                "catalogue/selected/report counts must be non-negative and "
                "selection cannot exceed the catalogue",
            )

            byte_limit = input_data.get(
                "argument_byte_limit_bytes", default_byte_limit
            )
            fixed_argv_bytes = input_data.get(
                "fixed_argv_bytes_including_nuls", 68
            )
            identifier_count = input_data.get(
                "container_identifier_count", selected_count
            )
            identifier_bytes = input_data.get(
                "container_identifier_bytes_including_nul",
                default_container_bytes,
            )
            lengths_valid = (
                self.is_int(byte_limit)
                and byte_limit > 0
                and self.is_int(fixed_argv_bytes)
                and fixed_argv_bytes > 0
                and self.is_int(identifier_count)
                and identifier_count == selected_count
                and self.is_int(identifier_bytes)
                and identifier_bytes > 0
                and fixed_argv_bytes + identifier_bytes <= byte_limit
            )
            self.require(
                lengths_valid,
                path,
                f"{context}.input",
                "complete argv components must be positive, fit the byte "
                "limit, and match the selected count",
            )

            if limits_valid and counts_valid and lengths_valid:
                expected_container_chunks = bounded_chunk_count(
                    selected_count,
                    container_limit,
                    byte_limit,
                    fixed_argv_bytes,
                    identifier_bytes,
                )
            else:
                expected_container_chunks = None
            self.require(
                chunks.get("container_inspect")
                == expected_container_chunks
                and set(chunks) == {"container_inspect"},
                path,
                f"{context}.expected_chunks",
                "container inspect chunks must obey both the declared item "
                "and complete-argv byte limits",
            )

            docker_processes = oracle.get("docker_processes")
            if self.require_keys(
                docker_processes,
                [
                    "container_list",
                    "container_inspect",
                    "total",
                ],
                path,
                f"{context}.oracle.docker_processes",
            ):
                expected_list_processes = 1 if enabled is True else 0
                expected_process_total = (
                    expected_list_processes
                    + expected_container_chunks
                    if self.is_int(expected_container_chunks)
                    else None
                )
                self.require(
                    docker_processes.get("container_list")
                    == expected_list_processes
                    and docker_processes.get("container_inspect")
                    == expected_container_chunks
                    and docker_processes.get("total")
                    == expected_process_total,
                    path,
                    f"{context}.oracle.docker_processes",
                    "Docker process total must equal list plus deterministic "
                    "inspect chunks",
                )

            expected_module_invocations = 1 if enabled is True else 0
            self.require(
                oracle.get("remote_module_invocations")
                == expected_module_invocations
                and oracle.get("role_owned_task_starts") == 1
                and oracle.get("per_object_ansible_events") == 0
                and oracle.get("ansible_changed") is False,
                path,
                f"{context}.oracle",
                "every invocation must use one action/module task, the "
                "expected remote call count, no per-object events, and no "
                "changed state",
            )
            for noise_key in (
                "registered_result_dumps",
                "censored_no_log_results",
                "normal_verbosity_incidental_lines",
            ):
                if enabled is True:
                    self.require(
                        oracle.get(noise_key) == 0,
                        path,
                        f"{context}.oracle.{noise_key}",
                        "enabled operations must declare zero incidental result "
                        "noise beyond the callback envelope",
                    )
            if "controller_display_actions" in oracle:
                self.require(
                    self.is_int(oracle["controller_display_actions"])
                    and 0 <= oracle["controller_display_actions"] <= 1,
                    path,
                    f"{context}.oracle.controller_display_actions",
                    "controller display action budget must be at most one",
                )
            if enabled is True:
                self.require(
                    oracle.get(
                        "intentional_table_lines_excluded_from_noise_budget"
                    )
                    is True,
                    path,
                    f"{context}.oracle."
                    "intentional_table_lines_excluded_from_noise_budget",
                    "intentional report lines must stay outside the noise budget",
                )

            operation = input_data.get("operation")
            report_mode = input_data.get("report_mode", "final")
            if enabled is True:
                self.enum(
                    report_mode,
                    {"final", "each", "none"},
                    path,
                    f"{context}.effective_report_mode",
                )
                self.enum(
                    operation,
                    {"pre", "post", "status"},
                    path,
                    f"{context}.input.operation",
                )
            if enabled is not True or report_mode == "none":
                expected_table_blocks = 0
            elif report_mode == "each":
                expected_table_blocks = 1
            else:
                expected_table_blocks = 0 if operation == "pre" else 1
            self.require(
                oracle.get("human_table_blocks") == expected_table_blocks,
                path,
                f"{context}.oracle.human_table_blocks",
                "table count must follow operation phase and report mode",
            )

            if enabled is not True:
                expected_display_actions = 0
            elif (
                case_id
                == "none_mode_fail_after_report_keeps_minimum_safe_diagnostic"
            ):
                expected_display_actions = 1
            elif report_mode == "none":
                expected_display_actions = 0
            elif report_mode == "each":
                expected_display_actions = 1
            elif operation == "pre":
                expected_display_actions = (
                    0
                    if input_data.get("observation_status") == "complete"
                    else 1
                )
            else:
                expected_display_actions = 1
            self.require(
                oracle.get("controller_display_actions")
                == expected_display_actions,
                path,
                f"{context}.oracle.controller_display_actions",
                "display calls must be exact: zero for quiet/none/disabled, "
                "one for the selected report or required diagnostic",
            )

            if case_id == "disabled_short_circuit_has_no_work":
                self.require(
                    enabled is False
                    and operation is None
                    and input_data.get("observation_status") is None
                    and listed_count == 0
                    and selected_count == 0
                    and oracle.get("controller_action_invocations") == 1
                    and oracle.get("remote_module_invocations") == 0
                    and oracle.get("controller_display_actions") == 0
                    and oracle.get("task_terminal_event") == "skipped"
                    and oracle.get("remote_temporary_files_created") == 0
                    and oracle.get("operation_specific_inputs_present")
                    is False
                    and chunks == {"container_inspect": 0}
                    and oracle.get("discovery_attempted") is False
                    and oracle.get("store_access_attempted") is False
                    and oracle.get("machine_result_status") == "skipped"
                    and docker_processes
                    == {
                        "container_list": 0,
                        "container_inspect": 0,
                        "total": 0,
                    },
                    path,
                    context,
                    "disabled execution must short-circuit with zero work",
                )
            elif case_id in {
                "partial_pre_final_emits_one_warning_without_table",
                "unavailable_pre_final_emits_one_warning_without_table",
            }:
                expected_status_reason = {
                    "partial_pre_final_emits_one_warning_without_table": (
                        "partial",
                        "required_field_missing",
                    ),
                    "unavailable_pre_final_emits_one_warning_without_table": (
                        "unavailable",
                        "docker_command_timeout",
                    ),
                }
                expected_status, expected_reason = expected_status_reason[
                    case_id
                ]
                expected_warning = (
                    "DAS warning | "
                    f"host={input_data.get('host')} | "
                    f"instance={input_data.get('instance_id')} | "
                    "operation=pre\n"
                    f"Observation {expected_status} | "
                    f"reason={expected_reason} | "
                    "table suppressed in report_mode=final"
                )
                warning_block = oracle.get("exact_warning_block")
                warning_lines = (
                    warning_block.splitlines()
                    if isinstance(warning_block, str)
                    else []
                )
                self.require(
                    operation == "pre"
                    and report_mode == "final"
                    and input_data.get("report_width") == 100
                    and isinstance(input_data.get("host"), str)
                    and bool(input_data["host"])
                    and input_data.get("instance_id") == "fixture-mdad"
                    and input_data.get("observation_status")
                    == expected_status
                    and input_data.get("observation_reason")
                    == expected_reason
                    and oracle.get("human_table_blocks") == 0
                    and oracle.get("compact_warning_blocks") == 1
                    and warning_block == expected_warning
                    and oracle.get("exact_warning_line_count") == 2
                    and len(warning_lines) == 2
                    and oracle.get("maximum_warning_line_width") == 100
                    and all(len(line) <= 100 for line in warning_lines)
                    and oracle.get("catalogue_dumped") is False,
                    path,
                    context,
                    "noncomplete pre in final mode must emit exactly one "
                    "exact two-line warning and no table or catalogue",
                )
            elif case_id == "complete_post_emits_one_final_block":
                self.require(
                    oracle.get("contiguous_host_blocks_required") is True
                    and oracle.get(
                        "single_display_call_is_sufficient_proof"
                    )
                    is False,
                    path,
                    f"{context}.oracle",
                    "final post report must require measured contiguous "
                    "transport rather than infer it from one display call",
                )
            elif case_id == "complete_pre_default_is_quiet":
                self.require(
                    listed_count == 250
                    and selected_count == 20
                    and report_row_count == 20
                    and oracle.get("unselected_catalogue_rows") == 230
                    and oracle.get("unselected_container_inspections") == 0
                    and chunks.get("container_inspect") == 1,
                    path,
                    context,
                    "ID/name catalogue scope selection must avoid inspecting "
                    "unselected containers",
                )
            elif case_id == "status_emits_one_store_free_block":
                self.require(
                    oracle.get("store_reads") == 0
                    and oracle.get("store_writes") == 0,
                    path,
                    f"{context}.oracle",
                    "status report must remain store-free",
                )
            elif case_id == "complete_empty_uses_only_catalogue_process":
                self.require(
                    input_data.get("pre_endpoint_present") is False
                    and report_row_count == 0
                    and oracle.get("comparison_shape")
                    == "post_only_current"
                    and oracle.get("primary_table_kind") == "current"
                    and oracle.get("run_window_comparison") is False
                    and oracle.get("zero_row_table_is_explicit") is True,
                    path,
                    f"{context}.oracle",
                    "post-only complete empty discovery must explicitly render "
                    "a zero-row current table without inventing a before endpoint",
                )
            elif (
                case_id
                == "complete_all_removals_zero_current_still_reports_union_rows"
            ):
                self.require(
                    input_data.get("pre_endpoint_present") is True
                    and input_data.get("pre_selected_rows") == 2
                    and listed_count == 0
                    and selected_count == 0
                    and report_row_count == 2
                    and oracle.get("comparison_shape")
                    == "complete_run_window"
                    and oracle.get("primary_table_kind") == "run_window"
                    and oracle.get("report_row_count") == 2
                    and oracle.get("removed_row_count") == 2
                    and oracle.get("after_marker") == "<absent>"
                    and oracle.get("generic_zero_row_message_forbidden")
                    is True,
                    path,
                    context,
                    "paired empty C must render every authoritative removal",
                )
            elif (
                case_id
                == "omitted_report_mode_defaults_final_and_display_is_last"
            ):
                trace = oracle.get("ordered_role_event_trace")
                self.require(
                    "report_mode" not in input_data
                    and report_mode == "final"
                    and oracle.get("effective_report_mode") == "final"
                    and trace
                    == [
                        "observe_compare_and_commit",
                        "display_and_finalize",
                    ]
                    and oracle.get("role_event_trace_granularity")
                    == "internal_single_action_phases"
                    and oracle.get("last_role_owned_event")
                    == "display_and_finalize"
                    and oracle.get("role_events_after_display") == []
                    and oracle.get("post_display_bookkeeping_events") == 0
                    and oracle.get("final_role_owned_output")
                    == "das_report"
                    and oracle.get("consumer_output_after_role_is_out_of_scope")
                    is True
                    and oracle.get("contiguous_host_blocks_required") is True
                    and oracle.get(
                        "single_display_call_is_sufficient_proof"
                    )
                    is False,
                    path,
                    context,
                    "omitted report mode must default to final and end the "
                    "single task with display/finalize",
                )
            elif case_id == "none_mode_suppresses_table_not_machine_result":
                final_case = next(
                    (
                        candidate
                        for candidate in cases
                        if candidate.get("id")
                        == "complete_post_emits_one_final_block"
                    ),
                    {},
                )
                self.require(
                    oracle.get("machine_result_present") is True
                    and oracle.get("machine_result_equivalent_to")
                    == final_case.get("id")
                    and input_data.get("observation_fixture_id")
                    == final_case.get("input", {}).get(
                        "observation_fixture_id"
                    )
                    and oracle.get("machine_result_equivalence_group")
                    == final_case.get("oracle", {}).get(
                        "machine_result_equivalence_group"
                    )
                    and oracle.get("machine_result_deep_equal") is True
                    and oracle.get("state_transition_deep_equal") is True
                    and oracle.get("persistence_result_deep_equal") is True
                    and oracle.get("replay_identity_equal") is True
                    and oracle.get("only_allowed_case_difference")
                    == "human_presentation"
                    and oracle.get(
                        "report_mode_controls_only_presentation"
                    )
                    is True
                    and oracle.get("hard_errors_suppressed") is False
                    and oracle.get(
                        "minimum_safe_failure_diagnostics_suppressed"
                    )
                    is False,
                    path,
                    f"{context}.oracle",
                    "none report mode must change only presentation and retain "
                    "all machine, transition, persistence, and failure semantics",
                )
            elif (
                case_id
                == "none_mode_fail_after_report_keeps_minimum_safe_diagnostic"
            ):
                diagnostic_fields = oracle.get(
                    "failure_diagnostic_contains"
                )
                self.require(
                    report_mode == "none"
                    and input_data.get("failure_policy")
                    == "fail_after_report"
                    and input_data.get("observation_status") == "unavailable"
                    and oracle.get(
                        "full_machine_result_in_failed_callback"
                    )
                    is False
                    and oracle.get("compact_failure_envelope_present")
                    is True
                    and oracle.get("failure_envelope_max_bytes") == 1024
                    and oracle.get(
                        "retained_full_result_replayable_with_report_policy"
                    )
                    is True
                    and oracle.get("task_failed") is True
                    and oracle.get("failure_reason")
                    == "observation_noncomplete"
                    and oracle.get("observation_reason")
                    == "docker_unavailable"
                    and oracle.get("hard_error_suppressed") is False
                    and oracle.get(
                        "minimum_safe_failure_diagnostic_blocks"
                    )
                    == 1
                    and oracle.get("diagnostic_rendered_before_failure")
                    is True
                    and oracle.get("full_table_suppressed") is True
                    and diagnostic_fields
                    == [
                        "host",
                        "instance_id",
                        "operation",
                        "failure_reason",
                        "observation_reason",
                    ],
                    path,
                    context,
                    "none mode must retain one safe diagnostic before "
                    "fail_after_report fails",
                )
            elif case_id == "large_catalogue_task_count_is_constant":
                target_ms = oracle.get("pure_pipeline_target_ms_max")
                self.require(
                    report_row_count == 500
                    and oracle.get("target_complexity")
                    == "O(G + R + N + K + S log S)"
                    and oracle.get("store_free_target_memory")
                    == "O(G + N + K + S)"
                    and oracle.get("writing_phase_additional_time")
                    == "O(P + Q)"
                    and oracle.get("writing_phase_additional_memory")
                    == "O(P + Q)"
                    and self.is_int(target_ms)
                    and 0 < target_ms <= 100
                    and oracle.get("absolute_timing_targets_provisional")
                    is True
                    and oracle.get("timing_target_freeze_condition")
                    == "adapter_spike_with_environment_metadata"
                    and oracle.get("benchmark_environment_required") is True
                    and oracle.get("benchmark_percentiles_required")
                    == ["p50", "p95"],
                    path,
                    f"{context}.oracle",
                    "large-catalogue fixture must retain its complexity, memory, "
                    "latency, environment, and percentile benchmark contract",
                )
            elif case_id == "synthetic_scaling_guard_100_to_1000":
                target_ms = oracle.get(
                    "one_thousand_pipeline_target_ms_max"
                )
                growth_factor = oracle.get(
                    "growth_factor_max_after_fixed_startup"
                )
                self.require(
                    input_data.get("comparison_sizes") == [100, 1000]
                    and input_data.get(
                        "comparison_selected_union_report_rows"
                    )
                    == [100, 1000]
                    and report_row_count == 1000
                    and chunks == {"container_inspect": 10}
                    and docker_processes
                    == {
                        "container_list": 1,
                        "container_inspect": 10,
                        "total": 11,
                    }
                    and self.is_int(target_ms)
                    and 0 < target_ms <= 1000
                    and (
                        self.is_int(growth_factor)
                        or isinstance(growth_factor, float)
                    )
                    and 0 < growth_factor <= 15
                    and oracle.get("absolute_timing_targets_provisional")
                    is True
                    and oracle.get("timing_target_freeze_condition")
                    == "adapter_spike_with_environment_metadata",
                    path,
                    context,
                    "100-to-1000 scaling guard must retain 10/11 process "
                    "arithmetic, <=1000 ms latency, and <=15x growth",
                )
            elif (
                case_id
                == "near_cap_store_rewrite_is_measured_and_bounded"
            ):
                state_max_bytes = input_data.get("state_max_bytes")
                pre_candidate_bytes = input_data.get(
                    "exact_candidate_store_bytes_before_pruning"
                )
                candidate_bytes = input_data.get(
                    "exact_candidate_store_bytes_after_pruning"
                )
                self.require(
                    input_data.get("retained_store_bytes_before")
                    == 15728640
                    and input_data.get(
                        "new_candidate_evidence_bytes_before_pruning"
                    )
                    == 1310720
                    and pre_candidate_bytes
                    == (
                        input_data.get("retained_store_bytes_before")
                        + input_data.get(
                            "new_candidate_evidence_bytes_before_pruning"
                        )
                    )
                    == 17039360
                    and state_max_bytes == 16777216
                    and candidate_bytes == 16515072
                    and candidate_bytes <= state_max_bytes
                    and pre_candidate_bytes > state_max_bytes
                    and oracle.get("state_work_complexity") == "O(P + Q)"
                    and oracle.get("state_memory_complexity") == "O(P + Q)"
                    and oracle.get("exact_candidate_within_byte_cap")
                    is True
                    and oracle.get("benchmark_store_profiles")
                    == ["empty", "typical", "near_cap"]
                    and oracle.get("measured_phases")
                    == [
                        "read",
                        "parse_validate",
                        "transition",
                        "canonical_serialize",
                        "fsync_replace",
                        "total",
                    ]
                    and oracle.get(
                        "absolute_state_timing_target_provisional"
                    )
                    is True
                    and oracle.get("timing_target_freeze_condition")
                    == "state_profile_benchmark",
                    path,
                    context,
                    "near-cap store fixture must bind P plus Q, exact byte safety, "
                    "and measured durable-replacement phases",
                )
    def validate_image_display_cases(
        self,
        path: Path,
        data: dict[str, Any],
        cases: list[dict[str, Any]],
    ) -> None:
        self.require(
            data.get("presentation_schema_version") == 1,
            path,
            "presentation_schema_version",
            "must equal 1",
        )

        def parse_supported_reference(reference: Any) -> dict[str, Any] | None:
            if not isinstance(reference, str) or not reference:
                return None
            if SHA256_RE.fullmatch(reference) is not None:
                digest_prefix = reference.split(":", 1)[1][:12]
                return {
                    "kind": "bare_image_id",
                    "repository": None,
                    "repository_basename": None,
                    "tag": None,
                    "digest": reference,
                    "digest_prefix_length": 12,
                    "compact_label": f"sha256:{digest_prefix}",
                }

            digest: str | None = None
            pre_digest = reference
            if "@" in reference:
                if reference.count("@") != 1:
                    return None
                pre_digest, digest_text = reference.rsplit("@", 1)
                digest = digest_text
                if SHA256_RE.fullmatch(digest) is None:
                    return None

            last_slash = pre_digest.rfind("/")
            last_colon = pre_digest.rfind(":")
            tag: str | None = None
            repository = pre_digest
            if last_colon > last_slash:
                repository = pre_digest[:last_colon]
                tag = pre_digest[last_colon + 1 :]
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
                        tag,
                    )
                    is None
                ):
                    return None

            components = repository.split("/")
            if not components or any(not component for component in components):
                return None
            authority_candidate = components[0]
            has_authority = len(components) >= 2 and (
                authority_candidate == "localhost"
                or "." in authority_candidate
                or ":" in authority_candidate
            )
            path_components = components
            if has_authority:
                path_components = components[1:]
                if authority_candidate.count(":") > 1:
                    return None
                authority_host = authority_candidate
                if ":" in authority_candidate:
                    authority_host, port_text = authority_candidate.rsplit(
                        ":", 1
                    )
                    if (
                        CANONICAL_PORT_RE.fullmatch(port_text) is None
                        or int(port_text) > 65535
                    ):
                        return None
                if authority_host != "localhost":
                    labels = authority_host.split(".")
                    if len(labels) < 2 or any(
                        AUTHORITY_LABEL_RE.fullmatch(label) is None
                        for label in labels
                    ):
                        return None
            if any(
                REPOSITORY_COMPONENT_RE.fullmatch(component) is None
                for component in path_components
            ):
                return None
            basename = path_components[-1]

            result: dict[str, Any] = {
                "kind": (
                    "tagged_digest_reference"
                    if tag is not None and digest is not None
                    else "digest_reference"
                    if digest is not None
                    else "tagged_reference"
                    if tag is not None
                    else "untagged_reference"
                ),
                "repository": repository,
                "repository_basename": basename,
                "tag": tag,
                "digest": digest,
            }
            if digest is not None:
                result["digest_prefix_length"] = 12
                digest_label = f"sha256:{digest.split(':', 1)[1][:12]}"
                result["compact_label"] = (
                    f"{basename}:{tag}@{digest_label}"
                    if tag is not None
                    else f"{basename}@{digest_label}"
                )
            elif tag is not None:
                result["compact_label"] = f"{basename}:{tag}"
            else:
                result["compact_label"] = (
                    f"{basename} <no explicit tag>"
                )
            return result

        def visible_escape_opaque(reference: str) -> tuple[str, list[str]]:
            atoms: list[str] = []
            for byte in reference.encode("ascii"):
                if 0x20 <= byte <= 0x7E and byte not in {
                    ord("\\"),
                    ord("|"),
                    ord("~"),
                    ord("#"),
                    ord("<"),
                    ord(">"),
                }:
                    atoms.append(chr(byte))
                else:
                    atoms.append(f"\\x{byte:02x}")
            return "".join(atoms), atoms

        def shorten_opaque_atoms(
            reference: str,
            width: int,
            *,
            suffix: str = "",
        ) -> tuple[str, str]:
            escaped_reference, reference_atoms = visible_escape_opaque(
                reference
            )
            atoms = [*reference_atoms, *list(suffix)]
            semantic = "o:" + "".join(atoms)
            if len(semantic) <= width:
                return semantic, escaped_reference
            payload_width = width - 2
            if payload_width == 1:
                return "o:~", escaped_reference
            left_budget = max(1, (2 * (payload_width - 1)) // 5)
            right_budget = payload_width - 1 - left_budget
            left_atoms: list[str] = []
            left_width = 0
            for atom in atoms:
                atom_width = len(atom)
                if left_width + atom_width > left_budget:
                    break
                left_atoms.append(atom)
                left_width += atom_width
            right_atoms: list[str] = []
            right_width = 0
            for atom in reversed(atoms):
                atom_width = len(atom)
                if right_width + atom_width > right_budget:
                    break
                right_atoms.append(atom)
                right_width += atom_width
            return (
                "o:"
                + "".join(left_atoms)
                + "~"
                + "".join(reversed(right_atoms)),
                escaped_reference,
            )

        parsing_expectations = {
            "registry_port_with_explicit_tag": {
                "kind": "tagged_reference",
                "repository": "registry.example.com:5443/team/api",
                "repository_basename": "api",
                "tag": "v1.2.3",
                "digest": None,
                "compact_label": "api:v1.2.3",
            },
            "registry_port_without_explicit_tag": {
                "kind": "untagged_reference",
                "repository": "registry.example.com:5443/team/api",
                "repository_basename": "api",
                "tag": None,
                "digest": None,
                "compact_label": "api <no explicit tag>",
            },
            "digest_reference": {
                "kind": "digest_reference",
                "repository": "registry.example.com/team/worker",
                "repository_basename": "worker",
                "tag": None,
                "digest": "sha256:"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "digest_prefix_length": 12,
                "compact_label": "worker@sha256:aaaaaaaaaaaa",
            },
            "tag_plus_digest_reference": {
                "kind": "tagged_digest_reference",
                "repository": "registry.example.com:5443/team/api",
                "repository_basename": "api",
                "tag": "v2",
                "digest": "sha256:"
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "digest_prefix_length": 12,
                "compact_label": "api:v2@sha256:bbbbbbbbbbbb",
            },
            "bare_image_id_reference": {
                "kind": "bare_image_id",
                "repository": None,
                "repository_basename": None,
                "tag": None,
                "digest": "sha256:"
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "digest_prefix_length": 12,
                "compact_label": "sha256:cccccccccccc",
            },
        }

        for case in cases:
            case_id = case.get("id")
            context = f"case {case_id!r}"
            input_data = case.get("input")
            oracle = case.get("oracle")
            if not (
                self.require(
                    isinstance(input_data, dict),
                    path,
                    f"{context}.input",
                    "must be a mapping",
                )
                and self.require(
                    isinstance(oracle, dict),
                    path,
                    f"{context}.oracle",
                    "must be a mapping",
                )
            ):
                continue
            self.require(
                oracle.get("comparison_input_used") is False,
                path,
                f"{context}.oracle.comparison_input_used",
                "display projection must never feed comparison semantics",
            )
            self.require(
                oracle.get("invented_latest", False) is False,
                path,
                f"{context}.oracle.invented_latest",
                "display projection must never invent a latest tag",
            )
            self.validate_image_display_sha_ids(
                path, f"{context}.input", input_data
            )
            digest = oracle.get("digest")
            if digest is not None:
                self.require(
                    isinstance(digest, str)
                    and SHA256_RE.fullmatch(digest) is not None,
                    path,
                    f"{context}.oracle.digest",
                    "must be a normalized sha256 digest",
                )

            expected_parsing = parsing_expectations.get(case_id)
            if expected_parsing is not None:
                derived_parsing = parse_supported_reference(
                    input_data.get("full_image_reference")
                )
                self.require(
                    derived_parsing == expected_parsing
                    and all(
                        oracle.get(key) == derived_parsing.get(key)
                        for key in expected_parsing
                    )
                    and oracle.get("invented_latest") is False,
                    path,
                    f"{context}.oracle",
                    "image-reference parsing outcome must preserve repository, "
                    "tag, digest, and compact-label semantics",
                )
            elif case_id == "reference_grammar_boundaries_are_exact":
                accepted = input_data.get("accepted")
                rejected = input_data.get("rejected")
                expected_accepted = {
                    "unqualified_tag": "ubuntu:latest",
                    "lowercase_path": "team/component_api",
                    "localhost_max_port": (
                        "localhost:65535/team/api:Release_2026.07-30"
                    ),
                }
                expected_rejected = {
                    "zero_port": "localhost:0/team/api:v1",
                    "leading_zero_port": "localhost:05000/team/api:v1",
                    "overflowing_port": "localhost:65536/team/api:v1",
                    "ipv6_authority": "[::1]:5000/team/api:v1",
                    "empty_path_component": "registry.example.com//api:v1",
                    "consecutive_path_separator": (
                        "registry.example.com/team--one/api:v1"
                    ),
                    "multiple_digest_separators": (
                        "registry.example.com/team/api:v1@sha256:"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaa@sha256:"
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        "bbbbbbbbbbbbbbbb"
                    ),
                }
                derived_accepted = (
                    {
                        item_id: parse_supported_reference(reference)
                        for item_id, reference in accepted.items()
                    }
                    if isinstance(accepted, dict)
                    else {}
                )
                derived_rejected = (
                    {
                        item_id: parse_supported_reference(reference)
                        for item_id, reference in rejected.items()
                    }
                    if isinstance(rejected, dict)
                    else {}
                )
                accepted_kinds = {
                    item_id: parsed.get("kind")
                    for item_id, parsed in derived_accepted.items()
                    if isinstance(parsed, dict)
                }
                self.require(
                    accepted == expected_accepted
                    and rejected == expected_rejected
                    and accepted_kinds
                    == oracle.get("accepted_kinds")
                    == {
                        "unqualified_tag": "tagged_reference",
                        "lowercase_path": "untagged_reference",
                        "localhost_max_port": "tagged_reference",
                    }
                    and all(
                        parsed is None
                        for parsed in derived_rejected.values()
                    )
                    and oracle.get("rejected_kind") == "opaque_reference"
                    and oracle.get("accepted_count")
                    == len(expected_accepted)
                    == 3
                    and oracle.get("rejected_count")
                    == len(expected_rejected)
                    == 7,
                    path,
                    context,
                    "reference grammar must accept the exact narrow boundary "
                    "set and classify every rejected form as opaque",
                )
            elif case_id == "opaque_tags_are_preserved_not_ordered":
                references = input_data.get("references")
                parsed_tags = (
                    [reference.rsplit(":", 1)[1] for reference in references]
                    if isinstance(references, list)
                    and all(
                        isinstance(reference, str) and ":" in reference
                        for reference in references
                    )
                    else None
                )
                oracle_tags = oracle.get("tags")
                self.require(
                    isinstance(oracle_tags, list)
                    and all(isinstance(tag, str) for tag in oracle_tags)
                    and oracle_tags == parsed_tags
                    and oracle.get("tags_preserved_verbatim") is True
                    and oracle.get("semantic_ordering_attempted") is False
                    and oracle.get("upgrade_or_downgrade_inferred") is False
                    and oracle.get("latest_freshness_inferred") is False,
                    path,
                    f"{context}.oracle",
                    "opaque tags must remain verbatim and unordered",
                )
            elif case_id == "repository_collision_expands_context":
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                self.require(
                    before.get("full_image_reference")
                    != after.get("full_image_reference")
                    and before.get("image_id") == after.get("image_id")
                    and oracle.get("initial_before_label")
                    == oracle.get("initial_after_label")
                    and oracle.get("disambiguation_reason")
                    == "repository_context"
                    and oracle.get("final_before_label")
                    == before.get("full_image_reference")
                    and oracle.get("final_after_label")
                    == after.get("full_image_reference")
                    and oracle.get("final_labels_equal") is False
                    and oracle.get("machine_references_unchanged") is True,
                    path,
                    context,
                    "repository-label collision must expand context without "
                    "changing machine references",
                )
            elif case_id == "mutable_tag_adds_image_id_evidence":
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                prefix_length = oracle.get("image_id_prefix_length")
                before_id = before.get("image_id")
                after_id = after.get("image_id")
                before_prefix = (
                    before_id.removeprefix("sha256:")[:prefix_length]
                    if isinstance(before_id, str)
                    and self.is_int(prefix_length)
                    else None
                )
                after_prefix = (
                    after_id.removeprefix("sha256:")[:prefix_length]
                    if isinstance(after_id, str)
                    and self.is_int(prefix_length)
                    else None
                )
                self.require(
                    before.get("full_image_reference")
                    == after.get("full_image_reference")
                    and before_id != after_id
                    and oracle.get("initial_before_label")
                    == oracle.get("initial_after_label")
                    and oracle.get("disambiguation_reason")
                    == "image_id_changed_under_equal_reference"
                    and prefix_length == 7
                    and oracle.get("image_id_separator") == "@"
                    and oracle.get("final_before_label")
                    == f"api:v1@{before_prefix}"
                    and oracle.get("final_after_label")
                    == f"api:v1@{after_prefix}"
                    and oracle.get("final_labels_equal") is False
                    and oracle.get("expected_change_kind") == "image_changed",
                    path,
                    context,
                    "mutable-tag collision must add distinct image-ID evidence",
                )
            elif (
                case_id
                == "long_colliding_references_preserve_suffix_and_identity"
            ):
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                max_width = input_data.get("max_cell_width")
                suffix = oracle.get("tag_suffix_preserved")
                before_hash = hashlib.sha256(
                    (
                        before.get("full_image_reference", "")
                        + "\0"
                        + before.get("image_id", "")
                    ).encode("ascii")
                ).hexdigest()[:4]
                after_hash = hashlib.sha256(
                    (
                        after.get("full_image_reference", "")
                        + "\0"
                        + after.get("image_id", "")
                    ).encode("ascii")
                ).hexdigest()[:4]
                self.require(
                    before.get("full_image_reference")
                    != after.get("full_image_reference")
                    and before.get("image_id") == after.get("image_id")
                    and oracle.get("identifier_aware_shortening") is True
                    and isinstance(suffix, str)
                    and suffix
                    in before.get("full_image_reference", "")
                    and suffix in after.get("full_image_reference", "")
                    and oracle.get("stable_disambiguator_present") is True
                    and oracle.get("shortened_collision_label")
                    == "component-api:release-2026-07-30"
                    and oracle.get("hash_prefix_length") == 4
                    and oracle.get("final_before_label")
                    == f"compone~:release-2026-07-30#{before_hash}"
                    and oracle.get("final_after_label")
                    == f"compone~:release-2026-07-30#{after_hash}"
                    and oracle.get("final_labels_equal") is False
                    and self.is_int(max_width)
                    and max_width > 0
                    and oracle.get("each_label_width_max") == max_width
                    and oracle.get("machine_references_truncated") is False,
                    path,
                    context,
                    "long colliding labels must preserve suffix and stable identity",
                )
            elif case_id == "colliding_short_id_prefix_extends_until_unique":
                before_id = input_data.get("before_image_id")
                after_id = input_data.get("after_image_id")
                initial_length = input_data.get("initial_prefix_length")
                selected_length = oracle.get("selected_prefix_length")
                before_hex = (
                    before_id.removeprefix("sha256:")
                    if isinstance(before_id, str)
                    else ""
                )
                after_hex = (
                    after_id.removeprefix("sha256:")
                    if isinstance(after_id, str)
                    else ""
                )
                self.require(
                    self.is_int(initial_length)
                    and self.is_int(selected_length)
                    and 0 < initial_length < selected_length <= 64
                    and before_hex[:initial_length]
                    == after_hex[:initial_length]
                    and before_hex[: selected_length - 1]
                    == after_hex[: selected_length - 1]
                    and before_hex[:selected_length]
                    != after_hex[:selected_length]
                    and oracle.get("before_prefix")
                    == before_hex[:selected_length]
                    and oracle.get("after_prefix")
                    == after_hex[:selected_length]
                    and oracle.get("base_label") == "api:v1"
                    and oracle.get("final_before_label")
                    == f"api:v1@{before_hex[:selected_length]}"
                    and oracle.get("final_after_label")
                    == f"api:v1@{after_hex[:selected_length]}"
                    and oracle.get("prefixes_equal") is False
                    and oracle.get("full_value_fallback_allowed") is True,
                    path,
                    context,
                    "colliding ID prefix must extend minimally until unique",
                )
            elif (
                case_id
                == "report_wide_repository_collisions_are_globally_unique"
            ):
                report_cells = input_data.get("report_cells")
                cells = (
                    report_cells
                    if isinstance(report_cells, list)
                    and all(isinstance(cell, dict) for cell in report_cells)
                    else []
                )
                cell_keys = [cell.get("cell_key") for cell in cells]
                references = [
                    cell.get("full_image_reference") for cell in cells
                ]
                references_by_cell = dict(zip(cell_keys, references))
                initial_labels = oracle.get("initial_labels_by_cell")
                final_labels = oracle.get("exact_final_labels_by_cell")
                permuted_keys = input_data.get("permuted_cell_order")
                derived_initial_labels = [
                    reference.rsplit("/", 1)[-1]
                    if isinstance(reference, str)
                    else None
                    for reference in references
                ]
                self.require(
                    len(cells) == 4
                    and len(cell_keys) == len(set(cell_keys))
                    and all(isinstance(key, str) and key for key in cell_keys)
                    and all(
                        isinstance(reference, str) and reference
                        for reference in references
                    )
                    and len(set(references)) == len(cells)
                    and isinstance(initial_labels, dict)
                    and set(initial_labels) == set(cell_keys)
                    and list(initial_labels.values())
                    == derived_initial_labels
                    and len(set(initial_labels.values())) == 1
                    and isinstance(final_labels, dict)
                    and final_labels == references_by_cell
                    and len(set(final_labels.values())) == len(cells)
                    and isinstance(permuted_keys, list)
                    and len(permuted_keys) == len(cells)
                    and len(set(permuted_keys)) == len(cells)
                    and set(permuted_keys) == set(cell_keys)
                    and permuted_keys != cell_keys
                    and oracle.get("collision_scope") == "whole_report"
                    and oracle.get("global_collision_group_size")
                    == len(cells)
                    and oracle.get("distinct_machine_reference_count")
                    == len(set(references))
                    and oracle.get("distinct_final_label_count")
                    == len(set(final_labels.values()))
                    and oracle.get(
                        "label_assignment_unchanged_under_input_permutation"
                    )
                    is True,
                    path,
                    context,
                    "repository collisions must be resolved over the whole "
                    "report into unique labels keyed independently of input "
                    "order while preserving every machine reference",
                )
            elif (
                case_id
                == "readable_collision_fallback_uses_hash_suffix"
            ):
                report_cells = input_data.get("report_cells")
                cells = (
                    report_cells
                    if isinstance(report_cells, list)
                    and all(isinstance(cell, dict) for cell in report_cells)
                    else []
                )
                cell_keys = [cell.get("cell_key") for cell in cells]
                references = [
                    cell.get("full_image_reference") for cell in cells
                ]
                image_ids = [cell.get("image_id") for cell in cells]
                readable_prefix = oracle.get("readable_prefix")
                computed_hashes = {
                    str(cell.get("cell_key")): hashlib.sha256(
                        (
                            str(cell.get("full_image_reference"))
                            + "\0"
                            + str(cell.get("image_id"))
                        ).encode("ascii")
                    ).hexdigest()[:4]
                    for cell in cells
                }
                expected_labels = {
                    key: f"{readable_prefix}#{computed_hashes[key]}"
                    for key in cell_keys
                    if isinstance(key, str)
                }
                exact_labels = oracle.get("exact_cell_labels")
                max_cell_width = input_data.get("max_cell_width")
                permuted_keys = input_data.get("permuted_cell_order")
                self.require(
                    len(cells) == 4
                    and len(cell_keys) == len(set(cell_keys))
                    and all(
                        isinstance(key, str) and bool(key)
                        for key in cell_keys
                    )
                    and all(
                        isinstance(reference, str) and bool(reference)
                        for reference in references
                    )
                    and len(set(references)) == len(cells)
                    and all(
                        isinstance(image_id, str)
                        and SHA256_RE.fullmatch(image_id) is not None
                        for image_id in image_ids
                    )
                    and isinstance(max_cell_width, int)
                    and max_cell_width == 15
                    and readable_prefix == "syn~.157.2"
                    and isinstance(exact_labels, dict)
                    and exact_labels == expected_labels
                    and len(set(exact_labels.values())) == len(cells)
                    and all(
                        len(label) <= max_cell_width
                        and label.startswith(f"{readable_prefix}#")
                        for label in exact_labels.values()
                    )
                    and all(
                        re.fullmatch(r"syn~\.157\.2#[0-9a-f]{4}", label)
                        is not None
                        for label in exact_labels.values()
                    )
                    and oracle.get("fallback_reason")
                    == "readable_compaction_collision"
                    and oracle.get("elision_marker") == "~"
                    and oracle.get("disambiguation_separator") == "#"
                    and oracle.get("hash_algorithm") == "sha256"
                    and oracle.get("hash_input")
                    == "full_image_reference NUL image_id"
                    and oracle.get("minimum_hash_prefix_length") == 4
                    and isinstance(permuted_keys, list)
                    and set(permuted_keys) == set(cell_keys)
                    and permuted_keys != cell_keys
                    and oracle.get("labels_stable_under_input_permutation")
                    is True
                    and oracle.get("endpoint_labels_visibly_distinct")
                    is True
                    and oracle.get("opaque_ordinal_markers_used") is False
                    and oracle.get("legend_entries") == []
                    and oracle.get("hidden_mappings") == 0
                    and oracle.get("machine_references_truncated") is False,
                    path,
                    context,
                    "readable colliding projections must retain visible "
                    "content and use stable hash suffixes without ordinal "
                    "markers, legends, or hidden mappings",
                )
            elif (
                case_id
                == "colliding_digest_prefix_extends_until_unique"
            ):
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                initial_length = input_data.get("initial_prefix_length")
                selected_length = oracle.get("selected_prefix_length")
                digest_re = re.compile(r"@sha256:([0-9a-f]{64})$")
                before_match = digest_re.search(
                    before.get("full_image_reference", "")
                )
                after_match = digest_re.search(
                    after.get("full_image_reference", "")
                )
                before_hex = (
                    before_match.group(1) if before_match is not None else ""
                )
                after_hex = (
                    after_match.group(1) if after_match is not None else ""
                )
                self.require(
                    initial_length == 12
                    and selected_length == 13
                    and before_hex[:initial_length]
                    == after_hex[:initial_length]
                    and before_hex[:selected_length]
                    != after_hex[:selected_length]
                    and oracle.get("before_prefix")
                    == before_hex[:selected_length]
                    and oracle.get("after_prefix")
                    == after_hex[:selected_length]
                    and oracle.get("final_before_label")
                    == f"api@sha256:{before_hex[:selected_length]}"
                    and oracle.get("final_after_label")
                    == f"api@sha256:{after_hex[:selected_length]}"
                    and oracle.get("prefixes_equal") is False,
                    path,
                    context,
                    "digest prefixes must begin at twelve characters and "
                    "extend minimally without adopting image-ID policy",
                )
            elif case_id == "hash_prefix_extends_past_four_until_unique":
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                max_width = input_data.get("max_cell_width")

                def identity_hash(endpoint: dict[str, Any]) -> str:
                    material = (
                        endpoint.get("full_image_reference", "")
                        + "\0"
                        + endpoint.get("image_id", "")
                    ).encode("ascii")
                    return hashlib.sha256(material).hexdigest()

                before_hash = identity_hash(before)
                after_hash = identity_hash(after)
                selected_length = oracle.get(
                    "selected_hash_prefix_length"
                )
                self.require(
                    max_width == 16
                    and oracle.get("minimum_hash_prefix_length") == 4
                    and selected_length == 5
                    and before_hash[:4] == after_hash[:4]
                    and before_hash[:5] != after_hash[:5]
                    and oracle.get("final_before_label")
                    == f"compon~:v1#{before_hash[:5]}"
                    and oracle.get("final_after_label")
                    == f"compon~:v1#{after_hash[:5]}"
                    and oracle.get("labels_equal") is False
                    and oracle.get("each_label_width") == max_width
                    and len(oracle.get("final_before_label", ""))
                    == max_width
                    and len(oracle.get("final_after_label", ""))
                    == max_width,
                    path,
                    context,
                    "hash suffixes must extend beyond four characters until "
                    "the final bounded labels are unique",
                )
            elif case_id == "presentation_capacity_failure_is_bounded":
                identities = input_data.get("identities")
                width = input_data.get("max_cell_width")
                compact_labels = (
                    [
                        identity.get("full_image_reference", "").rsplit(
                            "/", 1
                        )[-1]
                        for identity in identities
                    ]
                    if isinstance(identities, list)
                    and all(
                        isinstance(identity, dict)
                        for identity in identities
                    )
                    else []
                )
                self.require(
                    isinstance(identities, list)
                    and len(identities) == 2
                    and all(
                        isinstance(identity, dict)
                        and isinstance(
                            identity.get("full_image_reference"), str
                        )
                        and SHA256_RE.fullmatch(
                            identity.get("image_id", "")
                        )
                        is not None
                        for identity in identities
                    )
                    and len(
                        {
                            (
                                identity.get("full_image_reference"),
                                identity.get("image_id"),
                            )
                            for identity in identities
                        }
                    )
                    == 2
                    and len(set(compact_labels)) == 1
                    and compact_labels == ["api:v1", "api:v1"]
                    and width == 5
                    and oracle.get("minimum_readable_characters") == 1
                    and oracle.get("separator") == "#"
                    and oracle.get("minimum_hash_prefix_length") == 4
                    and oracle.get("minimum_representable_width")
                    == 1 + 1 + 4
                    and width < oracle.get("minimum_representable_width")
                    and oracle.get("failure_reason")
                    == "presentation_capacity_exceeded"
                    and oracle.get("full_table_rendered") is False
                    and oracle.get("compact_failure_envelope_present") is True
                    and oracle.get("machine_references_truncated") is False,
                    path,
                    context,
                    "a cell too narrow for one readable byte, separator, and "
                    "unique hash must fail through the bounded envelope",
                )
            elif (
                case_id
                == "missing_reference_never_uses_identifier_fallback"
            ):
                canonical_observation = input_data.get(
                    "canonical_observation"
                )
                canonical_gaps = (
                    canonical_observation.get("metadata_gaps")
                    if isinstance(canonical_observation, dict)
                    else None
                )
                self.require(
                    isinstance(canonical_observation, dict)
                    and canonical_observation.get("status") == "partial"
                    and canonical_gaps
                    == ["fixture-api.full_image_reference"]
                    and canonical_observation.get("reason_code")
                    == "required_field_missing"
                    and isinstance(
                        canonical_observation.get("warnings"), list
                    )
                    and bool(canonical_observation.get("warnings"))
                    and input_data.get("full_image_reference") is None
                    and oracle.get("kind") == "missing_reference"
                    and oracle.get("compact_label") == "<unknown>"
                    and oracle.get("observation_status")
                    == canonical_observation.get("status")
                    and oracle.get("metadata_gap")
                    == canonical_gaps[0].rsplit(".", 1)[-1]
                    and oracle.get("metadata_gaps") == canonical_gaps
                    and oracle.get("reason_code")
                    == canonical_observation.get("reason_code")
                    and oracle.get(
                        "observation_status_changed_by_projection"
                    )
                    is False
                    and oracle.get("metadata_gaps_changed_by_projection")
                    is False
                    and oracle.get("reason_code_changed_by_projection")
                    is False
                    and oracle.get("image_id_substituted_as_reference")
                    is False
                    and oracle.get("container_id_substituted_as_reference")
                    is False
                    and oracle.get("invented_latest") is False,
                    path,
                    context,
                    "missing reference must remain unknown without identifier "
                    "fallback or invented latest",
                )
                container_id = input_data.get("container_id")
                self.require(
                    isinstance(container_id, str)
                    and CONTAINER_ID_RE.fullmatch(container_id) is not None,
                    path,
                    f"{context}.input.container_id",
                    "must be a normalized container ID",
                )
            elif (
                case_id
                == "opaque_long_reference_escapes_then_shortens_atoms"
            ):
                reference = input_data.get("full_image_reference")
                width = input_data.get("max_cell_width")
                final_label, escaped_reference = shorten_opaque_atoms(
                    reference,
                    width,
                )
                semantic_label = f"o:{escaped_reference}"
                self.require(
                    reference
                    == "registry..example.com/team/"
                    "very~long|component:release#2026"
                    and parse_supported_reference(reference) is None
                    and width == 47
                    and escaped_reference
                    == oracle.get("escaped_reference")
                    == "registry..example.com/team/"
                    "very\\x7elong\\x7ccomponent:release\\x232026"
                    and semantic_label
                    == oracle.get("semantic_label")
                    == "o:registry..example.com/team/"
                    "very\\x7elong\\x7ccomponent:release\\x232026"
                    and final_label
                    == oracle.get("final_label")
                    == "o:registry..example~component:release\\x232026"
                    and len(final_label)
                    == oracle.get("final_label_width")
                    == 45
                    and len(final_label) <= width
                    and "\\x" in final_label
                    and not re.search(r"\\x(?:[^0-9a-f]|$)", final_label)
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("escape_before_shortening") is True
                    and oracle.get("escape_atoms_split") is False
                    and oracle.get("unused_atom_budget_reallocated") is False
                    and oracle.get("presentation_warning") is None,
                    path,
                    context,
                    "long opaque references must visibly escape first and "
                    "shorten only at complete escape-atom boundaries",
                )
            elif case_id == "opaque_width_collision_uses_identity_hash":
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                width = input_data.get("max_cell_width")
                before_reference = before.get("full_image_reference")
                after_reference = after.get("full_image_reference")
                before_candidate, _ = shorten_opaque_atoms(
                    before_reference,
                    width,
                )
                after_candidate, _ = shorten_opaque_atoms(
                    after_reference,
                    width,
                )
                hash_length = oracle.get("hash_prefix_length")
                reduced_width = width - 1 - hash_length
                before_readable, _ = shorten_opaque_atoms(
                    before_reference,
                    reduced_width,
                )
                after_readable, _ = shorten_opaque_atoms(
                    after_reference,
                    reduced_width,
                )
                before_hash = hashlib.sha256(
                    (
                        before_reference
                        + "\0"
                        + before.get("image_id")
                    ).encode("ascii")
                ).hexdigest()[:hash_length]
                after_hash = hashlib.sha256(
                    (
                        after_reference
                        + "\0"
                        + after.get("image_id")
                    ).encode("ascii")
                ).hexdigest()[:hash_length]
                final_before = f"{before_readable}#{before_hash}"
                final_after = f"{after_readable}#{after_hash}"
                self.require(
                    width == 32
                    and parse_supported_reference(before_reference) is None
                    and parse_supported_reference(after_reference) is None
                    and before_reference != after_reference
                    and before_candidate
                    == after_candidate
                    == oracle.get("pre_hash_before_label")
                    == oracle.get("pre_hash_after_label")
                    == "o:registry..e~zzzzzzzz-common:v1"
                    and hash_length == 4
                    and before_hash == "33fa"
                    and after_hash == "7f95"
                    and final_before
                    == oracle.get("final_before_label")
                    == "o:registry.~zzzzz-common:v1#33fa"
                    and final_after
                    == oracle.get("final_after_label")
                    == "o:registry.~zzzzz-common:v1#7f95"
                    and final_before != final_after
                    and len(final_before) == len(final_after) == width
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("final_labels_equal") is False
                    and oracle.get("readable_content_preserved") is True
                    and oracle.get("presentation_warning") is None,
                    path,
                    context,
                    "opaque width collisions must preserve bounded readable "
                    "content and use the common canonical identity hash",
                )
            elif (
                case_id
                == "opaque_equal_reference_adds_image_id_evidence"
            ):
                before = input_data.get("before", {})
                after = input_data.get("after", {})
                reference = before.get("full_image_reference")
                before_id = before.get("image_id")
                after_id = after.get("image_id")
                before_hex = before_id.removeprefix("sha256:")
                after_hex = after_id.removeprefix("sha256:")
                prefix_length = next(
                    length
                    for length in range(7, 65)
                    if before_hex[:length] != after_hex[:length]
                )
                before_label, _ = shorten_opaque_atoms(
                    reference,
                    input_data.get("max_cell_width"),
                    suffix=f"@{before_hex[:prefix_length]}",
                )
                after_label, _ = shorten_opaque_atoms(
                    reference,
                    input_data.get("max_cell_width"),
                    suffix=f"@{after_hex[:prefix_length]}",
                )
                self.require(
                    reference == after.get("full_image_reference")
                    and parse_supported_reference(reference) is None
                    and before_id != after_id
                    and prefix_length
                    == oracle.get("image_id_prefix_length")
                    == 7
                    and before_label
                    == oracle.get("final_before_label")
                    == "o:registry..example.com/team/api:v1@3333333"
                    and after_label
                    == oracle.get("final_after_label")
                    == "o:registry..example.com/team/api:v1@4444444"
                    and before_label != after_label
                    and len(before_label)
                    <= input_data.get("max_cell_width")
                    and len(after_label)
                    <= input_data.get("max_cell_width")
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("final_labels_equal") is False
                    and oracle.get("expected_change_kind")
                    == "image_changed"
                    and oracle.get("presentation_warning") is None,
                    path,
                    context,
                    "an equal opaque reference with differing image IDs must "
                    "append minimally unique image-ID evidence",
                )
            elif (
                case_id
                == "opaque_minimum_and_default_run_window_budgets"
            ):
                reference = input_data.get("full_image_reference")
                report_widths = input_data.get("report_widths")
                endpoint_widths: dict[int, int] = {}
                image_budgets: dict[int, int] = {}
                labels: dict[int, str] = {}
                if isinstance(report_widths, list):
                    for report_width in report_widths:
                        extra = report_width - 100
                        quotient, _ = divmod(extra, 3)
                        endpoint_width = 22 + quotient
                        image_budget = (
                            endpoint_width
                            - input_data.get(
                                "runtime_state_reservation", 0
                            )
                        )
                        endpoint_widths[report_width] = endpoint_width
                        image_budgets[report_width] = image_budget
                        labels[report_width] = shorten_opaque_atoms(
                            reference,
                            image_budget,
                        )[0]
                self.require(
                    parse_supported_reference(reference) is None
                    and report_widths == [100, 120]
                    and input_data.get("runtime_state_reservation") == 13
                    and endpoint_widths
                    == oracle.get("endpoint_content_widths")
                    == {100: 22, 120: 28}
                    and image_budgets
                    == oracle.get("image_label_budgets")
                    == {100: 9, 120: 15}
                    and labels
                    == oracle.get("exact_labels")
                    == {
                        100: "o:re~i:v1",
                        120: "o:regi~m/api:v1",
                    }
                    and all(
                        len(labels[width]) <= image_budgets[width]
                        for width in report_widths
                    )
                    and all(
                        labels[width].startswith("o:")
                        for width in report_widths
                    )
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("opaque_marker") == "o:"
                    and oracle.get(
                        "marker_visible_at_every_budget"
                    )
                    is True
                    and oracle.get("presentation_warning") is None,
                    path,
                    context,
                    "opaque projection must retain its exact short marker "
                    "within the real minimum/default run-window image budgets",
                )
            elif case_id == "unsupported_digest_algorithm_is_opaque":
                reference = input_data.get("full_image_reference")
                status = input_data.get("canonical_observation_status")
                sha512_reference = (
                    re.fullmatch(
                        r"[^@\s]+@sha512:([0-9a-f]{128})",
                        reference,
                    )
                    if isinstance(reference, str)
                    else None
                )
                self.require(
                    status == "complete"
                    and sha512_reference is not None
                    and reference.isascii()
                    and reference.isprintable()
                    and parse_supported_reference(reference) is None
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("preserved_reference") == reference
                    and oracle.get("presentation_warning") is None
                    and oracle.get("observation_status") == status
                    and oracle.get(
                        "observation_status_changed_by_projection"
                    )
                    is False
                    and oracle.get("digest_semantics_inferred") is False
                    and oracle.get("invented_latest") is False,
                    path,
                    context,
                    "unsupported sha512 syntax must stay byte-for-byte opaque "
                    "and must not degrade or otherwise alter the canonical "
                    "observation",
                )
            elif case_id in {
                "unsupported_authority_is_opaque",
                "unsupported_repository_component_is_opaque",
            }:
                reference = input_data.get("full_image_reference")
                expected_defect = {
                    "unsupported_authority_is_opaque": (
                        "authority_defect",
                        "empty_dns_label",
                    ),
                    "unsupported_repository_component_is_opaque": (
                        "repository_defect",
                        "uppercase_component",
                    ),
                }[case_id]
                defect_key, defect_value = expected_defect
                self.require(
                    isinstance(reference, str)
                    and bool(reference)
                    and reference.isascii()
                    and reference.isprintable()
                    and parse_supported_reference(reference) is None
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("preserved_reference") == reference
                    and oracle.get("presentation_warning") is None
                    and oracle.get(defect_key) == defect_value
                    and oracle.get(
                        "observation_status_changed_by_projection"
                    )
                    is False
                    and oracle.get("invented_latest") is False,
                    path,
                    context,
                    "unsupported authority and repository grammar must remain "
                    "opaque without altering canonical observation truth",
                )
            elif (
                case_id
                == "unsupported_reference_is_opaque_not_guessed"
            ):
                self.require(
                    isinstance(input_data.get("full_image_reference"), str)
                    and parse_supported_reference(
                        input_data.get("full_image_reference")
                    )
                    is None
                    and oracle.get("kind") == "opaque_reference"
                    and oracle.get("preserved_reference")
                    == input_data.get("full_image_reference")
                    and oracle.get("presentation_warning") is None
                    and oracle.get(
                        "observation_status_changed_by_projection"
                    )
                    is False
                    and oracle.get("invented_latest") is False,
                    path,
                    context,
                    "unsupported references must be preserved opaquely "
                    "without a per-reference warning",
                )

    def validate_image_display_sha_ids(
        self, path: Path, context: str, value: Any
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_context = f"{context}.{key}"
                if key == "image_id" or key.endswith("_image_id"):
                    self.require(
                        isinstance(child, str)
                        and SHA256_RE.fullmatch(child) is not None,
                        path,
                        child_context,
                        "must be sha256 followed by 64 lowercase hexadecimal "
                        "characters",
                    )
                self.validate_image_display_sha_ids(
                    path, child_context, child
                )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.validate_image_display_sha_ids(
                    path, f"{context}[{index}]", child
                )

    def validate_adapter_projection(
        self, path: Path, context: str, projection: Any
    ) -> None:
        if not self.require(
            isinstance(projection, dict), path, context, "must be a mapping"
        ):
            return
        for key in ("name", "container_id", "full_image_reference", "image_id"):
            self.require(
                key in projection,
                path,
                context,
                f"missing required safe projection key {key!r}",
            )
        name = projection.get("name")
        self.require(
            isinstance(name, str)
            and name.startswith("/")
            and CONTAINER_NAME_RE.fullmatch(name[1:]) is not None,
            path,
            f"{context}.name",
            "adapter input name must have one removable leading slash",
        )
        self.require(
            isinstance(projection.get("container_id"), str)
            and CONTAINER_ID_RE.fullmatch(projection["container_id"]) is not None,
            path,
            f"{context}.container_id",
            "must be exactly 64 lowercase hexadecimal characters",
        )
        self.require(
            isinstance(projection.get("image_id"), str)
            and SHA256_RE.fullmatch(projection["image_id"]) is not None,
            path,
            f"{context}.image_id",
            "must be sha256 followed by 64 lowercase hexadecimal characters",
        )
        if "runtime_state" in projection:
            self.enum(
                projection["runtime_state"],
                self.schema.get("observation", {}).get(
                    "canonical_runtime_state_values", []
                ),
                path,
                f"{context}.runtime_state",
            )

    def validate_partial_adapter_projection(
        self, path: Path, context: str, projection: Any
    ) -> None:
        required = [
            "name",
            "container_id",
            "full_image_reference",
            "image_id",
            "runtime_state",
            "missing_required_fields",
        ]
        if not self.require_keys(projection, required, path, context):
            return
        name = projection.get("name")
        self.require(
            isinstance(name, str)
            and name.startswith("/")
            and CONTAINER_NAME_RE.fullmatch(name[1:]) is not None,
            path,
            f"{context}.name",
            "must be a safe adapter name with one leading slash",
        )
        self.require(
            isinstance(projection.get("container_id"), str)
            and CONTAINER_ID_RE.fullmatch(projection["container_id"]) is not None,
            path,
            f"{context}.container_id",
            "must be exactly 64 lowercase hexadecimal characters",
        )
        self.require(
            isinstance(projection.get("full_image_reference"), str)
            and bool(projection["full_image_reference"].strip()),
            path,
            f"{context}.full_image_reference",
            "must be a non-empty image reference",
        )
        image_id = projection.get("image_id")
        self.require(
            image_id is None
            or (
                isinstance(image_id, str)
                and SHA256_RE.fullmatch(image_id) is not None
            ),
            path,
            f"{context}.image_id",
            "must be null or a normalized sha256 image ID",
        )
        self.enum(
            projection.get("runtime_state"),
            self.schema.get("observation", {}).get(
                "canonical_runtime_state_values", []
            ),
            path,
            f"{context}.runtime_state",
        )
        missing_fields = projection.get("missing_required_fields")
        self.require(
            isinstance(missing_fields, list)
            and bool(missing_fields)
            and all(
                field
                in self.schema.get("observation", {}).get(
                    "container_required", []
                )
                for field in missing_fields
            ),
            path,
            f"{context}.missing_required_fields",
            "must name one or more required normalized container fields",
        )
        if image_id is None:
            self.require(
                isinstance(missing_fields, list) and "image_id" in missing_fields,
                path,
                f"{context}.missing_required_fields",
                "null image_id must be declared missing",
            )

    def validate_normalized_container_projection(
        self, path: Path, context: str, container: Any
    ) -> None:
        required = self.schema.get("observation", {}).get(
            "container_required", []
        )
        if not self.require_keys(container, required, path, context):
            return
        name = container.get("name")
        self.require(
            isinstance(name, str)
            and CONTAINER_NAME_RE.fullmatch(name) is not None,
            path,
            f"{context}.name",
            "must be a normalized container name",
        )
        self.require(
            isinstance(container.get("container_id"), str)
            and CONTAINER_ID_RE.fullmatch(container["container_id"]) is not None,
            path,
            f"{context}.container_id",
            "must be exactly 64 lowercase hexadecimal characters",
        )
        self.require(
            isinstance(container.get("image_id"), str)
            and SHA256_RE.fullmatch(container["image_id"]) is not None,
            path,
            f"{context}.image_id",
            "must be sha256 followed by 64 lowercase hexadecimal characters",
        )
        self.enum(
            container.get("runtime_state"),
            self.schema.get("observation", {}).get(
                "canonical_runtime_state_values", []
            ),
            path,
            f"{context}.runtime_state",
        )

    def reject_sensitive_focused_keys(
        self, path: Path, value: Any, context: str = ""
    ) -> None:
        forbidden = {
            "credential",
            "credentials",
            "docker_inspect",
            "inspect_payload",
            "password",
            "private_key",
            "raw_inspect",
            "secret",
            "token",
            "vault",
        }
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                child_context = f"{context}.{key_text}" if context else key_text
                self.require(
                    key_text.lower() not in forbidden,
                    path,
                    child_context,
                    "secret-bearing or raw-inspect keys are forbidden in focused fixtures",
                )
                self.reject_sensitive_focused_keys(
                    path, child, child_context
                )
        elif isinstance(value, list):
            for index, child in enumerate(value):
                child_context = f"{context}[{index}]"
                self.reject_sensitive_focused_keys(
                    path, child, child_context
                )

    def validate_timestamp(
        self, value: Any, path: Path, context: str
    ) -> None:
        match = UTC_TIMESTAMP_RE.fullmatch(value) if isinstance(value, str) else None
        if not self.require(
            match is not None,
            path,
            context,
            "must use exact UTC YYYY-MM-DDTHH:MM:SS[.fraction]Z form",
        ):
            return
        fraction = match.group("fraction")
        self.require(
            fraction is None or not fraction.endswith("0"),
            path,
            context,
            "fractional seconds must not end in zero",
        )
        try:
            dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        except ValueError:
            self.error(path, context, f"invalid calendar timestamp {value!r}")

    def validate_string_list(
        self, value: Any, path: Path, context: str
    ) -> None:
        if not self.require(
            isinstance(value, list), path, context, "must be a list"
        ):
            return
        for index, item in enumerate(value):
            self.require(
                isinstance(item, str) and bool(item.strip()),
                path,
                f"{context}[{index}]",
                "must be a non-empty string",
            )

    @staticmethod
    def normalize_scope_input(value: Any) -> list[str] | None:
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        else:
            return None
        if not values or not all(isinstance(item, str) for item in values):
            return None
        stripped = [item.strip() for item in values]
        if any(not item for item in stripped):
            return None
        if any(
            item not in {"all", "*"}
            and (
                SCOPE_PATTERN_RE.fullmatch(item) is None
                or len(item.encode("ascii")) > 256
            )
            for item in stripped
        ):
            return None
        if "all" in stripped or "*" in stripped:
            return ["*"]
        normalized = sorted(set(stripped))
        if (
            len(normalized) > 64
            or sum(len(item.encode("ascii")) for item in normalized) > 4096
        ):
            return None
        return normalized

    @staticmethod
    def materialize_indexed_scope_recipe(recipe: Any) -> list[str] | None:
        if not isinstance(recipe, dict):
            return None
        if recipe.get("kind") != "indexed_ascii_patterns":
            return None
        count = recipe.get("count")
        prefix = recipe.get("prefix")
        index_width = recipe.get("index_width")
        pattern_bytes = recipe.get("pattern_bytes")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or not isinstance(prefix, str)
            or not prefix
            or not isinstance(index_width, int)
            or isinstance(index_width, bool)
            or index_width < 1
            or (
                pattern_bytes is not None
                and (
                    not isinstance(pattern_bytes, int)
                    or isinstance(pattern_bytes, bool)
                    or pattern_bytes < 1
                )
            )
        ):
            return None
        patterns: list[str] = []
        for index in range(count):
            pattern = f"{prefix}{index:0{index_width}d}"
            if pattern_bytes is not None:
                padding = pattern_bytes - len(pattern.encode("ascii"))
                if padding < 0:
                    return None
                pattern += "x" * padding
            patterns.append(pattern)
        return patterns

    @staticmethod
    def scope_identity(patterns: list[str]) -> str:
        canonical = json.dumps(
            {
                "comparison_schema_version": 1,
                "patterns": patterns,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def is_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)


if __name__ == "__main__":
    raise SystemExit(Validator().validate())
