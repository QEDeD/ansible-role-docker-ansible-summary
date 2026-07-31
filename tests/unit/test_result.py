# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import absolute_import, division, print_function

import copy
import json
import unittest

from module_utils.docker_ansible_summary.compare import compare_observations
from module_utils.docker_ansible_summary.result import (
    FAILURE_FIELDS,
    MACHINE_RESULT_FIELDS,
    ResultContractError,
    RETRY_UNCHANGED_PHASE,
    RETRY_WITHOUT_REPORT,
    RETRY_WITH_REPORT,
    build_machine_result,
    disabled_machine_result,
    failure_result,
    safe_hash_projection,
    sanitize_private_failure,
    sanitize_machine_result,
)
from module_utils.docker_ansible_summary.validation import normalize_scope


def _scope(pattern="*"):
    return normalize_scope(pattern)


def _observation(
    identifier="obs-1",
    status="complete",
    reason=None,
    warnings=None,
    observed_at="2026-07-30T12:00:00Z",
    scope=None,
):
    if status != "complete" and reason is None:
        reason = "docker_unavailable"
    if warnings is None:
        warnings = (
            []
            if reason is None
            else ["Docker daemon was unavailable"]
        )
    return {
        "observation_id": identifier,
        "observed_at": observed_at,
        "scope": scope or _scope(),
        "status": status,
        "reason_code": reason,
        "warnings": warnings,
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": {} if status != "unavailable" else None,
    }


def _expected_inputs(operation, observation, record_id=None, check_mode=False):
    return {
        "operation": operation,
        "instance_id": "fixture",
        "scope": observation["scope"],
        "correlation_id": None,
        "record_id": record_id,
        "check_mode": check_mode,
    }


def _writing_result(
    operation,
    observation,
    between,
    run_window,
    baseline,
    journal_status,
    replay=False,
):
    return build_machine_result(
        {
            "operation": operation,
            "instance_id": "fixture",
            "correlation_id": None,
        },
        observation,
        lifecycle={
            "record_id": "record-lifecycle-1",
            "correlation_id": None,
            "between_observation_delta": between,
            "run_window_delta": run_window,
            "baseline": baseline,
            "journal_status": journal_status,
            "persistence_outcome": (
                "not_attempted" if replay else "committed"
            ),
            "replay_outcome": "idempotent" if replay else None,
        },
    )


class ResultContractTests(unittest.TestCase):
    def test_disabled_result_has_exact_machine_fields(self):
        result = disabled_machine_result()
        self.assertEqual(set(MACHINE_RESULT_FIELDS), set(result))
        self.assertTrue(result["skipped"])
        self.assertFalse(result["simulated"])
        self.assertEqual("not_attempted", result["persistence_outcome"])

    def test_machine_result_derives_summaries_without_nesting(self):
        observation = _observation()
        baseline = {"advanced": False, "before": None, "after": None}
        result = build_machine_result(
            {
                "operation": "status",
                "instance_id": "example",
                "correlation_id": None,
            },
            observation,
            lifecycle={"baseline": baseline},
        )
        self.assertEqual(set(MACHINE_RESULT_FIELDS), set(result))
        self.assertEqual("complete", result["observation_status"])
        self.assertEqual(observation["scope"]["identity"], result["scope_identity"])
        self.assertFalse(result["baseline_advanced"])

    def test_sanitizer_drops_executor_and_arbitrary_module_data(self):
        value = disabled_machine_result()
        value.update(
            {
                "changed": False,
                "invocation": {"module_args": {"secret_canary": "never-return"}},
                "_ansible_private": "private",
                "stdout": "never-return",
            }
        )
        sanitized = sanitize_machine_result(value)
        self.assertEqual(set(MACHINE_RESULT_FIELDS), set(sanitized))
        self.assertNotIn("secret_canary", json.dumps(sanitized))
        self.assertNotIn("stdout", sanitized)

    def test_nested_machine_and_private_failure_channels_fail_closed(self):
        value = disabled_machine_result()
        value["skipped"] = False
        value["operation"] = "status"
        value["instance_id"] = "fixture"
        value["observation"] = {"containers": {"secret": "canary"}}
        with self.assertRaises(ResultContractError):
            sanitize_machine_result(value)

        with self.assertRaises(ResultContractError):
            sanitize_private_failure(
                {
                    "failure_reason": "attacker\ncontrolled",
                    "persistence_outcome": "failed",
                }
            )

    def test_success_channel_binds_lifecycle_and_controller_inputs(self):
        impossible_pre = build_machine_result(
            {
                "operation": "pre",
                "instance_id": "fixture",
                "correlation_id": None,
            },
            _observation(),
        )
        with self.assertRaises(ResultContractError):
            sanitize_machine_result(impossible_pre)

        status = build_machine_result(
            {
                "operation": "status",
                "instance_id": "fixture",
                "correlation_id": None,
            },
            _observation(),
        )
        with self.assertRaises(ResultContractError):
            sanitize_machine_result(
                status,
                expected_inputs={
                    "operation": "status",
                    "instance_id": "other-instance",
                    "scope": _scope(),
                    "correlation_id": None,
                    "record_id": None,
                    "check_mode": False,
                },
            )

    def test_post_only_correlation_is_bound_to_controller_input(self):
        post_only = build_machine_result(
            {
                "operation": "post",
                "instance_id": "fixture",
                "correlation_id": "unexpected-correlation",
            },
            _observation(),
            lifecycle={
                "record_id": "generated-post-only-record",
                "baseline": {
                    "advanced": True,
                    "before": None,
                    "after": "obs-1",
                },
                "journal_status": "incomplete_pre",
                "persistence_outcome": "committed",
                "replay_outcome": None,
            },
        )
        self.assertEqual(
            "unexpected-correlation",
            sanitize_machine_result(post_only)["correlation_id"],
        )
        with self.assertRaises(ResultContractError):
            sanitize_machine_result(
                post_only,
                expected_inputs={
                    "operation": "post",
                    "instance_id": "fixture",
                    "scope": _scope(),
                    "correlation_id": None,
                    "record_id": None,
                    "check_mode": False,
                },
            )

    def test_status_and_check_results_remain_store_free_and_valid(self):
        observation = _observation("obs-store-free")
        status = build_machine_result(
            {
                "operation": "status",
                "instance_id": "fixture",
                "correlation_id": None,
            },
            observation,
        )
        self.assertEqual(
            status,
            sanitize_machine_result(
                status,
                expected_inputs=_expected_inputs(
                    "status", observation, check_mode=False
                ),
            ),
        )

        check_pre = build_machine_result(
            {
                "operation": "pre",
                "instance_id": "fixture",
                "correlation_id": None,
            },
            observation,
            simulated=True,
        )
        self.assertEqual(
            check_pre,
            sanitize_machine_result(
                check_pre,
                expected_inputs=_expected_inputs(
                    "pre",
                    observation,
                    record_id="ignored-in-check-mode",
                    check_mode=True,
                ),
            ),
        )

    def test_complete_and_noncomplete_pre_lifecycle_and_replay(self):
        source = _observation(
            "obs-baseline",
            observed_at="2026-07-30T11:58:00Z",
        )
        cases = (
            (
                "complete",
                _observation(
                    "obs-pre-complete",
                    observed_at="2026-07-30T11:59:00Z",
                ),
                "complete",
            ),
            (
                "noncomplete",
                _observation(
                    "obs-pre-unavailable",
                    status="unavailable",
                    observed_at="2026-07-30T11:59:00Z",
                ),
                "incomplete_pre",
            ),
        )
        for name, observation, replay_status in cases:
            with self.subTest(name=name, outcome="commit"):
                result = _writing_result(
                    "pre",
                    observation,
                    compare_observations(source, observation),
                    None,
                    {
                        "advanced": False,
                        "before": source["observation_id"],
                        "after": source["observation_id"],
                    },
                    "open",
                )
                sanitize_machine_result(
                    result,
                    expected_inputs=_expected_inputs(
                        "pre",
                        observation,
                        record_id="record-lifecycle-1",
                    ),
                )

            with self.subTest(name=name, outcome="replay"):
                replay = _writing_result(
                    "pre",
                    observation,
                    compare_observations(source, observation),
                    None,
                    {
                        "advanced": False,
                        "before": source["observation_id"],
                        "after": source["observation_id"],
                    },
                    replay_status,
                    replay=True,
                )
                sanitize_machine_result(
                    replay,
                    expected_inputs=_expected_inputs(
                        "pre",
                        observation,
                        record_id="record-lifecycle-1",
                    ),
                )

    def test_paired_post_lifecycle_for_all_completeness_pairs(self):
        source = _observation(
            "obs-baseline",
            observed_at="2026-07-30T11:57:00Z",
        )
        complete_pre = _observation(
            "obs-pre-complete",
            observed_at="2026-07-30T11:58:00Z",
        )
        incomplete_pre = _observation(
            "obs-pre-unavailable",
            status="unavailable",
            observed_at="2026-07-30T11:58:00Z",
        )
        complete_post = _observation(
            "obs-post-complete",
            observed_at="2026-07-30T11:59:00Z",
        )
        incomplete_post = _observation(
            "obs-post-unavailable",
            status="unavailable",
            observed_at="2026-07-30T11:59:00Z",
        )
        cases = (
            (
                "complete-complete",
                complete_pre,
                complete_post,
                "complete",
            ),
            (
                "noncomplete-complete",
                incomplete_pre,
                complete_post,
                "incomplete_pre",
            ),
            (
                "complete-noncomplete",
                complete_pre,
                incomplete_post,
                "incomplete_post",
            ),
            (
                "noncomplete-noncomplete",
                incomplete_pre,
                incomplete_post,
                "incomplete_both",
            ),
        )
        for name, pre, post, status in cases:
            baseline = {
                "advanced": post["status"] == "complete",
                "before": source["observation_id"],
                "after": (
                    post["observation_id"]
                    if post["status"] == "complete"
                    else source["observation_id"]
                ),
            }
            with self.subTest(name=name):
                result = _writing_result(
                    "post",
                    post,
                    compare_observations(source, pre),
                    compare_observations(pre, post),
                    baseline,
                    status,
                    replay=name == "complete-complete",
                )
                sanitize_machine_result(
                    result,
                    expected_inputs=_expected_inputs(
                        "post",
                        post,
                        record_id="record-lifecycle-1",
                    ),
                )

    def test_scope_mismatch_and_post_only_lifecycles_are_valid(self):
        source = _observation(
            "obs-baseline",
            observed_at="2026-07-30T11:57:00Z",
        )
        pre = _observation(
            "obs-pre",
            observed_at="2026-07-30T11:58:00Z",
        )
        post = _observation(
            "obs-post",
            observed_at="2026-07-30T11:59:00Z",
            scope=_scope("other-*"),
        )
        scope_mismatch = _writing_result(
            "post",
            post,
            compare_observations(source, pre),
            compare_observations(pre, post),
            {
                "advanced": True,
                "before": source["observation_id"],
                "after": post["observation_id"],
            },
            "scope_mismatch",
        )
        sanitize_machine_result(
            scope_mismatch,
            expected_inputs=_expected_inputs(
                "post", post, record_id="record-lifecycle-1"
            ),
        )

        post_only_cases = (
            (
                _observation("obs-post-only-complete"),
                {
                    "advanced": True,
                    "before": source["observation_id"],
                    "after": "obs-post-only-complete",
                },
                "incomplete_pre",
                False,
            ),
            (
                _observation(
                    "obs-post-only-unavailable",
                    status="unavailable",
                ),
                {
                    "advanced": False,
                    "before": source["observation_id"],
                    "after": source["observation_id"],
                },
                "incomplete_both",
                True,
            ),
        )
        for observation, baseline, status, replay in post_only_cases:
            with self.subTest(status=observation["status"]):
                result = _writing_result(
                    "post",
                    observation,
                    None,
                    None,
                    baseline,
                    status,
                    replay=replay,
                )
                sanitize_machine_result(
                    result,
                    expected_inputs=_expected_inputs(
                        "post",
                        observation,
                        record_id=(
                            "record-lifecycle-1" if replay else None
                        ),
                    ),
                )

    def test_malformed_pre_lifecycle_results_fail_closed(self):
        source = _observation(
            "obs-baseline",
            observed_at="2026-07-30T11:58:00Z",
        )
        observation = _observation(
            "obs-pre",
            observed_at="2026-07-30T11:59:00Z",
        )
        base = _writing_result(
            "pre",
            observation,
            compare_observations(source, observation),
            None,
            {
                "advanced": False,
                "before": source["observation_id"],
                "after": source["observation_id"],
            },
            "open",
        )
        variants = []

        wrong_id = copy.deepcopy(base)
        wrong_id["between_observation_delta"][
            "to_observation_id"
        ] = "obs-wrong"
        variants.append(("target-id", wrong_id))

        wrong_time = copy.deepcopy(base)
        wrong_time["between_observation_delta"][
            "to_observed_at"
        ] = "2026-07-30T12:00:01Z"
        variants.append(("target-time", wrong_time))

        wrong_scope = copy.deepcopy(base)
        wrong_scope["between_observation_delta"]["to_scope"] = _scope(
            "other-*"
        )
        wrong_scope["between_observation_delta"][
            "comparability"
        ] = "incompatible_scope"
        variants.append(("target-scope", wrong_scope))

        wrong_status = copy.deepcopy(base)
        wrong_status["journal_status"] = "complete"
        variants.append(("commit-status", wrong_status))

        advanced = copy.deepcopy(base)
        advanced["baseline"]["advanced"] = True
        advanced["baseline_advanced"] = True
        variants.append(("baseline-advanced", advanced))

        moved_baseline = copy.deepcopy(base)
        moved_baseline["baseline"]["after"] = "obs-other-baseline"
        variants.append(("baseline-endpoints", moved_baseline))

        wrong_comparability = copy.deepcopy(base)
        wrong_comparability["between_observation_delta"][
            "comparability"
        ] = "incomplete"
        variants.append(("comparability", wrong_comparability))

        for name, result in variants:
            with self.subTest(name=name):
                with self.assertRaises(ResultContractError):
                    sanitize_machine_result(result)

    def test_malformed_paired_post_results_fail_closed(self):
        source = _observation(
            "obs-baseline",
            observed_at="2026-07-30T11:57:00Z",
        )
        pre = _observation(
            "obs-pre",
            observed_at="2026-07-30T11:58:00Z",
        )
        post = _observation(
            "obs-post",
            observed_at="2026-07-30T11:59:00Z",
        )
        base = _writing_result(
            "post",
            post,
            compare_observations(source, pre),
            compare_observations(pre, post),
            {
                "advanced": True,
                "before": source["observation_id"],
                "after": post["observation_id"],
            },
            "complete",
        )
        variants = []

        wrong_id = copy.deepcopy(base)
        wrong_id["run_window_delta"][
            "to_observation_id"
        ] = "obs-wrong-post"
        variants.append(("target-id", wrong_id))

        wrong_time = copy.deepcopy(base)
        wrong_time["run_window_delta"][
            "to_observed_at"
        ] = "2026-07-30T12:00:01Z"
        variants.append(("target-time", wrong_time))

        wrong_scope = copy.deepcopy(base)
        wrong_scope["run_window_delta"]["to_scope"] = _scope("other-*")
        wrong_scope["run_window_delta"][
            "comparability"
        ] = "incompatible_scope"
        wrong_scope["journal_status"] = "scope_mismatch"
        variants.append(("target-scope", wrong_scope))

        broken_link_id = copy.deepcopy(base)
        broken_link_id["run_window_delta"][
            "from_observation_id"
        ] = "obs-wrong-pre"
        variants.append(("paired-boundary-id", broken_link_id))

        broken_link = copy.deepcopy(base)
        broken_link["run_window_delta"][
            "from_observed_at"
        ] = "2026-07-30T11:58:01Z"
        variants.append(("paired-boundary-time", broken_link))

        broken_link_scope = copy.deepcopy(base)
        broken_link_scope["run_window_delta"]["from_scope"] = _scope(
            "other-*"
        )
        broken_link_scope["run_window_delta"][
            "comparability"
        ] = "incompatible_scope"
        broken_link_scope["journal_status"] = "scope_mismatch"
        variants.append(("paired-boundary-scope", broken_link_scope))

        wrong_status = copy.deepcopy(base)
        wrong_status["journal_status"] = "incomplete_post"
        variants.append(("journal-status", wrong_status))

        stale_baseline = copy.deepcopy(base)
        stale_baseline["baseline"]["advanced"] = False
        stale_baseline["baseline"]["after"] = source["observation_id"]
        stale_baseline["baseline_advanced"] = False
        variants.append(("complete-baseline", stale_baseline))

        wrong_source = copy.deepcopy(base)
        wrong_source["baseline"]["before"] = "obs-other-baseline"
        variants.append(("baseline-source", wrong_source))

        wrong_run_comparability = copy.deepcopy(base)
        wrong_run_comparability["run_window_delta"][
            "comparability"
        ] = "incomplete"
        variants.append(("run-comparability", wrong_run_comparability))

        wrong_pre_comparability = copy.deepcopy(base)
        wrong_pre_comparability["between_observation_delta"][
            "comparability"
        ] = "incomplete"
        variants.append(("pre-comparability", wrong_pre_comparability))

        for name, result in variants:
            with self.subTest(name=name):
                with self.assertRaises(ResultContractError):
                    sanitize_machine_result(result)

    def test_malformed_post_only_results_fail_closed(self):
        complete = _observation("obs-post-only-complete")
        valid_complete = _writing_result(
            "post",
            complete,
            None,
            None,
            {
                "advanced": True,
                "before": "obs-baseline",
                "after": complete["observation_id"],
            },
            "incomplete_pre",
        )
        complete_base = copy.deepcopy(valid_complete)
        complete_base["journal_status"] = "incomplete_both"

        unavailable = _observation(
            "obs-post-only-unavailable",
            status="unavailable",
        )
        unavailable_base = _writing_result(
            "post",
            unavailable,
            None,
            None,
            {
                "advanced": False,
                "before": "obs-baseline",
                "after": "obs-baseline",
            },
            "incomplete_both",
        )
        unavailable_base["baseline"]["advanced"] = True
        unavailable_base["baseline"]["after"] = unavailable[
            "observation_id"
        ]
        unavailable_base["baseline_advanced"] = True

        for name, result in (
            ("complete-journal-status", complete_base),
            ("noncomplete-baseline", unavailable_base),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ResultContractError):
                    sanitize_machine_result(result)

        with self.assertRaises(ResultContractError):
            sanitize_machine_result(
                valid_complete,
                expected_inputs=_expected_inputs(
                    "post",
                    complete,
                    record_id="record-lifecycle-1",
                ),
            )

    def test_failure_envelope_is_exact_and_bounded(self):
        result = failure_result(
            "fixture-a.example.com",
            "observation_noncomplete",
            instance_id="fixture-mdad",
            operation="post",
            record_id="record-failure-callback-01",
            observation_status="unavailable",
            observation_reason="docker_command_timeout",
            persistence_outcome="committed",
            committed_result_replayable=True,
        )
        self.assertEqual(
            {"changed", "failed", "docker_ansible_summary_failure"},
            set(result),
        )
        envelope = result["docker_ansible_summary_failure"]
        self.assertEqual(set(FAILURE_FIELDS), set(envelope))
        self.assertEqual(RETRY_WITH_REPORT, envelope["replay_guidance"])
        compact = json.dumps(
            result, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertLessEqual(len(compact), 1024)

    def test_failure_guidance_tracks_failure_stage(self):
        render = failure_result(
            "host",
            "render_failed",
            persistence_outcome="committed",
            committed_result_replayable=True,
        )
        self.assertEqual(
            RETRY_WITHOUT_REPORT,
            render["docker_ansible_summary_failure"]["replay_guidance"],
        )
        uncertain_commit = failure_result(
            "host",
            "state_write_failed",
            operation="pre",
            record_id="known-id",
            persistence_outcome="failed",
            retry_unchanged_phase=True,
        )
        self.assertEqual(
            RETRY_UNCHANGED_PHASE,
            uncertain_commit["docker_ansible_summary_failure"][
                "replay_guidance"
            ],
        )

    def test_host_projection_retains_safe_and_hashes_unsafe(self):
        self.assertEqual("fixture-a", safe_hash_projection("fixture-a"))
        self.assertEqual(
            "sha256:"
            "0d4e2ca9e9cbced7a7a5380eb29e1a3783b9b6d0db72de36a1051038e1c1fbc7",
            safe_hash_projection("x" * 300),
        )


if __name__ == "__main__":
    unittest.main()
