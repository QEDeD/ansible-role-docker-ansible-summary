# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import copy
import unittest

from module_utils.docker_ansible_summary.transition import (
    TransitionError,
    apply_retention,
    new_state_store,
    prepare_transition,
    propose_transition,
)
from module_utils.docker_ansible_summary.validation import normalize_scope


SCOPE = normalize_scope(["fixture-*"])
OTHER_SCOPE = normalize_scope(["other-*"])


def observation(identifier, observed_at, status="complete", scope=None):
    reason = None
    warnings = []
    containers = {}
    if status == "unavailable":
        reason = "docker_daemon_unreachable"
        warnings = ["Docker daemon was unreachable"]
        containers = None
    return {
        "observation_id": identifier,
        "observed_at": observed_at,
        "scope": copy.deepcopy(scope or SCOPE),
        "status": status,
        "reason_code": reason,
        "warnings": warnings,
        "discovery_backend": "synthetic",
        "metadata_gaps": [],
        "containers": containers,
    }


def fake_compare(before, after, instance_compatible=True):
    if before is None:
        comparability = (
            "no_baseline" if after["status"] == "complete" else "incomplete"
        )
    elif before["status"] != "complete" or after["status"] != "complete":
        comparability = "incomplete"
    elif before["scope"] != after["scope"] or not instance_compatible:
        comparability = "incompatible_scope"
    else:
        comparability = "exact"

    def endpoint(value, prefix):
        if value is None:
            return {
                prefix + "_observation_id": None,
                prefix + "_observed_at": None,
                prefix + "_scope": None,
            }
        return {
            prefix + "_observation_id": value["observation_id"],
            prefix + "_observed_at": value["observed_at"],
            prefix + "_scope": copy.deepcopy(value["scope"]),
        }

    result = {
        "comparability": comparability,
        "comparison_schema_version": 1,
        "changes": [],
        "warnings": [],
    }
    result.update(endpoint(before, "from"))
    result.update(endpoint(after, "to"))
    return result


class TransitionTests(unittest.TestCase):
    def test_baseline_advancement_matrix(self):
        cases = (
            ("complete", "complete", SCOPE, "complete", True),
            (
                "complete",
                "complete",
                OTHER_SCOPE,
                "scope_mismatch",
                True,
            ),
            (
                "unavailable",
                "complete",
                SCOPE,
                "incomplete_pre",
                True,
            ),
            (
                "complete",
                "unavailable",
                SCOPE,
                "incomplete_post",
                False,
            ),
            (
                "unavailable",
                "unavailable",
                SCOPE,
                "incomplete_both",
                False,
            ),
        )
        for pre_status, post_status, post_scope, status, advanced in cases:
            with self.subTest(status=status):
                initial = new_state_store("fixture-instance")
                pre = propose_transition(
                    initial,
                    "pre",
                    observation(
                        "obs-pre",
                        "2026-07-30T12:00:00Z",
                        status=pre_status,
                    ),
                    scope=SCOPE,
                    record_id="record-matrix",
                    comparator=fake_compare,
                    release_validation=False,
                )
                post = propose_transition(
                    pre["store"],
                    "post",
                    observation(
                        "obs-post",
                        "2026-07-30T12:01:00Z",
                        status=post_status,
                        scope=post_scope,
                    ),
                    scope=post_scope,
                    record_id="record-matrix",
                    comparator=fake_compare,
                    release_validation=False,
                )
                self.assertEqual(status, post["journal_status"])
                self.assertEqual(advanced, post["baseline_advanced"])
                if advanced:
                    self.assertEqual(
                        "obs-post",
                        post["store"]["latest_complete_post"][
                            "observation_id"
                        ],
                    )
                else:
                    self.assertIsNone(
                        post["store"]["latest_complete_post"]
                    )

    def test_pre_then_complete_post_advances_baseline(self):
        initial = new_state_store("fixture-instance")
        prepared = prepare_transition(
            initial,
            "pre",
            SCOPE,
            record_id="record-001",
            release_validation=False,
        )
        pre = propose_transition(
            initial,
            "pre",
            observation("obs-b", "2026-07-30T12:00:00Z"),
            comparator=fake_compare,
            prepared=prepared,
            expected_revision=prepared["expected_revision"],
            phase_signature_value=prepared["phase_signature"],
            release_validation=False,
        )
        self.assertEqual("open", pre["journal_status"])
        self.assertFalse(pre["baseline_advanced"])
        self.assertEqual(1, pre["store"]["revision"])
        self.assertEqual(1, pre["record"]["expected_post_revision"])

        post_prepared = prepare_transition(
            pre["store"],
            "post",
            SCOPE,
            record_id="record-001",
            release_validation=False,
        )
        post = propose_transition(
            pre["store"],
            "post",
            observation("obs-c", "2026-07-30T12:01:00Z"),
            comparator=fake_compare,
            prepared=post_prepared,
            expected_revision=post_prepared["expected_revision"],
            phase_signature_value=post_prepared["phase_signature"],
            release_validation=False,
        )
        self.assertEqual("complete", post["journal_status"])
        self.assertTrue(post["baseline_advanced"])
        self.assertEqual("obs-c", post["baseline"]["after"])
        self.assertEqual(
            "obs-c",
            post["store"]["latest_complete_post"]["observation_id"],
        )
        self.assertEqual(2, post["store"]["revision"])

    def test_unavailable_pre_complete_post_is_incomplete_pre(self):
        initial = new_state_store("fixture-instance")
        pre = propose_transition(
            initial,
            "pre",
            observation(
                "obs-unavailable",
                "2026-07-30T12:00:00Z",
                status="unavailable",
            ),
            scope=SCOPE,
            record_id="record-unavailable",
            comparator=fake_compare,
            release_validation=False,
        )
        post = propose_transition(
            pre["store"],
            "post",
            observation("obs-complete", "2026-07-30T12:01:00Z"),
            scope=SCOPE,
            record_id="record-unavailable",
            comparator=fake_compare,
            release_validation=False,
        )
        self.assertEqual("incomplete_pre", post["journal_status"])
        self.assertEqual(
            "incomplete", post["run_window_delta"]["comparability"]
        )
        self.assertTrue(post["baseline_advanced"])

    def test_post_only_uses_prepared_generated_identity(self):
        initial = new_state_store("fixture-instance")
        prepared = prepare_transition(
            initial,
            "post",
            SCOPE,
            record_id=None,
            record_id_factory=lambda: "generated-post-001",
            release_validation=False,
        )
        result = propose_transition(
            initial,
            "post",
            observation("obs-post", "2026-07-30T12:01:00Z"),
            comparator=fake_compare,
            prepared=prepared,
            expected_revision=prepared["expected_revision"],
            phase_signature_value=prepared["phase_signature"],
            release_validation=False,
        )
        self.assertEqual("generated-post-001", result["record_id"])
        self.assertEqual("incomplete_pre", result["journal_status"])
        self.assertIsNone(result["between_observation_delta"])
        self.assertIsNone(result["run_window_delta"])
        self.assertTrue(result["baseline_advanced"])

    def test_retained_phase_replay_is_idempotent(self):
        initial = new_state_store("fixture-instance")
        first = propose_transition(
            initial,
            "pre",
            observation("obs-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="caller-known-001",
            comparator=fake_compare,
            release_validation=False,
        )
        replay = prepare_transition(
            first["store"],
            "pre",
            SCOPE,
            record_id="caller-known-001",
            release_validation=False,
        )
        self.assertEqual("replay", replay["outcome"])
        self.assertEqual("idempotent", replay["replay_outcome"])
        self.assertEqual("not_attempted", replay["persistence_outcome"])
        self.assertEqual(first["store"], replay["store"])

    def test_signature_pruned_unknown_and_revision_conflicts(self):
        initial = new_state_store("fixture-instance")
        first = propose_transition(
            initial,
            "pre",
            observation("obs-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="caller-known-001",
            comparator=fake_compare,
            release_validation=False,
        )
        with self.assertRaises(TransitionError) as signature:
            prepare_transition(
                first["store"],
                "pre",
                OTHER_SCOPE,
                record_id="caller-known-001",
                release_validation=False,
            )
        self.assertEqual("signature_conflict", signature.exception.reason)

        pruned = new_state_store("fixture-instance")
        pruned["revision"] = 1
        pruned["recently_pruned_record_ids"] = ["record-pruned"]
        with self.assertRaises(TransitionError) as recently_pruned:
            prepare_transition(
                pruned,
                "post",
                SCOPE,
                record_id="record-pruned",
                release_validation=False,
            )
        self.assertEqual("record_pruned", recently_pruned.exception.reason)

        with self.assertRaises(TransitionError) as unknown:
            prepare_transition(
                initial,
                "post",
                SCOPE,
                record_id="record-never-known",
                release_validation=False,
            )
        self.assertEqual("unknown_record", unknown.exception.reason)

        stale = copy.deepcopy(first["store"])
        stale["revision"] = 2
        with self.assertRaises(TransitionError) as revision:
            prepare_transition(
                stale,
                "post",
                SCOPE,
                record_id="caller-known-001",
                release_validation=False,
            )
        self.assertEqual("revision_conflict", revision.exception.reason)

    def test_retention_prunes_oldest_open_but_keeps_baseline(self):
        state = new_state_store("fixture-instance")
        for index in range(3):
            result = propose_transition(
                state,
                "pre",
                observation(
                    "obs-{0}".format(index),
                    "2026-07-30T12:00:0{0}Z".format(index),
                ),
                scope=SCOPE,
                record_id="record-{0}".format(index),
                comparator=fake_compare,
                journal_max_records=3,
                release_validation=False,
            )
            state = result["store"]
        retained, pruned = apply_retention(
            state,
            protected_record_id="record-2",
            journal_max_records=2,
            state_max_bytes=16777216,
            release_validation=False,
        )
        self.assertEqual(["record-0"], pruned)
        self.assertEqual(
            ["record-1", "record-2"],
            [record["record_id"] for record in retained["journal"]],
        )
        self.assertEqual(
            ["record-0"], retained["recently_pruned_record_ids"]
        )

    def test_concurrent_same_phase_commit_becomes_replay(self):
        initial = new_state_store("fixture-instance")
        prepared = prepare_transition(
            initial,
            "pre",
            SCOPE,
            record_id="record-race",
            release_validation=False,
        )
        concurrent = propose_transition(
            initial,
            "pre",
            observation("obs-concurrent", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-race",
            comparator=fake_compare,
            release_validation=False,
        )
        replay = propose_transition(
            concurrent["store"],
            "pre",
            observation("obs-proposed", "2026-07-30T12:00:01Z"),
            comparator=fake_compare,
            prepared=prepared,
            expected_revision=prepared["expected_revision"],
            phase_signature_value=prepared["phase_signature"],
            release_validation=False,
        )
        self.assertEqual("replay", replay["outcome"])
        self.assertEqual("obs-concurrent", replay["observation"]["observation_id"])
        self.assertEqual(concurrent["store"], replay["store"])

    def test_concurrent_prune_precedes_stale_revision(self):
        initial = new_state_store("fixture-instance")
        open_record = propose_transition(
            initial,
            "pre",
            observation("obs-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-race",
            comparator=fake_compare,
            release_validation=False,
        )
        prepared = prepare_transition(
            open_record["store"],
            "post",
            SCOPE,
            record_id="record-race",
            release_validation=False,
        )
        pruned = new_state_store("fixture-instance")
        pruned["revision"] = 2
        pruned["recently_pruned_record_ids"] = ["record-race"]
        with self.assertRaises(TransitionError) as raised:
            propose_transition(
                pruned,
                "post",
                observation("obs-proposed", "2026-07-30T12:00:01Z"),
                comparator=fake_compare,
                prepared=prepared,
                expected_revision=prepared["expected_revision"],
                phase_signature_value=prepared["phase_signature"],
                release_validation=False,
            )
        self.assertEqual("record_pruned", raised.exception.reason)

    def test_optional_correlation_id_is_opaque_only(self):
        initial = new_state_store("fixture-instance")
        pre = propose_transition(
            initial,
            "pre",
            observation("obs-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-correlation",
            correlation_id="deployment-group-1",
            comparator=fake_compare,
            release_validation=False,
        )
        prepared_post = prepare_transition(
            pre["store"],
            "post",
            SCOPE,
            record_id="record-correlation",
            correlation_id=None,
            release_validation=False,
        )
        self.assertEqual(
            "deployment-group-1", prepared_post["correlation_id"]
        )
        post = propose_transition(
            pre["store"],
            "post",
            observation("obs-post", "2026-07-30T12:01:00Z"),
            comparator=fake_compare,
            prepared=prepared_post,
            expected_revision=prepared_post["expected_revision"],
            phase_signature_value=prepared_post["phase_signature"],
            release_validation=False,
        )
        self.assertEqual("deployment-group-1", post["correlation_id"])
        with self.assertRaises(TransitionError) as raised:
            prepare_transition(
                pre["store"],
                "post",
                SCOPE,
                record_id="record-correlation",
                correlation_id="different-group",
                release_validation=False,
            )
        self.assertEqual("signature_conflict", raised.exception.reason)


if __name__ == "__main__":
    unittest.main()
