# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import copy
import hashlib
import unittest

from module_utils.docker_ansible_summary.transition import (
    new_state_store,
    propose_transition,
)
from module_utils.docker_ansible_summary.validation import (
    ValidationError,
    canonical_store_bytes,
    normalize_scope,
    phase_signature,
    validate_instance_id,
    validate_observation,
    validate_public_inputs,
    validate_record_id,
    validate_state_root,
    validate_state_store,
)


def complete_observation(identifier, observed_at):
    scope = normalize_scope(["fixture-*"])
    return {
        "observation_id": identifier,
        "observed_at": observed_at,
        "scope": scope,
        "status": "complete",
        "reason_code": None,
        "warnings": [],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": {},
    }


def post_only_store():
    post = complete_observation(
        "obs-post-only", "2026-07-30T12:00:01Z"
    )
    signature = phase_signature(
        "post", "fixture-mdad", post["scope"], None
    )
    return {
        "schema_version": 1,
        "comparison_schema_version": 1,
        "instance_id": "fixture-mdad",
        "revision": 1,
        "latest_complete_post": post,
        "journal": [
            {
                "record_id": "record-post-only",
                "correlation_id": None,
                "created_at": post["observed_at"],
                "updated_at": post["observed_at"],
                "expected_post_revision": None,
                "pre_signature": None,
                "post_signature": signature,
                "status": "incomplete_pre",
                "pre": None,
                "post": post,
                "between_observation_delta": None,
                "run_window_delta": None,
                "pre_baseline": None,
                "post_baseline": {
                    "advanced": True,
                    "before": None,
                    "after": post["observation_id"],
                },
            }
        ],
        "recently_pruned_record_ids": [],
    }


class ScopeValidationTests(unittest.TestCase):
    def test_known_answer_scope_normalization(self):
        cases = (
            (
                " fixture-* ",
                ["fixture-*"],
                "sha256:"
                "0f416d928469c6d885f23bebd10cda4eb3c837a5da0229a912c831feff79a207",
            ),
            (
                ["fixture-*", "Fixture.*", "fixture-*"],
                ["Fixture.*", "fixture-*"],
                "sha256:"
                "3929b345aa6fc8903b016555abfbd19a30006b472a57e06ba1a66ca025b162a3",
            ),
            (
                ["fixture-*", "all"],
                ["*"],
                "sha256:"
                "b98487f528496053b979eeb6ae103f5e566821b215dc63e01046df24995aa93a",
            ),
        )
        for raw, patterns, identity in cases:
            normalized = normalize_scope(raw)
            self.assertEqual(patterns, normalized["patterns"])
            self.assertEqual(identity, normalized["identity"])

    def test_invalid_scope_is_rejected(self):
        for raw in (
            [],
            " ",
            ["fixture-*", " "],
            ("fixture-*",),
            "x/y",
            ["*", "invalid/after-all"],
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError):
                    normalize_scope(raw)

    def test_state_root_lexical_contract(self):
        self.assertEqual("/srv/das-state", validate_state_root("/srv/das-state"))
        for value in (
            "srv/das-state",
            "/",
            "/srv/../das-state",
            "/srv/./das-state",
            "/srv//das-state",
            "/srv/das-state/",
            "/srv/das\x00-state",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_state_root(value)

    def test_fnmatch_literal_bracket_and_bang_characters_are_preserved(self):
        normalized = normalize_scope(["fixture-[", "fixture-!", "fixture-]"])
        self.assertEqual(
            ["fixture-!", "fixture-[", "fixture-]"],
            normalized["patterns"],
        )


class PublicInputTests(unittest.TestCase):
    def test_identifiers_are_anchored_at_the_absolute_string_end(self):
        for value in ("fixture\n", "fixture\r", "fixture\x00"):
            with self.subTest(kind="instance_id", value=repr(value)):
                with self.assertRaises(ValidationError):
                    validate_instance_id(value)
        for value in ("record\n", "record\r", "record\x00"):
            with self.subTest(kind="record_id", value=repr(value)):
                with self.assertRaises(ValidationError):
                    validate_record_id(value)

    def test_disabled_prefixed_call_skips_all_other_validation(self):
        values = {
            "docker_ansible_summary_enabled": False,
            "docker_ansible_summary_operation": "invalid",
            "docker_ansible_summary_unknown_future_input": object(),
            "docker_summary_old_variable": object(),
        }
        self.assertEqual(
            {"enabled": False},
            validate_public_inputs(values),
        )

    def test_enabled_call_rejects_unknown_public_variable(self):
        values = {
            "docker_ansible_summary_enabled": True,
            "docker_ansible_summary_operation": "status",
            "docker_ansible_summary_instance_id": "fixture-mdad",
            "docker_ansible_summary_scope": "*",
            "docker_ansible_summary_unknown": True,
        }
        with self.assertRaises(ValidationError) as raised:
            validate_public_inputs(values)
        self.assertEqual("unknown_public_variable", raised.exception.code)

    def test_enabled_call_distinguishes_removed_variable(self):
        values = {
            "docker_ansible_summary_enabled": True,
            "docker_ansible_summary_operation": "status",
            "docker_ansible_summary_instance_id": "fixture-mdad",
            "docker_ansible_summary_scope": "*",
            "docker_ansible_summary_history_max_entries": 10,
        }
        with self.assertRaises(ValidationError) as raised:
            validate_public_inputs(values)
        self.assertEqual("removed_variable", raised.exception.code)

    def test_defaults_and_status_contract(self):
        result = validate_public_inputs(
            {
                "operation": "status",
                "instance_id": "fixture-mdad",
                "scope": "*",
            }
        )
        self.assertEqual("/var/lib/docker-ansible-summary", result["state_root"])
        self.assertEqual(30, result["journal_max_records"])
        self.assertEqual(16777216, result["state_max_bytes"])
        self.assertEqual("final", result["report_mode"])
        self.assertEqual("report", result["failure_policy"])
        with self.assertRaises(ValidationError):
            validate_public_inputs(
                {
                    "operation": "status",
                    "instance_id": "fixture-mdad",
                    "scope": "*",
                    "record_id": "forbidden",
                }
            )

    def test_phase_signature_known_answer(self):
        signature = phase_signature(
            "pre", "fixture-mdad", normalize_scope(["fixture-*"]), None
        )
        self.assertEqual(
            "sha256:f09b6fbb422b755acd3aa1eb22814ed702aa91be62052df1bd9ca20bc8fb4f70",
            signature,
        )

    def test_correlation_id_allows_utf8_but_rejects_unicode_control(self):
        valid = validate_public_inputs(
            {
                "operation": "pre",
                "instance_id": "fixture-mdad",
                "scope": "*",
                "correlation_id": "déploiement",
            }
        )
        self.assertEqual("déploiement", valid["correlation_id"])
        with self.assertRaises(ValidationError):
            validate_public_inputs(
                {
                    "operation": "pre",
                    "instance_id": "fixture-mdad",
                    "scope": "*",
                    "correlation_id": "before\u0085after",
                }
            )


class ClosedStoreTests(unittest.TestCase):
    def test_closed_observation_rejects_line_breaks_in_protocol_tokens(self):
        observation = complete_observation(
            "obs-strict-tokens", "2026-07-30T12:00:01Z"
        )
        observation["containers"] = {
            "fixture": {
                "name": "fixture",
                "container_id": "0" * 64,
                "full_image_reference": "example:1",
                "image_id": "sha256:" + ("a" * 64),
                "runtime_state": "running",
                "created_at": "2026-07-30T12:00:00Z",
                "started_at": "2026-07-30T12:00:01Z",
                "finished_at": None,
                "restart_count": 0,
            }
        }
        validate_observation(observation, release=True)

        mutations = (
            ("container name", ("containers", "fixture", "name"), "fixture\n"),
            (
                "container ID",
                ("containers", "fixture", "container_id"),
                ("0" * 64) + "\n",
            ),
            (
                "image ID",
                ("containers", "fixture", "image_id"),
                "sha256:" + ("a" * 64) + "\n",
            ),
            (
                "observation timestamp",
                ("observed_at",),
                "2026-07-30T12:00:01Z\n",
            ),
            (
                "container timestamp",
                ("containers", "fixture", "created_at"),
                "2026-07-30T12:00:00Z\n",
            ),
        )
        for label, keys, value in mutations:
            candidate = copy.deepcopy(observation)
            target = candidate
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = value
            with self.subTest(field=label):
                with self.assertRaises(ValidationError):
                    validate_observation(candidate, release=True)

    def test_post_only_closed_store_and_canonical_encoding(self):
        store = post_only_store()
        self.assertIs(store, validate_state_store(store))
        encoded = canonical_store_bytes(store)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(1, encoded.count(b"\n"))
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            hashlib.sha256(canonical_store_bytes(copy.deepcopy(store))).hexdigest(),
        )

    def test_unknown_key_and_stale_signature_are_rejected(self):
        unknown = post_only_store()
        unknown["unexpected"] = True
        with self.assertRaises(ValidationError):
            validate_state_store(unknown)

        stale = post_only_store()
        stale["journal"][0]["correlation_id"] = "different"
        with self.assertRaises(ValidationError) as raised:
            validate_state_store(stale)
        self.assertEqual("stale_post_signature", raised.exception.code)

    def test_latest_baseline_requires_full_observation_equality(self):
        altered = post_only_store()
        altered["latest_complete_post"] = copy.deepcopy(
            altered["latest_complete_post"]
        )
        altered["latest_complete_post"]["observed_at"] = (
            "2026-07-30T12:00:02Z"
        )
        with self.assertRaises(ValidationError) as raised:
            validate_state_store(altered)
        self.assertEqual("latest_baseline_mismatch", raised.exception.code)

    def test_retained_delta_is_semantically_recomputed(self):
        initial = new_state_store("fixture-mdad")
        pre_observation = complete_observation(
            "obs-pre", "2026-07-30T12:00:00Z"
        )
        pre = propose_transition(
            initial,
            "pre",
            pre_observation,
            scope=pre_observation["scope"],
            record_id="record-semantic-delta",
            release_validation=True,
        )
        post_observation = complete_observation(
            "obs-post", "2026-07-30T12:00:01Z"
        )
        post = propose_transition(
            pre["store"],
            "post",
            post_observation,
            scope=post_observation["scope"],
            record_id="record-semantic-delta",
            release_validation=True,
        )
        altered = post["store"]
        altered["journal"][0]["run_window_delta"]["comparability"] = "degraded"
        with self.assertRaises(ValidationError) as raised:
            validate_state_store(altered)
        self.assertEqual("delta_semantic_mismatch", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
