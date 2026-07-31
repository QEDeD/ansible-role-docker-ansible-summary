# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import copy
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "module_utils"))

from docker_ansible_summary.compare import compare_observations  # noqa: E402
from docker_ansible_summary.constants import (  # noqa: E402
    CONTAINER_DELTA_FIELDS,
    DELTA_RESULT_FIELDS,
)


def _fixture_root():
    return ROOT / "tests" / "fixtures" / "conformance"


def _load(path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _assert_subset(test, expected, actual, context="value"):
    if isinstance(expected, dict):
        test.assertIsInstance(actual, dict, context)
        for key, value in expected.items():
            test.assertIn(key, actual, "%s.%s" % (context, key))
            _assert_subset(test, value, actual[key], "%s.%s" % (context, key))
    elif isinstance(expected, list):
        test.assertEqual(len(expected), len(actual), context)
        for index, value in enumerate(expected):
            _assert_subset(
                test, value, actual[index], "%s[%d]" % (context, index)
            )
    else:
        test.assertEqual(expected, actual, context)


class NumberedComparisonTests(unittest.TestCase):
    def test_numbered_observation_scenarios(self):
        root = _fixture_root() / "scenarios"
        paths = sorted(root.glob("*.yml"))
        self.assertEqual(22, len(paths))
        for path in paths[:18]:
            fixture = _load(path)
            observations = fixture["observations"]
            for oracle_key, before_key, after_key in (
                ("between_observation_delta", "a", "b"),
                ("run_window_delta", "b", "c"),
            ):
                expected = fixture["oracle"][oracle_key]
                if expected is None:
                    continue
                actual = compare_observations(
                    observations[before_key], observations[after_key]
                )
                self.assertEqual(
                    DELTA_RESULT_FIELDS,
                    frozenset(actual),
                    "%s %s" % (path.name, oracle_key),
                )
                for delta in actual["changes"]:
                    self.assertEqual(
                        CONTAINER_DELTA_FIELDS, frozenset(delta), path.name
                    )
                _assert_subset(
                    self,
                    expected,
                    actual,
                    "%s.%s" % (path.name, oracle_key),
                )

    def test_complete_empty_is_exact_not_unavailable(self):
        fixture = _load(
            _fixture_root() / "scenarios" / "01-first-complete-empty.yml"
        )
        result = compare_observations(
            fixture["observations"]["b"], fixture["observations"]["c"]
        )
        self.assertEqual("exact", result["comparability"])
        self.assertEqual([], result["changes"])

    def test_scope_mismatch_suppresses_membership_changes(self):
        fixture = _load(
            _fixture_root() / "scenarios" / "14-incompatible-scope-change.yml"
        )
        result = compare_observations(
            fixture["observations"]["b"], fixture["observations"]["c"]
        )
        self.assertEqual("incompatible_scope", result["comparability"])
        self.assertEqual([], result["changes"])

    def test_instance_mismatch_is_incompatible(self):
        fixture = _load(
            _fixture_root() / "scenarios" / "03-repeated-unchanged.yml"
        )
        result = compare_observations(
            fixture["observations"]["b"],
            fixture["observations"]["c"],
            instance_compatible=False,
        )
        self.assertEqual("incompatible_scope", result["comparability"])
        self.assertEqual([], result["changes"])


class FocusedComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = _load(_fixture_root() / "focused" / "change-kinds.yml")
        cls.fixture = fixture
        cls.cases = {case["id"]: case for case in fixture["cases"]}
        cls.scope = fixture["shared"]["scope"]
        cls.base = fixture["shared"]["base_container"]

    def _observation(self, observation_id, container, gaps=None, status="complete"):
        return {
            "observation_id": observation_id,
            "observed_at": (
                "2026-07-30T12:00:00Z"
                if observation_id == "before"
                else "2026-07-30T12:00:01Z"
            ),
            "status": status,
            "scope": copy.deepcopy(self.scope),
            "metadata_gaps": list(gaps or []),
            "containers": {"fixture-api": container},
        }

    def _compare_containers(self, before, after, before_gaps=None, after_gaps=None):
        return compare_observations(
            self._observation("before", before, before_gaps),
            self._observation("after", after, after_gaps),
        )

    def test_restart_evidence_truth_table(self):
        case = self.cases["restart_evidence_comparability_matrix"]
        for name, variant in case["input_variants"].items():
            before = copy.deepcopy(self.base)
            after = copy.deepcopy(self.base)
            if not variant["same_container_id"]:
                after["container_id"] = "f" * 64
            before["runtime_state"] = variant["before_runtime_state"]
            after["runtime_state"] = variant["after_runtime_state"]
            before["started_at"] = variant["before_started_at"]
            after["started_at"] = variant["after_started_at"]
            before["restart_count"] = variant["before_restart_count"]
            after["restart_count"] = variant["after_restart_count"]
            result = self._compare_containers(before, after)
            expected = case["oracle"][name]
            self.assertEqual(expected["comparability"], result["comparability"], name)
            self.assertEqual(expected["primary_kind"], result["changes"][0]["primary_kind"], name)
            self.assertEqual(expected["kinds"], result["changes"][0]["kinds"], name)

    def test_positive_restart_and_state_change_cases(self):
        for case_id in (
            "same_container_restarted_by_start_time",
            "same_container_restarted_by_restart_count",
            "active_state_changed_paused_to_running",
            "inactive_state_changed_created_to_stopped",
        ):
            case = self.cases[case_id]
            gaps = case.get("unavailable_optional_evidence", {})
            result = self._compare_containers(
                copy.deepcopy(case["before"]),
                copy.deepcopy(case["after"]),
                gaps.get("before"),
                gaps.get("after"),
            )
            self.assertEqual(case["oracle"]["comparability"], result["comparability"])
            self.assertEqual(
                case["oracle"]["primary_kind"],
                result["changes"][0]["primary_kind"],
            )
            self.assertEqual(case["oracle"]["kinds"], result["changes"][0]["kinds"])

    def test_image_facets_are_separate_from_primary_vocabulary(self):
        for case_id in (
            "same_container_reference_only_image_change",
            "same_container_same_tag_new_image_id",
        ):
            case = self.cases[case_id]
            result = self._compare_containers(
                copy.deepcopy(case["before"]), copy.deepcopy(case["after"])
            )
            delta = result["changes"][0]
            for key in (
                "primary_kind",
                "kinds",
                "image_reference_changed",
                "image_content_changed",
            ):
                self.assertEqual(case["oracle"][key], delta[key], (case_id, key))
            self.assertEqual("image_id", delta["image_content_evidence"])

    def test_added_removed_and_unchanged_endpoint_shapes(self):
        case = self.cases["delta_endpoint_shapes"]
        empty = {
            "observation_id": "empty",
            "observed_at": "2026-07-30T12:00:00Z",
            "status": "complete",
            "scope": copy.deepcopy(self.scope),
            "containers": {},
        }
        populated = self._observation(
            "populated", copy.deepcopy(self.base)
        )
        added = compare_observations(empty, populated)["changes"][0]
        removed = compare_observations(populated, empty)["changes"][0]
        unchanged = compare_observations(populated, populated)["changes"][0]
        self.assertIsNone(added["before"])
        self.assertEqual(self.base, added["after"])
        self.assertEqual(self.base, removed["before"])
        self.assertIsNone(removed["after"])
        self.assertEqual(self.base, unchanged["before"])
        self.assertEqual(self.base, unchanged["after"])

    def test_multiple_kinds_follow_primary_precedence(self):
        before = copy.deepcopy(self.base)
        after = copy.deepcopy(self.base)
        after["container_id"] = "f" * 64
        after["full_image_reference"] = "registry.example.com/fixture/api:v2"
        after["image_id"] = "sha256:" + "2" * 64
        after["runtime_state"] = "stopped"
        delta = self._compare_containers(before, after)["changes"][0]
        self.assertEqual("recreated", delta["primary_kind"])
        self.assertEqual(
            ["recreated", "image_changed", "stopped"], delta["kinds"]
        )


if __name__ == "__main__":
    unittest.main()
