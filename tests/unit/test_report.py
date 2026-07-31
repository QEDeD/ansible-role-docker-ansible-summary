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

from docker_ansible_summary.constants import (  # noqa: E402
    REPORT_HEADER_FIELDS,
    REPORT_MODEL_FIELDS,
    REPORT_TABLE_FIELDS,
)
from docker_ansible_summary.image import visible_escape  # noqa: E402
from docker_ansible_summary.model import ModelError, normalize_warnings  # noqa: E402
from docker_ansible_summary.report import (  # noqa: E402
    build_between_observation_summary,
    build_report_model,
    change_label,
    project_container_labels,
    table_content_widths,
)
from docker_ansible_summary.render import render_report  # noqa: E402


def _fixture():
    path = (
        ROOT
        / "tests"
        / "fixtures"
        / "conformance"
        / "focused"
        / "presentation.yml"
    )
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    return {case["id"]: case for case in data["cases"]}


class ReportModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = _fixture()

    def test_exact_fixture_report_models(self):
        for case_id in (
            "comparable_post_includes_changed_and_unchanged_rows",
            "incomplete_endpoint_shows_known_state_without_absence",
            "unavailable_endpoint_renders_no_invented_rows",
        ):
            case = self.cases[case_id]
            actual = build_report_model(
                case["input"]["machine_result"],
                case["input"]["host"],
                case["input"]["report_width"],
            )
            self.assertEqual(case["oracle"]["exact_report_model"], actual, case_id)
            self.assertEqual(REPORT_MODEL_FIELDS, frozenset(actual))
            self.assertEqual(REPORT_HEADER_FIELDS, frozenset(actual["header"]))
            self.assertEqual(
                REPORT_TABLE_FIELDS, frozenset(actual["primary_table"])
            )

    def test_between_observation_summary_matrix(self):
        case = self.cases["between_observation_summary_is_exact"]
        actual = build_between_observation_summary(
            case["input"]["between_observation_delta"]
        )
        self.assertEqual(
            case["oracle"]["exact_between_observation_summary"], actual
        )

        expected = case["oracle"]["exact_summary_matrix"]
        for name, variant in case["input"]["summary_variants"].items():
            changes = []
            if variant["material_primary_kinds"]:
                # The fixture's material variant is the reference-only image
                # row frozen immediately above the matrix.
                changes = case["input"]["between_observation_delta"]["changes"]
            delta = {
                "comparability": variant["comparability"],
                "changes": changes,
            }
            self.assertEqual(
                expected[name],
                build_between_observation_summary(delta),
                name,
            )

    def test_multi_label_summary_uses_closed_facet_order(self):
        case = self.cases["between_observation_summary_is_exact"]
        delta = {
            "comparability": "exact",
            "changes": [
                dict(item, container_name="fixture-%02d" % index)
                for index, item in enumerate(
                    case["input"]["multi_label_summary_changes"]
                )
            ],
        }
        self.assertEqual(
            case["oracle"]["exact_multi_label_summary"],
            build_between_observation_summary(delta)["message"],
        )

    def test_change_vocabulary_is_closed(self):
        case = self.cases["change_vocabulary_is_closed_and_bounded"]
        for change in case["input"]["changes"]:
            self.assertEqual(
                case["oracle"]["exact_labels"][change["id"]],
                change_label(change),
                change["id"],
            )
        with self.assertRaises(ModelError):
            change_label(
                {
                    "primary_kind": "image_changed",
                    "image_reference_changed": False,
                    "image_content_changed": False,
                }
            )

    def test_changed_rows_sort_before_unchanged_rows(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        result = copy.deepcopy(case["input"]["machine_result"])
        result["run_window_delta"]["changes"].reverse()
        model = build_report_model(
            result, case["input"]["host"], case["input"]["report_width"]
        )
        self.assertEqual(
            ["fixture-api", "fixture-cache"],
            [
                row["container_name"]
                for row in model["primary_table"]["rows"]
            ],
        )

    def test_all_removal_rows_remain_visible(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        result = copy.deepcopy(case["input"]["machine_result"])
        before = [
            item["before"]
            for item in result["run_window_delta"]["changes"]
        ]
        result["observation"]["containers"] = {}
        result["run_window_delta"]["changes"] = [
            {
                "container_name": item["name"],
                "primary_kind": "removed",
                "kinds": ["removed"],
                "before": item,
                "after": None,
                "image_reference_changed": None,
                "image_content_changed": None,
                "image_content_evidence": None,
            }
            for item in before
        ]
        model = build_report_model(result, "fixture-a.example.com", 120)
        self.assertEqual("run_window", model["primary_table"]["kind"])
        self.assertEqual(2, len(model["primary_table"]["rows"]))
        self.assertTrue(
            all(
                row["cells"]["after"] == "<absent>"
                for row in model["primary_table"]["rows"]
            )
        )

    def test_exact_geometry(self):
        self.assertEqual((26, 22, 22, 17), table_content_widths("run_window", 100))
        self.assertEqual((34, 28, 28, 17), table_content_widths("run_window", 120))
        self.assertEqual((34, 46, 10), table_content_widths("current", 100))
        self.assertEqual((44, 56, 10), table_content_widths("known_endpoint", 120))

    def test_container_shortening_and_hash_collision(self):
        case = self.cases["container_shortening_and_collision_are_exact"]
        single = case["input"]["single"]
        labels = project_container_labels([single["name"]], single["width"])
        self.assertEqual(case["oracle"]["single"]["exact_label"], labels[single["name"]])

        group = case["input"]["collision_group"]
        labels = project_container_labels(group["names"], group["width"])
        self.assertEqual(case["oracle"]["collision_group"]["exact_labels"], labels)
        self.assertEqual(
            labels,
            project_container_labels(group["permuted_order"], group["width"]),
        )

    def test_warning_normalization_and_bounds(self):
        case = self.cases["warning_normalization_is_exact_bounded_and_sorted"]
        sources = case["input"]["warning_sources"]
        actual = normalize_warnings(
            sources["observation"],
            sources["delta"],
            sources["persistence"],
        )
        self.assertEqual(case["oracle"]["normalized_warnings"], actual)
        with self.assertRaises(ModelError):
            normalize_warnings(["x" * 257])
        with self.assertRaises(ModelError):
            normalize_warnings(["warning-%02d" % index for index in range(65)])
        with self.assertRaises(ModelError):
            normalize_warnings(["bad\nwarning"])

    def test_report_host_is_visible_escaped_and_wrapped(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        for host in (
            "x" * 128,
            "x" * 129,
            "x" * 100000,
            "fixture\nhost",
            "fixture-é",
        ):
            model = build_report_model(
                case["input"]["machine_result"],
                host,
                100,
            )
            rendered = render_report(model, 100)
            with self.subTest(host=repr(host[:20])):
                self.assertEqual(host, model["header"]["host"])
                self.assertIn(
                    "host=" + visible_escape(host),
                    rendered.replace("\n  ", ""),
                )
                self.assertTrue(
                    all(len(line) <= 100 for line in rendered.splitlines())
                )


if __name__ == "__main__":
    unittest.main()
