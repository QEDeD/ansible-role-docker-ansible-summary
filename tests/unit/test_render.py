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

from docker_ansible_summary.image import visible_escape  # noqa: E402
from docker_ansible_summary.model import ModelError  # noqa: E402
from docker_ansible_summary.report import build_report_model  # noqa: E402
from docker_ansible_summary.render import (  # noqa: E402
    render_report,
    render_warning_lines,
)


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


class RendererGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = _fixture()

    def test_exact_fixture_blocks(self):
        for case_id in (
            "comparable_post_includes_changed_and_unchanged_rows",
            "incomplete_endpoint_shows_known_state_without_absence",
            "unavailable_endpoint_renders_no_invented_rows",
        ):
            case = self.cases[case_id]
            model = build_report_model(
                case["input"]["machine_result"],
                case["input"]["host"],
                case["input"]["report_width"],
            )
            actual = render_report(model, case["input"]["report_width"])
            self.assertEqual(
                case["oracle"]["exact_ascii_rendered_block"], actual, case_id
            )
            self.assertFalse(actual.endswith("\n"))
            self.assertTrue(
                all(
                    len(line) <= case["input"]["report_width"]
                    for line in actual.splitlines()
                )
            )

    def test_minimum_width_layout_golden(self):
        case = self.cases["ascii_layout_is_deterministic_and_aligned"]
        source = case["input"]
        rows = []
        primary_kinds = ("image_changed", "started")
        for values, primary_kind in zip(source["row_values"], primary_kinds):
            rows.append(
                {
                    "container_name": values[0],
                    "machine_before": {},
                    "machine_after": {},
                    "cells": {
                        "container": values[0],
                        "before": values[1],
                        "after": values[2],
                        "change": values[3],
                    },
                }
            )
        warnings = list(source["long_metadata_fields"]["warnings"])
        warning_probe = source["overlong_warning_field"]
        warnings.append(
            warning_probe["prefix"]
            + warning_probe["character"] * warning_probe["repeat"]
        )
        model = {
            "presentation_schema_version": 1,
            "header": {
                "host": source["long_metadata_fields"]["header"][1][5:],
                "instance_id": source["long_metadata_fields"]["header"][2][9:],
                "operation": "post",
                "observed_at": source["observed_at"],
                "observation_status": source["observation_status"],
                "correlation_id": None,
                "simulated": False,
                "replay_outcome": None,
            },
            "primary_table": {
                "kind": "run_window",
                "columns": ["CONTAINER", "BEFORE", "AFTER", "CHANGE"],
                "rows": rows,
            },
            "between_observation_summary": None,
            "run_window_notice": None,
            "counts": {"image_changed": 1, "started": 1, "total": 2},
            "warnings": warnings,
            "baseline_outcome": {
                "advanced": True,
                "before": source["baseline_before"],
                "after": source["baseline_after"],
            },
            "journal_status": source["journal_status"],
            "persistence_outcome": source["persistence_outcome"],
        }
        actual = render_report(model, source["report_width"])
        self.assertEqual(
            case["oracle"]["exact_minimum_width_rendered_block"], actual
        )
        borders = [
            line
            for line in actual.splitlines()
            if line.startswith("+") and line.endswith("+")
        ]
        self.assertTrue(borders)
        self.assertTrue(all(len(line) == 100 for line in borders))

    def test_header_truthfulness_annotations(self):
        source_case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        base = build_report_model(
            source_case["input"]["machine_result"],
            source_case["input"]["host"],
            source_case["input"]["report_width"],
        )
        case = self.cases["header_truthfulness_annotations_are_exact"]
        for name, values in case["input"]["variants"].items():
            model = copy.deepcopy(base)
            model["header"].update(
                {
                    "host": case["input"]["host"],
                    "instance_id": case["input"]["instance_id"],
                    "operation": case["input"]["operation"],
                    "observed_at": case["input"]["observed_at"],
                    "observation_status": case["input"]["observation_status"],
                    "correlation_id": case["input"]["correlation_id"],
                    "simulated": values["simulated"],
                    "replay_outcome": values["replay_outcome"],
                }
            )
            observed = render_report(model, 120).splitlines()[1]
            self.assertEqual(case["oracle"]["exact_observed_lines"][name], observed)

    def test_empty_table_messages_are_semantic(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        model = build_report_model(
            case["input"]["machine_result"], case["input"]["host"], 120
        )
        model["primary_table"]["rows"] = []
        model["counts"] = {"total": 0}
        output = render_report(model, 120)
        self.assertIn(
            "No containers observed in either complete run-window endpoint",
            output,
        )

        model["primary_table"] = {
            "kind": "current",
            "columns": ["CONTAINER", "IMAGE", "STATE"],
            "rows": [],
        }
        model["counts"] = {
            "authoritative_changes": 0,
            "known_rows": 0,
            "rows_with_required_gaps": 0,
        }
        output = render_report(model, 120)
        self.assertIn("No containers observed in complete scope", output)

        model["primary_table"]["kind"] = "known_endpoint"
        output = render_report(model, 120)
        self.assertNotIn("No containers observed", output)

    def test_null_baseline_endpoints_render_language_neutral_token(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        model = build_report_model(
            case["input"]["machine_result"], case["input"]["host"], 120
        )
        model["baseline_outcome"] = {
            "advanced": True,
            "before": None,
            "after": "obs-first-complete-post",
        }
        output = render_report(model, 120)
        self.assertIn(
            "Baseline: advanced (<none> -> obs-first-complete-post)", output
        )
        self.assertNotIn("None", output)

    def test_visible_escape_matches_utf8_byte_projection(self):
        case = self.cases["visible_escape_is_exact_utf8_byte_projection"]
        self.assertEqual(
            case["oracle"]["exact_escaped_value"],
            visible_escape(case["input"]["value"]),
        )

    def test_warning_hard_wrap_has_exact_prefixes(self):
        case = self.cases["ascii_layout_is_deterministic_and_aligned"]
        source = case["input"]
        probe = source["overlong_warning_field"]
        warnings = list(source["long_metadata_fields"]["warnings"])
        warnings.append(probe["prefix"] + probe["character"] * probe["repeat"])
        self.assertEqual(
            case["oracle"]["exact_wrapped_metadata_lines"]["warnings"],
            render_warning_lines(warnings, source["report_width"]),
        )
        first_warning_lines = render_warning_lines(["x" * 200], 100)
        self.assertEqual(
            [100, 100, 14],
            [len(line) for line in first_warning_lines],
        )
        self.assertEqual(
            [90, 98, 12],
            [
                len(first_warning_lines[0]) - len("Warnings: "),
                len(first_warning_lines[1]) - len("  "),
                len(first_warning_lines[2]) - len("  "),
            ],
        )

    def test_unknown_model_keys_and_inconsistent_counts_fail(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        model = build_report_model(
            case["input"]["machine_result"], case["input"]["host"], 120
        )
        model["unexpected"] = True
        with self.assertRaises(ModelError):
            render_report(model, 120)
        del model["unexpected"]
        model["counts"]["total"] = 999
        with self.assertRaises(ModelError):
            render_report(model, 120)

    def test_internal_table_cells_cannot_create_physical_lines_or_controls(self):
        case = self.cases[
            "comparable_post_includes_changed_and_unchanged_rows"
        ]
        base = build_report_model(
            case["input"]["machine_result"], case["input"]["host"], 120
        )
        for value in ("evil\nrow", "evil\rrow", "evil\trow", "evil\x1brow", "é"):
            model = copy.deepcopy(base)
            model["primary_table"]["rows"][0]["cells"]["container"] = value
            with self.subTest(value=repr(value)):
                with self.assertRaises(ModelError):
                    render_report(model, 120)


if __name__ == "__main__":
    unittest.main()
