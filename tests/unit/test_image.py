# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "module_utils"))

from docker_ansible_summary.image import (  # noqa: E402
    parse_image_reference,
    project_image_diagnostics,
    project_image_labels,
    project_image_reference,
    visible_escape,
)
from docker_ansible_summary.model import (  # noqa: E402
    PresentationCapacityError,
)


def _fixture():
    path = (
        ROOT
        / "tests"
        / "fixtures"
        / "conformance"
        / "focused"
        / "image-display.yml"
    )
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    return {case["id"]: case for case in data["cases"]}


class ImageParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = _fixture()

    def test_structural_reference_examples(self):
        for case_id in (
            "registry_port_with_explicit_tag",
            "registry_port_without_explicit_tag",
            "digest_reference",
            "tag_plus_digest_reference",
            "bare_image_id_reference",
        ):
            case = self.cases[case_id]
            parsed = parse_image_reference(case["input"]["full_image_reference"])
            oracle = case["oracle"]
            for key in (
                "kind",
                "repository",
                "repository_basename",
                "tag",
                "digest",
                "compact_label",
            ):
                self.assertEqual(oracle[key], parsed[key], (case_id, key))

    def test_reference_grammar_boundaries(self):
        case = self.cases["reference_grammar_boundaries_are_exact"]
        for name, reference in case["input"]["accepted"].items():
            expected = case["oracle"]["accepted_kinds"][name]
            self.assertEqual(expected, parse_image_reference(reference)["kind"])
        for reference in case["input"]["rejected"].values():
            self.assertEqual(
                "opaque_reference", parse_image_reference(reference)["kind"]
            )

    def test_tags_are_preserved_as_opaque_labels(self):
        case = self.cases["opaque_tags_are_preserved_not_ordered"]
        tags = [
            parse_image_reference(reference)["tag"]
            for reference in case["input"]["references"]
        ]
        self.assertEqual(case["oracle"]["tags"], tags)

    def test_unsupported_safe_forms_are_opaque(self):
        for case_id in (
            "unsupported_digest_algorithm_is_opaque",
            "unsupported_authority_is_opaque",
            "unsupported_repository_component_is_opaque",
            "unsupported_reference_is_opaque_not_guessed",
        ):
            case = self.cases[case_id]
            parsed = parse_image_reference(case["input"]["full_image_reference"])
            self.assertEqual("opaque_reference", parsed["kind"], case_id)
            self.assertEqual(
                case["input"]["full_image_reference"],
                parsed["full_image_reference"],
            )

    def test_missing_reference_has_no_identifier_fallback(self):
        case = self.cases["missing_reference_never_uses_identifier_fallback"]
        parsed = parse_image_reference(case["input"]["full_image_reference"])
        self.assertEqual("missing_reference", parsed["kind"])
        self.assertEqual("<unknown>", parsed["compact_label"])


class ImageProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = _fixture()

    def test_repository_collision_expands_context(self):
        case = self.cases["repository_collision_expands_context"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            100,
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_equal_reference_adds_unique_image_id_evidence(self):
        case = self.cases["mutable_tag_adds_image_id_evidence"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            100,
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])
        diagnostics = project_image_diagnostics(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            100,
        )
        self.assertEqual(
            case["oracle"]["disambiguation_reason"],
            diagnostics["before"]["disambiguation_reason"],
        )

    def test_long_collisions_preserve_semantics_and_hash_identity(self):
        case = self.cases[
            "long_colliding_references_preserve_suffix_and_identity"
        ]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            case["input"]["max_cell_width"],
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])
        diagnostics = project_image_diagnostics(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            case["input"]["max_cell_width"],
        )
        self.assertEqual(
            "readable_compaction_collision",
            diagnostics["before"]["disambiguation_reason"],
        )

    def test_short_image_id_prefix_extends_until_unique(self):
        case = self.cases["colliding_short_id_prefix_extends_until_unique"]
        labels = project_image_labels(
            {
                "before": ("registry.example.com/team/api:v1", case["input"]["before_image_id"]),
                "after": ("registry.example.com/team/api:v1", case["input"]["after_image_id"]),
            },
            100,
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_report_wide_projection_is_order_invariant(self):
        case = self.cases[
            "report_wide_repository_collisions_are_globally_unique"
        ]
        identities = {
            item["cell_key"]: item for item in case["input"]["report_cells"]
        }
        labels = project_image_labels(identities, 100)
        self.assertEqual(
            case["oracle"]["exact_final_labels_by_cell"], labels
        )
        permuted = {
            key: identities[key] for key in case["input"]["permuted_cell_order"]
        }
        self.assertEqual(labels, project_image_labels(permuted, 100))

    def test_readable_collision_hash_fallback(self):
        case = self.cases["readable_collision_fallback_uses_hash_suffix"]
        identities = {
            item["cell_key"]: item for item in case["input"]["report_cells"]
        }
        labels = project_image_labels(
            identities, case["input"]["max_cell_width"]
        )
        self.assertEqual(case["oracle"]["exact_cell_labels"], labels)

    def test_digest_prefix_extends_until_unique(self):
        case = self.cases["colliding_digest_prefix_extends_until_unique"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            100,
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_hash_prefix_extends_past_four(self):
        case = self.cases["hash_prefix_extends_past_four_until_unique"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            case["input"]["max_cell_width"],
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_capacity_failure_is_explicit(self):
        case = self.cases["presentation_capacity_failure_is_bounded"]
        identities = {
            str(index): item
            for index, item in enumerate(case["input"]["identities"])
        }
        with self.assertRaises(PresentationCapacityError) as raised:
            project_image_labels(identities, case["input"]["max_cell_width"])
        self.assertEqual(
            case["oracle"]["failure_reason"], raised.exception.failure_reason
        )

    def test_opaque_reference_escape_and_atom_aware_elision(self):
        case = self.cases["opaque_long_reference_escapes_then_shortens_atoms"]
        reference = case["input"]["full_image_reference"]
        self.assertEqual(
            case["oracle"]["escaped_reference"], visible_escape(reference)
        )
        self.assertEqual(
            case["oracle"]["final_label"],
            project_image_reference(
                reference,
                case["input"]["image_id"],
                case["input"]["max_cell_width"],
            ),
        )

    def test_opaque_width_collision_uses_identity_hash(self):
        case = self.cases["opaque_width_collision_uses_identity_hash"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            case["input"]["max_cell_width"],
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_equal_opaque_reference_adds_image_id_evidence(self):
        case = self.cases["opaque_equal_reference_adds_image_id_evidence"]
        labels = project_image_labels(
            {"before": case["input"]["before"], "after": case["input"]["after"]},
            case["input"]["max_cell_width"],
        )
        self.assertEqual(case["oracle"]["final_before_label"], labels["before"])
        self.assertEqual(case["oracle"]["final_after_label"], labels["after"])

    def test_opaque_marker_survives_minimum_and_default_budgets(self):
        case = self.cases["opaque_minimum_and_default_run_window_budgets"]
        for report_width in case["input"]["report_widths"]:
            width = case["oracle"]["image_label_budgets"][report_width]
            label = project_image_reference(
                case["input"]["full_image_reference"],
                case["input"]["image_id"],
                width,
            )
            self.assertEqual(
                case["oracle"]["exact_labels"][report_width], label
            )


if __name__ == "__main__":
    unittest.main()
