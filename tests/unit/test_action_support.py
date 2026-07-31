# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import absolute_import, division, print_function

import unittest

from module_utils.docker_ansible_summary.action_support import (
    compact_warning_block,
    detect_public_variable_error,
    effective_diagnostic_width,
    failure_block,
    input_error_block,
    presentation_kind,
)
from module_utils.docker_ansible_summary.result import disabled_machine_result
from module_utils.docker_ansible_summary.result import safe_hash_projection


def _machine(operation="pre", status="complete"):
    result = disabled_machine_result()
    result.update(
        {
            "operation": operation,
            "instance_id": "fixture",
            "observation": {
                "status": status,
                "reason_code": (
                    None if status == "complete" else "docker_unavailable"
                ),
            },
            "observation_status": status,
            "skipped": False,
        }
    )
    return result


class ActionSupportTests(unittest.TestCase):
    def test_unknown_and_removed_names_are_counted_without_values(self):
        error = detect_public_variable_error(
            {"enabled": True},
            {
                "docker_summary_old": "secret-a",
                "docker_ansible_summary_mock_mode": "secret-b",
                "docker_ansible_summary_unknown": "secret-c",
                "docker_ansible_summary_result": {},
            },
        )
        self.assertEqual(3, error.count)
        self.assertEqual("removed_variable", error.code)
        block = input_error_block(error)
        self.assertNotIn("secret-", block)
        self.assertIn("offending variables=3", block)

    def test_valid_output_variable_is_exempt(self):
        self.assertIsNone(
            detect_public_variable_error(
                {"enabled": True},
                {"docker_ansible_summary_result": {"record_id": "old"}},
            )
        )

    def test_invalid_width_uses_frozen_fallback(self):
        self.assertEqual(
            120, effective_diagnostic_width({"report_width": "invalid"})
        )
        self.assertEqual(
            100, effective_diagnostic_width({"report_width": 100})
        )

    def test_presentation_matrix(self):
        self.assertEqual("none", presentation_kind(_machine("pre"), "final"))
        self.assertEqual("table", presentation_kind(_machine("pre"), "each"))
        self.assertEqual("table", presentation_kind(_machine("post"), "final"))
        self.assertEqual("none", presentation_kind(_machine("post"), "none"))
        self.assertEqual(
            "warning",
            presentation_kind(_machine("pre", "unavailable"), "final"),
        )
        self.assertEqual(
            "warning",
            presentation_kind(_machine("status", "partial"), "none"),
        )

    def test_compact_warning_has_exact_two_semantic_lines(self):
        block = compact_warning_block(
            _machine("pre", "unavailable"), "fixture-host", "final", 120
        )
        self.assertEqual(2, len(block.splitlines()))
        self.assertIn("table suppressed in report_mode=final", block)

    def test_compact_warning_projects_unbounded_or_unsafe_hosts(self):
        for host in (
            "x" * 100000,
            "fixture\nhost",
            "fixture-é",
        ):
            block = compact_warning_block(
                _machine("pre", "unavailable"),
                host,
                "final",
                100,
            )
            with self.subTest(host=repr(host[:20])):
                self.assertIn(
                    "host=" + safe_hash_projection(host),
                    block,
                )
                self.assertLess(len(block.encode("ascii")), 512)
                self.assertLessEqual(len(block.splitlines()), 4)
                self.assertTrue(
                    all(len(line) <= 100 for line in block.splitlines())
                )

    def test_revision_conflict_diagnostic_is_actionable_and_truthful(self):
        block = failure_block(
            "fixture-host",
            "revision_conflict",
            instance_id="fixture",
            operation="post",
            record_id="record-1",
            persistence_outcome="conflict",
        )
        for message in (
            "Concurrent writer conflict",
            "Store unchanged",
            "Use a post-only observation or start a new pre/post window",
        ):
            self.assertIn(message, block)
        self.assertNotIn("Ansible caused", block)


if __name__ == "__main__":
    unittest.main()
