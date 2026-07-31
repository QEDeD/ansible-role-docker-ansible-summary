# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Keep the implementation proof registry executable and auditable."""

import ast
import os
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "tests" / "proof-registry.yml"


def _python_selectors(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    selectors = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                selectors.add("%s.%s" % (node.name, child.name))
    return selectors


class ProofRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with REGISTRY_PATH.open(encoding="utf-8") as stream:
            cls.registry = yaml.safe_load(stream)

    def test_registry_owns_every_frozen_requirement_and_secondary_lane(self):
        self.assertEqual(1, self.registry["schema_version"])
        self.assertEqual(
            "32c7c106fe1b7f6a126f094774cb5531f44fb0e4",
            self.registry["normative_commit"],
        )
        self.assertEqual(
            {"DAS-R%03d" % number for number in range(1, 21)},
            set(self.registry["requirements"]),
        )
        self.assertEqual(
            {
                "raw_docker_process",
                "persistence",
                "ansible_boundary",
                "renderer_callback",
            },
            set(self.registry["secondary_lanes"]),
        )

    def test_every_registered_path_and_python_selector_exists(self):
        entries = []
        for requirement_entries in self.registry["requirements"].values():
            entries.extend(requirement_entries)
        for lane_entries in self.registry["secondary_lanes"].values():
            entries.extend(lane_entries)

        selector_cache = {}
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertEqual(
                    {"path"} | ({"selector"} if "selector" in entry else set()),
                    set(entry),
                )
                relative_path = entry["path"]
                self.assertFalse(os.path.isabs(relative_path))
                path = ROOT / relative_path
                self.assertTrue(path.is_file(), relative_path)
                if path.suffix == ".sh":
                    self.assertTrue(os.access(str(path), os.X_OK), relative_path)
                selector = entry.get("selector")
                if selector is not None:
                    self.assertEqual(".py", path.suffix)
                    if path not in selector_cache:
                        selector_cache[path] = _python_selectors(path)
                    self.assertIn(selector, selector_cache[path])


if __name__ == "__main__":
    unittest.main()
