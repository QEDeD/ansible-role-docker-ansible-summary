# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Offline structural contract checks for the standalone role boundary."""

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


TESTS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS_ROOT))

from conftest import ROLE_ROOT, read_role_file  # noqa: E402


PUBLIC_INPUTS = {
    "docker_ansible_summary_enabled",
    "docker_ansible_summary_operation",
    "docker_ansible_summary_instance_id",
    "docker_ansible_summary_scope",
    "docker_ansible_summary_record_id",
    "docker_ansible_summary_state_root",
    "docker_ansible_summary_journal_max_records",
    "docker_ansible_summary_state_max_bytes",
    "docker_ansible_summary_correlation_id",
    "docker_ansible_summary_report_mode",
    "docker_ansible_summary_report_width",
    "docker_ansible_summary_discovery_timeout_seconds",
    "docker_ansible_summary_failure_policy",
}

PUBLIC_PREFIX = "docker_ansible_summary_"

DEFAULTS = {
    "docker_ansible_summary_enabled": "true",
    "docker_ansible_summary_state_root": "/var/lib/docker-ansible-summary",
    "docker_ansible_summary_journal_max_records": "30",
    "docker_ansible_summary_state_max_bytes": "16777216",
    "docker_ansible_summary_report_mode": "final",
    "docker_ansible_summary_report_width": "120",
    "docker_ansible_summary_discovery_timeout_seconds": "30",
    "docker_ansible_summary_failure_policy": "report",
}

MODULE_ARGUMENTS = {
    name[len(PUBLIC_PREFIX) :] for name in PUBLIC_INPUTS
}


class PublicRoleContractTests(unittest.TestCase):
    """Freeze the YAML role surface without requiring PyYAML or Ansible."""

    def test_defaults_contain_exactly_the_eight_defined_v1_values(self):
        defaults = read_role_file("defaults/main.yml")
        found = dict(
            re.findall(
                r"^(docker_ansible_summary_[a-z_]+):[ \t]*(.*?)$",
                defaults,
                flags=re.MULTILINE,
            )
        )
        self.assertEqual(DEFAULTS, found)

    def test_observe_contains_one_task_and_exactly_thirteen_arguments(self):
        observe = read_role_file("tasks/observe.yml")
        self.assertEqual(1, len(re.findall(r"^- name:", observe, re.MULTILINE)))
        self.assertIn("\n  docker_ansible_summary:\n", observe)
        self.assertIn(
            "\n  register: docker_ansible_summary_result\n",
            observe,
        )

        arguments = set(
            re.findall(r"^    ([a-z_]+):", observe, flags=re.MULTILINE)
        )
        self.assertEqual(MODULE_ARGUMENTS, arguments)

        self.assertIn(
            'enabled: "{{ docker_ansible_summary_enabled }}"',
            observe,
        )
        for public_name in PUBLIC_INPUTS - {
            "docker_ansible_summary_enabled"
        }:
            module_name = public_name[len(PUBLIC_PREFIX) :]
            pattern = (
                r"^\s{4}"
                + re.escape(module_name)
                + r":(?:\s*>-)?(?:\n\s+)?[\s\S]*?"
                + re.escape(public_name)
                + r"\s*\|\s*default\(omit\)"
            )
            self.assertRegex(observe, re.compile(pattern, re.MULTILINE))

    def test_main_is_only_a_static_convenience_import(self):
        main = read_role_file("tasks/main.yml")
        self.assertEqual(1, len(re.findall(r"^- name:", main, re.MULTILINE)))
        self.assertIn("ansible.builtin.import_tasks: observe.yml", main)
        self.assertNotIn("include_tasks", main)

    def test_role_metadata_explicitly_allows_repeated_use(self):
        metadata = read_role_file("meta/main.yml")
        self.assertIn("role_name: docker_ansible_summary", metadata)
        self.assertIn('min_ansible_version: "2.20.1"', metadata)
        self.assertIn(
            "the proposed 2.15.1 floor remains unproved",
            metadata,
        )
        self.assertRegex(metadata, r"(?m)^dependencies: \[\]$")
        self.assertRegex(metadata, r"(?m)^allow_duplicates: true$")

    def test_readme_documents_exactly_the_public_input_set(self):
        readme = read_role_file("README.md")
        section = readme.split("<!-- public-inputs:start -->", 1)[1].split(
            "<!-- public-inputs:end -->",
            1,
        )[0]
        documented = set(
            re.findall(r"`(docker_ansible_summary_[a-z_]+)`", section)
        )
        self.assertEqual(PUBLIC_INPUTS, documented)

    def test_role_has_no_legacy_or_project_specific_entry_point(self):
        role_surface = "\n".join(
            [
                read_role_file("defaults/main.yml"),
                read_role_file("tasks/main.yml"),
                read_role_file("tasks/observe.yml"),
            ]
        )
        for removed in (
            "legacy_initialize",
            "initialize_legacy",
            "docker_summary_",
            "matrix_",
            "mdad_",
            "mash_",
        ):
            self.assertNotIn(removed, role_surface)
        self.assertFalse((ROLE_ROOT / "vars" / "main.yml").exists())


class DaemonlessHarnessContractTests(unittest.TestCase):
    """Prove the checked-in harness itself needs no daemon or network."""

    def test_molecule_uses_local_default_driver_not_docker(self):
        molecule = read_role_file("molecule/default/molecule.yml")
        converge = read_role_file("molecule/default/converge.yml")
        self.assertRegex(molecule, r"(?m)^driver:\n  name: default$")
        self.assertIn("ansible_connection: local", molecule)
        self.assertNotRegex(molecule, r"(?m)^\s+name: docker$")
        self.assertNotIn("community.docker", molecule + converge)
        self.assertEqual(5, converge.count("ansible.builtin.import_role:"))
        self.assertEqual(5, converge.count("tasks_from: observe"))

    def test_fake_docker_protocol_is_deterministic(self):
        fake_docker = ROLE_ROOT / "molecule" / "default" / "files" / "docker"
        container_id = "a" * 64
        catalogue_format = '{"id":{{json .ID}},"name":{{json .Names}}}'
        inspect_format = (
            '{"container_id":{{json .Id}},"created_at":{{json .Created}},'
            '"finished_at":{{json .State.FinishedAt}},'
            '"full_image_reference":{{json .Config.Image}},'
            '"image_id":{{json .Image}},"name":{{json .Name}},'
            '"restart_count":{{json .RestartCount}},'
            '"runtime_state":{{json .State.Status}},'
            '"started_at":{{json .State.StartedAt}}}'
        )

        with tempfile.TemporaryDirectory(
            prefix="docker-ansible-summary-contract-"
        ) as temporary_directory:
            log_path = Path(temporary_directory) / "calls.jsonl"
            environment = os.environ.copy()
            environment["DAS_FAKE_DOCKER_LOG"] = str(log_path)

            catalogue = subprocess.run(
                [
                    sys.executable,
                    str(fake_docker),
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--format",
                    catalogue_format,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=environment,
            )
            catalogue_row = json.loads(catalogue.stdout)
            self.assertEqual(
                {"id": container_id, "name": "das-fixture"},
                catalogue_row,
            )

            inspection = subprocess.run(
                [
                    sys.executable,
                    str(fake_docker),
                    "container",
                    "inspect",
                    "--format",
                    inspect_format,
                    container_id,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                env=environment,
            )
            inspection_row = json.loads(inspection.stdout)
            self.assertEqual(container_id, inspection_row["container_id"])
            self.assertEqual("/das-fixture", inspection_row["name"])
            self.assertEqual("exited", inspection_row["runtime_state"])
            self.assertEqual(
                "registry.example.invalid:5000/team/example:1.0",
                inspection_row["full_image_reference"],
            )
            self.assertEqual(2, len(log_path.read_text().splitlines()))


class RepositoryMetadataContractTests(unittest.TestCase):
    """Check local release metadata without requiring the REUSE executable."""

    def test_scaffold_files_have_spdx_license_markers(self):
        scaffold_files = [
            ".ansible-lint",
            ".gitignore",
            ".yamllint",
            "CHANGELOG.md",
            "README.md",
            "REUSE.toml",
            "defaults/main.yml",
            "meta/main.yml",
            "molecule/README.md",
            "molecule/default/cleanup.yml",
            "molecule/default/converge.yml",
            "molecule/default/create.yml",
            "molecule/default/destroy.yml",
            "molecule/default/files/docker",
            "molecule/default/molecule.yml",
            "molecule/default/prepare.yml",
            "molecule/default/verify.yml",
            "pyproject.toml",
            "requirements-dev.txt",
            "tasks/main.yml",
            "tasks/observe.yml",
            "tests/conftest.py",
            "tests/role_contract/test_role_contract.py",
        ]
        for relative_path in scaffold_files:
            with self.subTest(relative_path=relative_path):
                contents = read_role_file(relative_path)
                self.assertIn("SPDX-FileCopyrightText:", contents)
                license_marker = "SPDX-" + "License-Identifier:"
                self.assertIn(license_marker, contents)

    def test_declared_license_texts_are_present(self):
        self.assertIn(
            "GNU AFFERO GENERAL PUBLIC LICENSE",
            read_role_file("LICENSE"),
        )
        self.assertIn(
            "GNU AFFERO GENERAL PUBLIC LICENSE",
            read_role_file("LICENSES/AGPL-3.0-or-later.txt"),
        )
        self.assertIn(
            "CC0 1.0 Universal",
            read_role_file("LICENSES/CC0-1.0.txt"),
        )
        self.assertRegex(read_role_file("REUSE.toml"), r"(?m)^version = 1$")

    def test_production_python_parses_with_python_36_grammar(self):
        production_files = [
            ROLE_ROOT / "action_plugins" / "docker_ansible_summary.py",
            ROLE_ROOT / "library" / "docker_ansible_summary.py",
            ROLE_ROOT / "molecule" / "default" / "files" / "docker",
        ]
        production_files.extend(
            sorted(
                (
                    ROLE_ROOT
                    / "module_utils"
                    / "docker_ansible_summary"
                ).glob("*.py")
            )
        )
        for path in production_files:
            with self.subTest(path=path.relative_to(ROLE_ROOT)):
                ast.parse(
                    path.read_text(),
                    filename=str(path),
                    mode="exec",
                    feature_version=6,
                )


if __name__ == "__main__":
    unittest.main()
