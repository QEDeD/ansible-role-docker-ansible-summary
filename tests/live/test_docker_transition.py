# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Opt-in lifecycle matrix for an isolated disposable Docker daemon."""

from __future__ import absolute_import, division, print_function

import json
import os
import re
import socket
import subprocess
import unittest
import uuid
import warnings

from module_utils.docker_ansible_summary.compare import compare_observations
from module_utils.docker_ansible_summary.discovery import discover
from module_utils.docker_ansible_summary.render import render_report
from module_utils.docker_ansible_summary.report import build_report_model
from module_utils.docker_ansible_summary.result import (
    build_machine_result,
    sanitize_machine_result,
)
from module_utils.docker_ansible_summary.validation import (
    normalize_scope,
    validate_observation,
)
from tests.live.docker_safety import require_disposable_docker_host


MUTATING_ENABLED = os.environ.get("DAS_LIVE_DOCKER_MUTATING") == "1"
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_COMMAND = "while :; do sleep 3600; done"


def _change(delta, name):
    matches = [
        item for item in delta["changes"] if item["container_name"] == name
    ]
    if len(matches) != 1:
        raise AssertionError("expected exactly one delta row for %s" % name)
    return matches[0]


class _DisposableFixture(object):
    """Own exact container IDs and tags created by one test invocation."""

    def __init__(self, docker_path, prefix):
        self.docker_path = docker_path
        self.prefix = prefix
        self.scope = normalize_scope(prefix + "-*")
        self.container_ids = []
        self.removed_container_ids = set()
        self.tags = []

    def _run(self, arguments, check=True):
        completed = subprocess.run(
            [self.docker_path] + list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                "Docker CLI failed (%d): %s"
                % (
                    completed.returncode,
                    completed.stderr.decode("utf-8", "replace").strip(),
                )
            )
        return completed

    def observation(self):
        observation = discover(
            self.scope,
            timeout_seconds=30,
            docker_path=self.docker_path,
        )
        validate_observation(observation, release=True)
        if observation["status"] != "complete":
            raise AssertionError(
                "live observation was not complete: %s"
                % observation["reason_code"]
            )
        return observation

    def resolve_image_id(self, configured_id):
        if not configured_id or not IMAGE_ID_RE.match(configured_id):
            raise AssertionError(
                "live images must be exact sha256:<64 lowercase hex> IDs"
            )
        completed = self._run(
            (
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                configured_id,
            )
        )
        resolved = completed.stdout.decode("ascii", "strict").strip()
        if resolved != configured_id:
            raise AssertionError("the configured image ID did not resolve exactly")
        return resolved

    def image_tags(self, image_id):
        completed = self._run(
            (
                "image",
                "inspect",
                "--format",
                "{{json .RepoTags}}",
                image_id,
            )
        )
        tags = json.loads(completed.stdout.decode("utf-8", "strict"))
        if tags is None:
            return []
        if not isinstance(tags, list) or not all(
            isinstance(tag, str) and tag for tag in tags
        ):
            raise AssertionError("Docker returned an invalid RepoTags value")
        return tags

    def create_running(self, suffix, image_reference):
        name = self.prefix + "-" + suffix
        completed = self._run(
            (
                "container",
                "create",
                "--pull=never",
                "--name",
                name,
                "--label",
                "io.github.docker-ansible-summary.live-run=" + self.prefix,
                "--network",
                "none",
                "--stop-timeout=1",
                "--entrypoint",
                "sh",
                image_reference,
                "-c",
                CONTAINER_COMMAND,
            )
        )
        container_id = completed.stdout.decode("ascii", "strict").strip()
        if not re.match(r"^[0-9a-f]{64}$", container_id):
            raise AssertionError("docker create returned an invalid container ID")
        self.container_ids.append(container_id)
        self._run(("container", "start", container_id))
        return name, container_id

    def remove_container(self, container_id):
        self._run(("container", "rm", "--force", container_id))
        self.removed_container_ids.add(container_id)

    def add_tag(self, image_id, tag):
        if tag not in self.tags:
            existing = self._run(
                ("image", "ls", "--quiet", "--no-trunc", tag)
            )
            if existing.stdout.strip():
                raise AssertionError(
                    "the unique live-test image tag already exists"
                )
        self._run(("image", "tag", image_id, tag))
        if tag not in self.tags:
            self.tags.append(tag)

    def cleanup(self, preserve_failure):
        errors = []
        # Untag before container cleanup.  The same-tag lane separately
        # requires both underlying images to retain a pre-existing tag, so this
        # removes only the unique test reference and cannot delete image data.
        for tag in reversed(self.tags):
            completed = self._run(("image", "rm", tag), check=False)
            if completed.returncode != 0:
                errors.append("tag " + tag)
        for container_id in reversed(self.container_ids):
            if container_id in self.removed_container_ids:
                continue
            completed = self._run(
                ("container", "rm", "--force", container_id),
                check=False,
            )
            if completed.returncode != 0:
                errors.append("container " + container_id)
        if errors:
            message = "live-Docker cleanup failed for: " + ", ".join(errors)
            if preserve_failure:
                warnings.warn(message)
            else:
                raise AssertionError(message)

    def __enter__(self):
        initial = self.observation()
        if initial["containers"]:
            raise AssertionError(
                "unique live-test scope was unexpectedly nonempty"
            )
        return self

    def __exit__(self, exception_type, _exception, _traceback):
        self.cleanup(preserve_failure=exception_type is not None)
        return False


def _new_prefix():
    return "das-live-%d-%s" % (os.getpid(), uuid.uuid4().hex[:12])


@unittest.skipUnless(
    MUTATING_ENABLED,
    "set DAS_LIVE_DOCKER_MUTATING=1 for a disposable Docker daemon",
)
class LiveDockerTransitionTests(unittest.TestCase):
    def setUp(self):
        self.docker_path, self.socket_path, self.disposable_root = (
            require_disposable_docker_host("DAS_LIVE_DOCKER_MUTATING")
        )

    def test_authorized_lifecycle_matrix(self):
        image_id = os.environ.get("DAS_LIVE_IMAGE_ID")
        with _DisposableFixture(
            self.docker_path, _new_prefix()
        ) as fixture:
            fixture.resolve_image_id(image_id)
            empty_before = fixture.observation()
            self.assertEqual({}, empty_before["containers"])

            running_name, running_id = fixture.create_running(
                "running", image_id
            )
            stopped_name, stopped_id = fixture.create_running(
                "stopped", image_id
            )
            fixture._run(("container", "stop", stopped_id))
            catalogue = fixture.observation()
            self.assertEqual(
                {running_name, stopped_name},
                set(catalogue["containers"]),
            )
            self.assertEqual(
                "running",
                catalogue["containers"][running_name]["runtime_state"],
            )
            self.assertEqual(
                "stopped",
                catalogue["containers"][stopped_name]["runtime_state"],
            )

            fixture._run(("container", "start", stopped_id))
            after_start = fixture.observation()
            started = _change(
                compare_observations(catalogue, after_start), stopped_name
            )
            self.assertEqual(["started"], started["kinds"])

            fixture._run(("container", "stop", running_id))
            after_stop = fixture.observation()
            stopped = _change(
                compare_observations(after_start, after_stop), running_name
            )
            self.assertEqual(["stopped"], stopped["kinds"])

            fixture._run(("container", "start", running_id))
            before_restart = fixture.observation()
            fixture._run(("container", "restart", running_id))
            after_restart = fixture.observation()
            restarted = _change(
                compare_observations(before_restart, after_restart),
                running_name,
            )
            self.assertEqual(["restarted"], restarted["kinds"])
            self.assertEqual(
                running_id, restarted["after"]["container_id"]
            )

            before_recreate = after_restart
            fixture.remove_container(running_id)
            _same_name, recreated_id = fixture.create_running(
                "running", image_id
            )
            after_recreate = fixture.observation()
            recreated = _change(
                compare_observations(before_recreate, after_recreate),
                running_name,
            )
            self.assertEqual(["recreated"], recreated["kinds"])
            self.assertNotEqual(running_id, recreated_id)
            self.assertEqual(
                recreated["before"]["image_id"],
                recreated["after"]["image_id"],
            )

            before_add = after_recreate
            added_name, added_id = fixture.create_running("added", image_id)
            after_add = fixture.observation()
            added = _change(
                compare_observations(before_add, after_add), added_name
            )
            self.assertEqual(["added"], added["kinds"])

            fixture.remove_container(added_id)
            after_remove = fixture.observation()
            removed = _change(
                compare_observations(after_add, after_remove), added_name
            )
            self.assertEqual(["removed"], removed["kinds"])

            fixture.remove_container(recreated_id)
            fixture.remove_container(stopped_id)
            empty_after = fixture.observation()
            self.assertEqual({}, empty_after["containers"])
            all_removed_delta = compare_observations(
                after_remove, empty_after
            )
            self.assertEqual("exact", all_removed_delta["comparability"])
            self.assertEqual(
                {running_name, stopped_name},
                {
                    item["container_name"]
                    for item in all_removed_delta["changes"]
                },
            )
            self.assertTrue(
                all(
                    item["kinds"] == ["removed"]
                    for item in all_removed_delta["changes"]
                )
            )
            unchanged_between = compare_observations(
                after_remove, after_remove
            )

            machine = build_machine_result(
                {
                    "operation": "post",
                    "instance_id": "live-fixture",
                    "correlation_id": "live-lifecycle",
                },
                empty_after,
                lifecycle={
                    "record_id": "live-lifecycle-record",
                    "correlation_id": "live-lifecycle",
                    "between_observation_delta": unchanged_between,
                    "run_window_delta": all_removed_delta,
                    "baseline": {
                        "advanced": True,
                        "before": after_remove["observation_id"],
                        "after": empty_after["observation_id"],
                    },
                    "journal_status": "complete",
                    "persistence_outcome": "committed",
                    "replay_outcome": None,
                },
            )
            model = build_report_model(
                sanitize_machine_result(machine),
                "live-fixture",
                report_width=120,
            )
            self.assertEqual(
                {running_name, stopped_name},
                {
                    row["container_name"]
                    for row in model["primary_table"]["rows"]
                },
            )
            rendered = render_report(model, report_width=120)
            self.assertTrue(
                all(
                    row["cells"]["container"] in rendered
                    for row in model["primary_table"]["rows"]
                )
            )
            self.assertIn("removed", rendered)
            self.assertLessEqual(
                max(len(line) for line in rendered.splitlines()), 120
            )

    def test_same_tag_with_new_offline_image_id(self):
        first_id = os.environ.get("DAS_LIVE_IMAGE_ID")
        second_id = os.environ.get("DAS_LIVE_IMAGE_ID_SECOND")
        if not second_id:
            self.skipTest(
                "DAS_LIVE_IMAGE_ID_SECOND was not supplied; "
                "same-tag content replacement is optional"
            )

        prefix = _new_prefix()
        with _DisposableFixture(self.docker_path, prefix) as fixture:
            first_id = fixture.resolve_image_id(first_id)
            second_id = fixture.resolve_image_id(second_id)
            if first_id == second_id:
                self.skipTest("the two configured image IDs resolve equally")
            if not fixture.image_tags(first_id) or not fixture.image_tags(
                second_id
            ):
                self.skipTest(
                    "same-tag cleanup requires each preloaded image to retain "
                    "at least one pre-existing tag"
                )

            tag = "das-live-offline-%s:same-tag" % prefix[len("das-live-"):]
            fixture.add_tag(first_id, tag)
            name, first_container_id = fixture.create_running(
                "same-tag", tag
            )
            before = fixture.observation()

            fixture.add_tag(second_id, tag)
            fixture.remove_container(first_container_id)
            _same_name, second_container_id = fixture.create_running(
                "same-tag", tag
            )
            after = fixture.observation()
            changed = _change(compare_observations(before, after), name)

            self.assertEqual(
                ["recreated", "image_changed"], changed["kinds"]
            )
            self.assertFalse(changed["image_reference_changed"])
            self.assertTrue(changed["image_content_changed"])
            self.assertEqual(tag, changed["before"]["full_image_reference"])
            self.assertEqual(tag, changed["after"]["full_image_reference"])
            self.assertEqual(first_id, changed["before"]["image_id"])
            self.assertEqual(second_id, changed["after"]["image_id"])
            self.assertNotEqual(first_container_id, second_container_id)

    def test_daemon_permission_denial_is_not_complete_empty(self):
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest(
                "effective UID 0 bypasses the permission-denial fixture"
            )

        denied_path = os.path.join(
            self.disposable_root,
            ".das-denied-%d-%s.sock"
            % (os.getpid(), uuid.uuid4().hex[:8]),
        )
        if len(denied_path.encode("utf-8")) >= 104:
            self.skipTest("disposable root is too long for a denial socket")

        denied_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        original_host = os.environ["DOCKER_HOST"]
        try:
            denied_socket.bind(denied_path)
            denied_socket.listen(1)
            os.chmod(denied_path, 0)
            os.environ["DOCKER_HOST"] = "unix://" + denied_path
            observation = discover(
                normalize_scope(_new_prefix() + "-*"),
                timeout_seconds=10,
                docker_path=self.docker_path,
            )
            validate_observation(observation, release=True)
            self.assertEqual("unavailable", observation["status"])
            self.assertEqual(
                "docker_daemon_unauthorized", observation["reason_code"]
            )
            self.assertIsNone(observation["containers"])
        finally:
            os.environ["DOCKER_HOST"] = original_host
            denied_socket.close()
            if os.path.lexists(denied_path):
                os.chmod(denied_path, 0o600)
                os.unlink(denied_path)


if __name__ == "__main__":
    unittest.main()
