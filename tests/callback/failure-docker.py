#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Failure-harness Docker CLI with only deterministic, public test modes."""

from __future__ import print_function

import json
import os
import sys
import time


CATALOGUE_FORMAT = '{"id":{{json .ID}},"name":{{json .Names}}}'
INSPECT_FORMAT = (
    '{"container_id":{{json .Id}},"created_at":{{json .Created}},'
    '"finished_at":{{json .State.FinishedAt}},'
    '"full_image_reference":{{json .Config.Image}},'
    '"image_id":{{json .Image}},"name":{{json .Name}},'
    '"restart_count":{{json .RestartCount}},'
    '"runtime_state":{{json .State.Status}},'
    '"started_at":{{json .State.StartedAt}}}'
)
CAPACITY_CONTAINERS = (
    (
        "a" * 64,
        "das-capacity-a",
        "registry-050694.example.com/team/api:v1",
    ),
    (
        "c" * 64,
        "das-capacity-b",
        "registry-100222.example.com/team/api:v1",
    ),
)
IMAGE_ID = "sha256:" + ("a" * 64)


def _catalogue():
    for container_id, name, _reference in CAPACITY_CONTAINERS:
        print(
            json.dumps(
                {"id": container_id, "name": name},
                separators=(",", ":"),
            )
        )


def _inspect(identifiers):
    by_identifier = {
        container_id: (name, reference)
        for container_id, name, reference in CAPACITY_CONTAINERS
    }
    if (
        not identifiers
        or len(set(identifiers)) != len(identifiers)
        or any(identifier not in by_identifier for identifier in identifiers)
    ):
        return 2
    for identifier in identifiers:
        name, reference = by_identifier[identifier]
        print(
            json.dumps(
                {
                    "container_id": identifier,
                    "created_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:02:00Z",
                    "full_image_reference": reference,
                    "image_id": IMAGE_ID,
                    "name": "/" + name,
                    "restart_count": 0,
                    "runtime_state": "exited",
                    "started_at": "2026-01-01T00:01:00Z",
                },
                separators=(",", ":"),
            )
        )
    return 0


def _wait_at_barrier():
    barrier = os.environ.get("DAS_CALLBACK_FAILURE_BARRIER")
    participant = os.environ.get("DAS_CALLBACK_FAILURE_PARTICIPANT")
    if not barrier or not participant:
        return 2
    try:
        os.makedirs(barrier, mode=0o700)
    except OSError:
        if not os.path.isdir(barrier):
            return 2
    marker = os.path.join(barrier, participant)
    try:
        descriptor = os.open(
            marker,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except OSError:
        return 2
    else:
        os.close(descriptor)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            participants = [
                name
                for name in os.listdir(barrier)
                if not name.startswith(".")
            ]
        except OSError:
            return 2
        if len(participants) == 2:
            return 0
        time.sleep(0.01)
    return 2


def main():
    arguments = sys.argv[1:]
    mode = os.environ.get("DAS_CALLBACK_FAILURE_MODE", "unavailable")
    catalogue_arguments = [
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--format",
        CATALOGUE_FORMAT,
    ]
    if mode == "unavailable":
        return 1
    if arguments == catalogue_arguments:
        if mode == "empty":
            return 0
        if mode == "barrier-empty":
            return _wait_at_barrier()
        if mode == "capacity":
            _catalogue()
            return 0
    if (
        mode == "capacity"
        and arguments[:4]
        == ["container", "inspect", "--format", INSPECT_FORMAT]
    ):
        return _inspect(arguments[4:])
    return 2


if __name__ == "__main__":
    sys.exit(main())
