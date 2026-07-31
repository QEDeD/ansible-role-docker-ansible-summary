#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify real state visibility around harness-injected production faults."""

from __future__ import print_function

import argparse
import json
import os
import sys


def _read(path):
    with open(path, "rb") as stream:
        source = stream.read()
    return source, json.loads(source.decode("utf-8"))


def verify(case, before_path, after_path, record_id):
    before_bytes, before = _read(before_path)
    after_bytes, after = _read(after_path)
    if before["revision"] != 1:
        raise AssertionError("prepared store did not have revision 1")
    before_ids = [record["record_id"] for record in before["journal"]]
    expected_before_ids = (
        ["callback-render-record"]
        if case == "render-failed"
        else ["callback-seed-record"]
    )
    if before_ids != expected_before_ids:
        raise AssertionError("prepared record differs")

    if case == "state-write-before":
        if before_bytes != after_bytes or before != after:
            raise AssertionError("pre-replacement fault changed prior store")
        expected_revision = 1
        retained = False
    else:
        if before_bytes == after_bytes:
            raise AssertionError("post-boundary state did not change")
        if after["revision"] != 2:
            raise AssertionError("post-boundary state did not reach revision 2")
        expected_revision = 2
        retained = True

    after_ids = [record["record_id"] for record in after["journal"]]
    if (record_id in after_ids) is not retained:
        raise AssertionError("faulting record retention differs")
    records = {
        record["record_id"]: record for record in after["journal"]
    }
    if case == "state-write-after":
        retained_record = records[record_id]
        if (
            retained_record["status"] != "open"
            or retained_record["pre"] is None
            or retained_record["post"] is not None
        ):
            raise AssertionError("post-replacement candidate record differs")
    elif case == "render-failed":
        retained_record = records[record_id]
        if (
            retained_record["status"] != "complete"
            or retained_record["post"] is None
            or after["latest_complete_post"]
            != retained_record["post"]
        ):
            raise AssertionError("renderer failure did not retain committed post")
    temporary_names = [
        name
        for name in os.listdir(os.path.dirname(after_path))
        if name.startswith(".state.json.tmp.")
    ]
    if temporary_names:
        raise AssertionError("owned temporary state file escaped cleanup")
    return {
        "case": case,
        "before_revision": before["revision"],
        "after_revision": expected_revision,
        "record_retained": retained,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        choices=("state-write-before", "state-write-after", "render-failed"),
        required=True,
    )
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--record-id", required=True)
    arguments = parser.parse_args()
    evidence = verify(
        arguments.case,
        arguments.before,
        arguments.after,
        arguments.record_id,
    )
    print(
        "callback failure state contract passed: "
        "case={case} before_revision={before_revision} "
        "after_revision={after_revision} "
        "record_retained={record_retained}".format(**evidence)
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IOError, KeyError, TypeError, ValueError) as error:
        print(
            "callback failure state contract failed: %s" % error,
            file=sys.stderr,
        )
        sys.exit(1)
