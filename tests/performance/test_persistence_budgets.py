# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real-filesystem persistence timing for empty, typical, and near-cap state.

The benchmark uses secure temporary namespaces, the production store, actual
locking, file and directory fsync, atomic replacement, canonical decode, and
retention. It does not include Docker or Ansible transport.
"""

from __future__ import absolute_import, division, print_function

import copy
import gc
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "performance"))

from module_utils.docker_ansible_summary.persistence import (  # noqa: E402
    PosixStateStore,
    decode_store_bytes,
)
from module_utils.docker_ansible_summary.transition import (  # noqa: E402
    apply_retention,
)
from module_utils.docker_ansible_summary.validation import (  # noqa: E402
    canonical_store_bytes,
    normalize_scope,
    phase_signature,
    validate_state_store,
)
from test_budgets import (  # noqa: E402
    _normalize_observation,
    _percentile_metadata,
    _sample_summary,
    build_workload,
    environment_metadata,
)


STATE_MAX_BYTES = 16777216
COLD_REPETITIONS = 5
WARM_REPETITIONS = 20
PROFILES = (
    ("complete_empty", 0, 1),
    ("typical", 10, 5),
    ("near_default_byte_ceiling", 1000, 30),
)
TYPICAL_TOTAL_P95_LIMIT_MS = 2000.0
NEAR_CAP_TOTAL_P95_LIMIT_MS = 10000.0


def _build_store(container_count, record_count):
    scope = normalize_scope("*")
    raw = build_workload(container_count)["after"]
    base = _normalize_observation(
        raw,
        "persistence-template",
        "2026-07-30T12:00:00Z",
        scope,
    )
    store = {
        "schema_version": 1,
        "comparison_schema_version": 1,
        "instance_id": "benchmark",
        "revision": 1,
        "latest_complete_post": None,
        "journal": [],
        "recently_pruned_record_ids": [],
    }
    previous_id = None
    signature = phase_signature("post", "benchmark", scope, None)
    for index in range(record_count):
        observation = copy.deepcopy(base)
        observation["observation_id"] = "observation-{0:03d}".format(index)
        observation["observed_at"] = "2026-07-30T12:{0:02d}:00Z".format(
            index
        )
        record = {
            "record_id": "record-{0:03d}".format(index),
            "correlation_id": None,
            "created_at": observation["observed_at"],
            "updated_at": observation["observed_at"],
            "expected_post_revision": None,
            "pre_signature": None,
            "post_signature": signature,
            "status": "incomplete_pre",
            "pre": None,
            "post": observation,
            "between_observation_delta": None,
            "run_window_delta": None,
            "pre_baseline": None,
            "post_baseline": {
                "advanced": True,
                "before": previous_id,
                "after": observation["observation_id"],
            },
        }
        store["journal"].append(record)
        store["latest_complete_post"] = copy.deepcopy(observation)
        previous_id = observation["observation_id"]
    validate_state_store(
        store,
        expected_instance_id="benchmark",
        release=True,
    )
    return store


def _measure_once(template):
    ancestor = tempfile.mkdtemp(
        prefix="docker-ansible-summary-persistence-benchmark-"
    )
    os.chmod(ancestor, 0o700)
    try:
        encoded = canonical_store_bytes(
            template,
            expected_instance_id="benchmark",
            release=True,
        )

        total_started = time.perf_counter()
        started = time.perf_counter()
        decoded = decode_store_bytes(
            encoded,
            "benchmark",
            STATE_MAX_BYTES,
            release_validation=True,
        )
        parse_ms = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        candidate, pruned = apply_retention(
            decoded,
            protected_record_id=decoded["journal"][-1]["record_id"],
            journal_max_records=30,
            state_max_bytes=STATE_MAX_BYTES,
            release_validation=True,
        )
        transition_ms = (time.perf_counter() - started) * 1000.0
        if pruned:
            raise AssertionError("benchmark fixture unexpectedly pruned")

        started = time.perf_counter()
        candidate_bytes = canonical_store_bytes(
            candidate,
            expected_instance_id="benchmark",
            release=True,
        )
        serialization_ms = (time.perf_counter() - started) * 1000.0

        backend = PosixStateStore(
            os.path.join(ancestor, "state"),
            "benchmark",
            trusted_root_uid=os.stat("/").st_uid,
        )
        started = time.perf_counter()
        backend.commit(
            candidate,
            expected_revision=0,
            state_max_bytes=STATE_MAX_BYTES,
        )
        durable_replace_ms = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        loaded = backend.load(
            STATE_MAX_BYTES,
            create_namespace=False,
        )
        reload_ms = (time.perf_counter() - started) * 1000.0
        total_ms = (time.perf_counter() - total_started) * 1000.0
        if loaded != candidate:
            raise AssertionError("durable persistence round trip changed state")
        return {
            "parse_ms": parse_ms,
            "transition_ms": transition_ms,
            "serialization_ms": serialization_ms,
            "durable_replace_ms": durable_replace_ms,
            "reload_ms": reload_ms,
            "total_ms": total_ms,
            "serialized_bytes": len(candidate_bytes),
        }
    finally:
        shutil.rmtree(ancestor)


def _summarize_samples(samples):
    fields = (
        "parse_ms",
        "transition_ms",
        "serialization_ms",
        "durable_replace_ms",
        "reload_ms",
        "total_ms",
    )
    return dict(
        (
            field,
            _sample_summary([sample[field] for sample in samples]),
        )
        for field in fields
    )


def run_persistence_benchmark():
    results = []
    for name, container_count, record_count in PROFILES:
        template = _build_store(container_count, record_count)

        cold = []
        for _index in range(COLD_REPETITIONS):
            gc.collect()
            cold.append(_measure_once(template))

        _measure_once(template)
        warm = [
            _measure_once(template)
            for _index in range(WARM_REPETITIONS)
        ]
        serialized_bytes = warm[-1]["serialized_bytes"]
        results.append(
            {
                "profile": name,
                "container_count_per_record": container_count,
                "record_count": record_count,
                "serialized_bytes": serialized_bytes,
                "state_max_bytes": STATE_MAX_BYTES,
                "ceiling_fraction": (
                    serialized_bytes / float(STATE_MAX_BYTES)
                ),
                "cold": _summarize_samples(cold),
                "warm": _summarize_samples(warm),
            }
        )

    by_name = dict((item["profile"], item) for item in results)
    typical_p95 = by_name["typical"]["warm"]["total_ms"]["p95_ms"]
    near_p95 = by_name[
        "near_default_byte_ceiling"
    ]["warm"]["total_ms"]["p95_ms"]
    near_fraction = by_name[
        "near_default_byte_ceiling"
    ]["ceiling_fraction"]
    return {
        "benchmark_schema_version": 1,
        "benchmark_kind": "real_filesystem_persistence",
        "environment": environment_metadata(),
        "configuration": {
            "cold_definition": (
                "full-GC-conditioned run in a fresh secure namespace"
            ),
            "cold_repetitions_per_profile": COLD_REPETITIONS,
            "percentiles": _percentile_metadata(
                COLD_REPETITIONS, WARM_REPETITIONS
            ),
            "state_max_bytes": STATE_MAX_BYTES,
            "warm_definition": (
                "fresh secure namespaces after one unmeasured run, with "
                "process and operating-system caches retained"
            ),
            "warm_repetitions_per_profile": WARM_REPETITIONS,
        },
        "guards": {
            "near_cap_fixture_fraction": {
                "actual": near_fraction,
                "minimum_inclusive": 0.70,
                "maximum_exclusive": 1.0,
                "passed": 0.70 <= near_fraction < 1.0,
            },
            "typical_total_warm_p95": {
                "actual_ms": typical_p95,
                "limit_ms_exclusive": TYPICAL_TOTAL_P95_LIMIT_MS,
                "passed": typical_p95 < TYPICAL_TOTAL_P95_LIMIT_MS,
            },
            "near_cap_total_warm_p95": {
                "actual_ms": near_p95,
                "limit_ms_exclusive": NEAR_CAP_TOTAL_P95_LIMIT_MS,
                "passed": near_p95 < NEAR_CAP_TOTAL_P95_LIMIT_MS,
            },
        },
        "limitations": [
            "Docker discovery and Ansible transport/callbacks are excluded",
            (
                "fresh namespaces retain operating-system caches and do not "
                "model a cold host"
            ),
            (
                "the durable replacement timing is filesystem-specific and "
                "is a local regression guard, not a release ceiling"
            ),
            (
                "nearest-rank p95 over five cold samples is the fifth order "
                "statistic (the maximum) and is diagnostic only"
            ),
            (
                "warm acceptance uses twenty samples, whose nearest-rank "
                "p95 is the nineteenth order statistic"
            ),
            (
                "sample counts and thresholds are local regression guards, "
                "not statistically portable service-level objectives"
            ),
        ],
        "results": results,
    }


def assert_persistence_guards(record):
    failed = [
        name
        for name, guard in record["guards"].items()
        if not guard["passed"]
    ]
    if failed:
        raise AssertionError(
            "persistence benchmark guards failed: {0}".format(
                ", ".join(sorted(failed))
            )
        )


class PersistencePerformanceTests(unittest.TestCase):
    def test_empty_typical_and_near_cap_persistence_budgets(self):
        record = run_persistence_benchmark()
        self.assertEqual(
            [item[0] for item in PROFILES],
            [item["profile"] for item in record["results"]],
        )
        self.assertEqual(
            5,
            record["configuration"]["percentiles"][
                "cold"
            ]["p95_order_statistic"],
        )
        self.assertTrue(
            record["configuration"]["percentiles"][
                "cold"
            ]["p95_is_maximum"]
        )
        self.assertEqual(
            19,
            record["configuration"]["percentiles"][
                "warm"
            ]["p95_order_statistic"],
        )
        self.assertTrue(
            all(
                item["cold"]["total_ms"]["repetitions"]
                == COLD_REPETITIONS
                and item["warm"]["total_ms"]["repetitions"]
                == WARM_REPETITIONS
                for item in record["results"]
            )
        )
        assert_persistence_guards(record)


if __name__ == "__main__":
    result = run_persistence_benchmark()
    assert_persistence_guards(result)
    print(json.dumps(result, indent=2, sort_keys=True))
