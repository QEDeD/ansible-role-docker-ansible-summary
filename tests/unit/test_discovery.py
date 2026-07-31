# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import datetime
import errno
import json
import unittest
from unittest import mock

from module_utils.docker_ansible_summary.discovery import (
    ARGV_MAX_BYTES,
    CATALOGUE_FORMAT,
    INSPECT_FORMAT,
    InspectFault,
    DiscoveryProtocolError,
    _is_exact_no_such,
    _line_limit_exceeded,
    argv_size,
    chunk_identifiers,
    discover,
    normalize_container_name,
    normalize_timestamp,
    parse_catalogue,
    parse_inspect_chunk,
)
from module_utils.docker_ansible_summary.validation import (
    normalize_scope,
    validate_observation,
)


DOCKER = "/usr/bin/docker"
CID_A = "0" * 64
CID_B = "1" * 64
IMAGE_A = "sha256:" + ("a" * 64)


def _json_lines(*items):
    return "".join(
        json.dumps(item, separators=(",", ":")) + "\n" for item in items
    ).encode()


def _scope(patterns=None):
    return {
        "patterns": patterns or ["*"],
        "identity": "sha256:" + ("f" * 64),
        "comparison_schema_version": 1,
    }


def _result(stdout=b"", stderr=b"", returncode=0, status="ok"):
    return {
        "stdout": stdout,
        "stderr": stderr,
        "returncode": returncode,
        "status": status,
    }


def _inspect(container_id=CID_A, name="/alpha", **overrides):
    item = {
        "container_id": container_id,
        "created_at": "2026-07-30T12:00:00.100000000Z",
        "finished_at": "0001-01-01T00:00:00Z",
        "full_image_reference": "registry.example:5000/team/app:stable",
        "image_id": IMAGE_A,
        "name": name,
        "restart_count": 0,
        "runtime_state": "running",
        "started_at": "2026-07-30T12:00:01Z",
    }
    item.update(overrides)
    return item


class FakeRunner(object):
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, timeout_seconds):
        self.calls.append((argv, timeout_seconds))
        return self.results.pop(0)


def _wall_clock():
    return datetime.datetime(2026, 7, 30, 12, 0, 0)


def _monotonic(values):
    iterator = iter(values)
    return lambda: next(iterator)


class DiscoveryTests(unittest.TestCase):
    def test_protocol_tokens_are_anchored_at_the_absolute_string_end(self):
        for value in ("alpha\n", "alpha\r", "alpha\x00"):
            with self.subTest(kind="container_name", value=repr(value)):
                self.assertIsNone(normalize_container_name(value))

        with self.assertRaises(DiscoveryProtocolError):
            parse_catalogue(
                _json_lines({"id": CID_A + "\n", "name": "/alpha"})
            )
        self.assertEqual(
            [{"container_id": CID_A, "name": None}],
            parse_catalogue(
                _json_lines({"id": CID_A, "name": "/alpha\n"})
            ),
        )

        for overrides in (
            {"container_id": CID_A + "\n"},
            {"image_id": IMAGE_A + "\n"},
            {"name": "/alpha\n"},
        ):
            with self.subTest(inspect_overrides=overrides):
                with self.assertRaises(InspectFault):
                    parse_inspect_chunk(
                        _json_lines(_inspect(**overrides)),
                        [{"container_id": CID_A, "name": "alpha"}],
                    )

    def test_exact_command_templates_are_frozen(self):
        self.assertEqual(
            CATALOGUE_FORMAT,
            '{"id":{{json .ID}},"name":{{json .Names}}}',
        )
        self.assertEqual(
            INSPECT_FORMAT,
            (
                '{"container_id":{{json .Id}},"created_at":{{json .Created}},'
                '"finished_at":{{json .State.FinishedAt}},'
                '"full_image_reference":{{json .Config.Image}},'
                '"image_id":{{json .Image}},"name":{{json .Name}},'
                '"restart_count":{{json .RestartCount}},'
                '"runtime_state":{{json .State.Status}},'
                '"started_at":{{json .State.StartedAt}}}'
            ),
        )

    def test_catalogue_parser_rejects_nonterminated_and_duplicate_protocol(self):
        with self.assertRaises(DiscoveryProtocolError):
            parse_catalogue(
                json.dumps({"id": CID_A, "name": "alpha"}).encode()
            )
        with self.assertRaises(DiscoveryProtocolError):
            parse_catalogue(
                _json_lines(
                    {"id": CID_A, "name": "alpha"},
                    {"id": CID_A, "name": "beta"},
                )
            )
        with self.assertRaises(DiscoveryProtocolError):
            parse_catalogue(
                (
                    '{"id":"%s","id":"%s","name":"alpha"}\n'
                    % (CID_A, CID_A)
                ).encode()
            )

    def test_protocol_uses_only_lf_as_a_record_delimiter(self):
        first = json.dumps({"id": CID_A, "name": "alpha"}).encode()
        second = json.dumps({"id": CID_B, "name": "beta"}).encode()
        for separator in (b"\r\n", b"\x0b", b"\x0c"):
            with self.subTest(separator=repr(separator)):
                with self.assertRaises(DiscoveryProtocolError):
                    parse_catalogue(first + separator + second + b"\n")

        with mock.patch(
            "module_utils.docker_ansible_summary.discovery."
            "OUTPUT_LINE_MAX_BYTES",
            32,
        ):
            self.assertFalse(_line_limit_exceeded((b"x" * 32) + b"\n"))
            self.assertTrue(
                _line_limit_exceeded(
                    (b"x" * 20) + b"\x0b" + (b"x" * 20) + b"\n"
                )
            )

    def test_no_such_object_classifier_requires_exact_lf_records(self):
        exact = ("Error: No such object: " + CID_A + "\n").encode()
        self.assertTrue(_is_exact_no_such(exact, [CID_A]))
        for malformed in (
            exact.rstrip(b"\n"),
            exact.replace(b"\n", b"\r\n"),
            exact.rstrip(b"\n") + b"\x0b",
        ):
            with self.subTest(stderr=repr(malformed[-8:])):
                self.assertFalse(_is_exact_no_such(malformed, [CID_A]))

    def test_catalogue_normalizes_one_leading_slash_and_stable_sorts(self):
        self.assertEqual(
            parse_catalogue(
                _json_lines(
                    {"id": CID_B, "name": "/beta"},
                    {"id": CID_A, "name": "/Alpha"},
                )
            ),
            [
                {"container_id": CID_A, "name": "Alpha"},
                {"container_id": CID_B, "name": "beta"},
            ],
        )

    def test_complete_empty_catalogue_is_authoritative(self):
        runner = FakeRunner([_result()])
        observation = discover(
            normalize_scope("*"),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1]),
            observation_id_factory=lambda: "obs-empty",
        )
        self.assertEqual(observation["status"], "complete")
        self.assertEqual(observation["containers"], {})
        self.assertIsNone(observation["reason_code"])
        self.assertEqual(observation["warnings"], [])
        self.assertEqual(len(runner.calls), 1)

    def test_scope_is_applied_before_one_atomic_inspect_chunk(self):
        runner = FakeRunner(
            [
                _result(
                    _json_lines(
                        {"id": CID_A, "name": "/alpha"},
                        {"id": CID_B, "name": "/beta"},
                    )
                ),
                _result(_json_lines(_inspect())),
            ]
        )
        observation = discover(
            _scope(["a*"]),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1, 10.2]),
            observation_id_factory=lambda: "obs-alpha",
        )
        self.assertEqual(observation["status"], "complete")
        self.assertEqual(list(observation["containers"]), ["alpha"])
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[1][0][-1], CID_A)
        self.assertNotIn(CID_B, runner.calls[1][0])

    def test_optional_timestamp_and_restart_gaps_do_not_make_partial(self):
        item = _inspect(
            created_at="not-a-time",
            started_at=None,
            finished_at="0001-01-01T00:00:00Z",
            restart_count=True,
        )
        containers, gaps, partial_reason = parse_inspect_chunk(
            _json_lines(item), [{"container_id": CID_A, "name": "alpha"}]
        )
        self.assertIsNone(partial_reason)
        self.assertIsNone(containers["alpha"]["created_at"])
        self.assertIsNone(containers["alpha"]["finished_at"])
        self.assertEqual(
            sorted(gaps),
            [
                "alpha.created_at",
                "alpha.restart_count",
                "alpha.started_at",
            ],
        )

    def test_same_chunk_missing_required_evidence_is_retained_and_partial(self):
        runner = FakeRunner(
            [
                _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                _result(_json_lines(_inspect(image_id=None))),
            ]
        )
        observation = discover(
            normalize_scope("*"),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1, 10.2]),
            observation_id_factory=lambda: "obs-partial",
        )
        self.assertEqual(observation["status"], "partial")
        self.assertEqual(list(observation["containers"]), ["alpha"])
        self.assertIsNone(
            observation["containers"]["alpha"]["image_id"]
        )
        self.assertEqual(observation["reason_code"], "required_field_missing")
        self.assertEqual(
            ["alpha.image_id"], observation["metadata_gaps"]
        )
        validate_observation(observation, release=True)

    def test_field_local_required_and_unsupported_evidence_is_retained(self):
        variants = (
            (
                "missing_reference",
                {"full_image_reference": None},
                "required_field_missing",
                "full_image_reference",
            ),
            (
                "missing_image_id",
                {"image_id": None},
                "required_field_missing",
                "image_id",
            ),
            (
                "missing_runtime",
                {"runtime_state": None},
                "required_field_missing",
                "runtime_state",
            ),
            (
                "unsupported_runtime",
                {"runtime_state": "hibernating"},
                "unsupported_runtime_state",
                "runtime_state",
            ),
        )
        for label, mutation, reason, field in variants:
            runner = FakeRunner(
                [
                    _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                    _result(_json_lines(_inspect(**mutation))),
                ]
            )
            observation = discover(
                normalize_scope("*"),
                30,
                docker_path=DOCKER,
                runner=runner,
                wall_clock=_wall_clock,
                monotonic=_monotonic([10.0, 10.1, 10.2]),
                observation_id_factory=lambda: "obs-field-local",
            )
            with self.subTest(variant=label):
                self.assertEqual("partial", observation["status"])
                self.assertEqual(reason, observation["reason_code"])
                self.assertEqual(["alpha"], list(observation["containers"]))
                self.assertIsNone(
                    observation["containers"]["alpha"][field]
                )
                self.assertEqual(
                    ["alpha." + field],
                    observation["metadata_gaps"],
                )
                validate_observation(observation, release=True)

    def test_wrong_required_type_is_protocol_error_not_missing_evidence(self):
        runner = FakeRunner(
            [
                _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                _result(_json_lines(_inspect(image_id=123))),
            ]
        )
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1, 10.2]),
            observation_id_factory=lambda: "obs-protocol",
        )
        self.assertEqual("partial", observation["status"])
        self.assertEqual("docker_protocol_error", observation["reason_code"])

    def test_wrong_name_type_and_nonfinite_json_are_protocol_errors(self):
        for raw_inspect in (
            _json_lines(_inspect(name=123)),
            (
                json.dumps(_inspect()).replace(
                    '"restart_count": 0', '"restart_count": NaN'
                )
                + "\n"
            ).encode(),
        ):
            runner = FakeRunner(
                [
                    _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                    _result(raw_inspect),
                ]
            )
            observation = discover(
                normalize_scope("*"),
                30,
                docker_path=DOCKER,
                runner=runner,
                wall_clock=_wall_clock,
                monotonic=_monotonic([10.0, 10.1, 10.2]),
                observation_id_factory=lambda: "obs-structural-protocol",
            )
            self.assertEqual(
                "docker_protocol_error", observation["reason_code"]
            )

    def test_unhashable_and_wrong_container_id_types_are_protocol_errors(self):
        for invalid_id in (None, 1, [], {}):
            runner = FakeRunner(
                [
                    _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                    _result(
                        _json_lines(_inspect(container_id=invalid_id))
                    ),
                ]
            )
            observation = discover(
                normalize_scope("*"),
                30,
                docker_path=DOCKER,
                runner=runner,
                wall_clock=_wall_clock,
                monotonic=_monotonic([10.0, 10.1, 10.2]),
                observation_id_factory=lambda: "obs-id-type-protocol",
            )
            self.assertEqual(
                "docker_protocol_error", observation["reason_code"]
            )
            self.assertEqual(
                ["alpha.container_inspect"],
                observation["metadata_gaps"],
            )
            validate_observation(observation, release=True)

    def test_chunk_identity_faults_remain_valid_atomic_partial_observations(self):
        variants = (
            (
                "malformed",
                _json_lines(_inspect(container_id=None)),
                "docker_protocol_error",
            ),
            (
                "unexpected",
                _json_lines(_inspect(container_id=CID_B)),
                "required_field_missing",
            ),
            (
                "duplicate",
                _json_lines(_inspect(), _inspect()),
                "required_field_missing",
            ),
            ("missing", b"", "required_field_missing"),
        )
        for label, inspect_output, reason in variants:
            runner = FakeRunner(
                [
                    _result(
                        _json_lines({"id": CID_A, "name": "/alpha"})
                    ),
                    _result(inspect_output),
                ]
            )
            observation = discover(
                normalize_scope("*"),
                30,
                docker_path=DOCKER,
                runner=runner,
                wall_clock=_wall_clock,
                monotonic=_monotonic([10.0, 10.1, 10.2]),
                observation_id_factory=lambda: "obs-chunk-identity",
            )
            with self.subTest(variant=label):
                self.assertEqual("partial", observation["status"])
                self.assertEqual(reason, observation["reason_code"])
                self.assertEqual({}, observation["containers"])
                self.assertEqual(
                    ["alpha.container_inspect"],
                    observation["metadata_gaps"],
                )
                validate_observation(observation, release=True)

    def test_duplicate_inspect_json_key_is_protocol_error(self):
        duplicate = (
            '{"container_id":"%s","container_id":"%s",'
            '"created_at":"2026-07-30T12:00:00Z",'
            '"finished_at":"0001-01-01T00:00:00Z",'
            '"full_image_reference":"example:1",'
            '"image_id":"%s","name":"/alpha","restart_count":0,'
            '"runtime_state":"running",'
            '"started_at":"2026-07-30T12:00:01Z"}\n'
            % (CID_A, CID_A, IMAGE_A)
        ).encode()
        runner = FakeRunner(
            [
                _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                _result(duplicate),
            ]
        )
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1, 10.2]),
            observation_id_factory=lambda: "obs-duplicate",
        )
        self.assertEqual("docker_protocol_error", observation["reason_code"])

    def test_executable_disappearing_is_bounded_unavailable(self):
        def missing_runner(_argv, _timeout):
            raise OSError(errno.ENOENT, "not returned")

        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=missing_runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1]),
            observation_id_factory=lambda: "obs-missing-cli",
        )
        self.assertEqual("unavailable", observation["status"])
        self.assertEqual("docker_cli_absent", observation["reason_code"])

    def test_cli_absence_is_unavailable_not_complete_empty(self):
        with mock.patch(
            "module_utils.docker_ansible_summary.discovery.shutil.which",
            return_value=None,
        ):
            observation = discover(
                _scope(),
                30,
                docker_path=None,
                runner=FakeRunner([]),
                wall_clock=_wall_clock,
                monotonic=_monotonic([10.0]),
                observation_id_factory=lambda: "obs-unavailable",
            )
        self.assertEqual(observation["status"], "unavailable")
        self.assertIsNone(observation["containers"])
        self.assertEqual(observation["reason_code"], "docker_cli_absent")

    def test_catalogue_timeout_is_unavailable(self):
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=FakeRunner([_result(status="timeout", returncode=None)]),
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1]),
            observation_id_factory=lambda: "obs-timeout",
        )
        self.assertEqual(observation["status"], "unavailable")
        self.assertIsNone(observation["containers"])
        self.assertEqual(observation["reason_code"], "docker_command_timeout")
        self.assertEqual(
            observation["warnings"], ["Docker discovery command timed out"]
        )

    def test_exact_no_such_discards_chunk_without_echoing_stderr(self):
        runner = FakeRunner(
            [
                _result(_json_lines({"id": CID_A, "name": "/alpha"})),
                _result(
                    stderr=("Error: No such object: " + CID_A + "\n").encode(),
                    returncode=1,
                ),
            ]
        )
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic([10.0, 10.1, 10.2]),
            observation_id_factory=lambda: "obs-race",
        )
        self.assertEqual(observation["status"], "partial")
        self.assertEqual(observation["reason_code"], "required_field_missing")
        self.assertNotIn(CID_A, json.dumps(observation))

    def test_chunking_binds_complete_argv_bytes_and_preserves_order(self):
        fixed = [DOCKER, "container", "inspect"]
        identifiers = [("%064x" % number) for number in range(10)]
        limit = argv_size(fixed + identifiers[:3])
        chunks = chunk_identifiers(
            fixed, identifiers, max_items=100, max_bytes=limit
        )
        self.assertEqual([len(chunk) for chunk in chunks], [3, 3, 3, 1])
        self.assertEqual(
            [item for chunk in chunks for item in chunk], identifiers
        )
        self.assertTrue(
            all(argv_size(fixed + chunk) <= limit for chunk in chunks)
        )
        self.assertEqual(ARGV_MAX_BYTES, 8192)

    def test_one_deadline_budget_decreases_across_all_inspect_chunks(self):
        identifiers = ["%064x" % number for number in range(301)]
        names = ["fixture-%03d" % number for number in range(301)]
        catalogue = _result(
            _json_lines(
                *[
                    {"id": identifier, "name": "/" + name}
                    for identifier, name in zip(identifiers, names)
                ]
            )
        )
        inspect_results = []
        for offset in (0, 100, 200):
            inspect_results.append(
                _result(
                    _json_lines(
                        *[
                            _inspect(
                                container_id=identifier,
                                name="/" + name,
                            )
                            for identifier, name in zip(
                                identifiers[offset:offset + 100],
                                names[offset:offset + 100],
                            )
                        ]
                    )
                )
            )
        runner = FakeRunner(
            [catalogue]
            + inspect_results
            + [_result(status="timeout", returncode=None)]
        )

        observation = discover(
            _scope(["fixture-*"]),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_wall_clock,
            monotonic=_monotonic(
                [1000.0, 1000.0, 1002.0, 1007.0, 1014.0, 1018.0]
            ),
            observation_id_factory=lambda: "obs-shared-deadline",
        )

        self.assertEqual(
            [30.0, 28.0, 23.0, 16.0, 12.0],
            [timeout for _argv, timeout in runner.calls],
        )
        self.assertTrue(
            all(
                later < earlier
                for earlier, later in zip(
                    [timeout for _argv, timeout in runner.calls],
                    [timeout for _argv, timeout in runner.calls][1:],
                )
            )
        )
        self.assertEqual("partial", observation["status"])
        self.assertEqual(
            "docker_command_timeout", observation["reason_code"]
        )
        self.assertEqual(300, len(observation["containers"]))
        self.assertEqual(
            ["fixture-300.container_inspect"],
            observation["metadata_gaps"],
        )

    def test_timestamp_normalization(self):
        cases = [
            (
                "2026-07-30T12:00:00.120000000Z",
                False,
                "2026-07-30T12:00:00.12Z",
                False,
            ),
            ("0001-01-01T00:00:00Z", True, None, False),
            ("0001-01-01T00:00:00Z", False, None, True),
            ("invalid", False, None, True),
        ]
        for value, semantic_zero, expected, gap in cases:
            with self.subTest(value=value, semantic_zero=semantic_zero):
                self.assertEqual(
                    normalize_timestamp(value, semantic_zero),
                    (expected, gap),
                )


if __name__ == "__main__":
    unittest.main()
