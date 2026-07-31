# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Operation orchestration for the DAS managed-host module."""

from __future__ import absolute_import, division, print_function

from .compare import compare_observations
from .discovery import discover
from .persistence import PersistenceError, PosixStateStore
from .result import (
    build_machine_result,
    disabled_machine_result,
)
from .transition import (
    TransitionError,
    prepare_transition,
    propose_transition,
)
from .validation import ValidationError, validate_public_inputs


class OperationFailure(RuntimeError):
    """A closed, safe failure context for the controller action plugin."""

    def __init__(
        self,
        reason,
        persistence_outcome="not_attempted",
        record_id=None,
        observation=None,
        committed_result_replayable=False,
        retry_unchanged_phase=False,
    ):
        RuntimeError.__init__(self, reason)
        self.reason = reason
        self.persistence_outcome = persistence_outcome
        self.record_id = record_id
        self.observation_status = (
            None if observation is None else observation.get("status")
        )
        self.observation_reason = (
            None if observation is None else observation.get("reason_code")
        )
        self.committed_result_replayable = bool(
            committed_result_replayable
        )
        self.retry_unchanged_phase = bool(retry_unchanged_phase)

    def as_private_dict(self):
        """Return only bounded fields that the action may consume."""

        return {
            "failure_reason": self.reason,
            "persistence_outcome": self.persistence_outcome,
            "record_id": self.record_id,
            "observation_status": self.observation_status,
            "observation_reason": self.observation_reason,
            "committed_result_replayable": (
                self.committed_result_replayable
            ),
            "retry_unchanged_phase": self.retry_unchanged_phase,
        }


def _raise_transition(error, observation=None, record_id=None):
    raise OperationFailure(
        error.reason,
        persistence_outcome=error.persistence_outcome,
        record_id=record_id,
        observation=observation,
    )


def _raise_persistence(error, observation=None, record_id=None):
    raise OperationFailure(
        error.reason,
        persistence_outcome=error.persistence_outcome,
        record_id=record_id,
        observation=observation,
        committed_result_replayable=False,
        retry_unchanged_phase=bool(
            error.replacement_completed and record_id is not None
        ),
    )


def _observe(discovery, inputs):
    return discovery(
        inputs["scope"],
        inputs["discovery_timeout_seconds"],
    )


def _store_free_result(inputs, discovery, check_mode):
    observation = _observe(discovery, inputs)
    return build_machine_result(
        inputs,
        observation,
        lifecycle=None,
        simulated=check_mode,
    )


def _state_writing_result(
    inputs,
    discovery,
    persistence_factory,
    comparator,
    record_id_factory,
):
    operation = inputs["operation"]
    create_namespace = (
        operation == "pre"
        or (operation == "post" and inputs["record_id"] is None)
    )
    try:
        backend = persistence_factory(
            inputs["state_root"],
            inputs["instance_id"],
        )
        store = backend.load(
            state_max_bytes=inputs["state_max_bytes"],
            create_namespace=create_namespace,
        )
    except PersistenceError as error:
        _raise_persistence(error, record_id=inputs["record_id"])

    try:
        prepared = prepare_transition(
            store,
            operation,
            inputs["scope"],
            record_id=inputs["record_id"],
            correlation_id=inputs["correlation_id"],
            instance_id=inputs["instance_id"],
            record_id_factory=record_id_factory,
            release_validation=True,
        )
    except TransitionError as error:
        _raise_transition(error, record_id=inputs["record_id"])

    if prepared["outcome"] == "replay":
        return build_machine_result(
            inputs,
            prepared["observation"],
            lifecycle=prepared,
            simulated=False,
        )

    observation = _observe(discovery, inputs)

    def build_under_lock(current):
        transition = propose_transition(
            current,
            operation,
            observation,
            scope=inputs["scope"],
            record_id=prepared["record_id"],
            correlation_id=prepared["correlation_id"],
            instance_id=inputs["instance_id"],
            expected_revision=prepared["expected_revision"],
            phase_signature_value=prepared["phase_signature"],
            comparator=comparator,
            journal_max_records=inputs["journal_max_records"],
            state_max_bytes=inputs["state_max_bytes"],
            release_validation=True,
            prepared=prepared,
        )
        if transition["outcome"] == "replay":
            return None, transition
        return transition["store"], transition

    try:
        lifecycle = backend.transact(
            expected_revision=prepared["expected_revision"],
            state_max_bytes=inputs["state_max_bytes"],
            builder=build_under_lock,
        )
    except TransitionError as error:
        _raise_transition(
            error,
            observation=observation,
            record_id=prepared["record_id"],
        )
    except PersistenceError as error:
        _raise_persistence(
            error,
            observation=observation,
            record_id=prepared["record_id"],
        )

    return build_machine_result(
        inputs,
        lifecycle["observation"],
        lifecycle=lifecycle,
        simulated=False,
    )


def execute_operation(
    raw_inputs,
    check_mode=False,
    discovery=None,
    persistence_factory=None,
    comparator=None,
    record_id_factory=None,
):
    """Validate and execute exactly one DAS operation.

    Dependencies are optional test seams. Production uses the Docker CLI,
    secure POSIX persistence, and the canonical comparator.
    """

    inputs = validate_public_inputs(raw_inputs, check_mode=check_mode)
    if not inputs["enabled"]:
        return disabled_machine_result()

    selected_discovery = discovery or discover
    if check_mode or inputs["operation"] == "status":
        return _store_free_result(
            inputs,
            selected_discovery,
            check_mode=check_mode,
        )

    return _state_writing_result(
        inputs,
        selected_discovery,
        persistence_factory or PosixStateStore,
        comparator or compare_observations,
        record_id_factory,
    )


__all__ = (
    "OperationFailure",
    "PersistenceError",
    "TransitionError",
    "ValidationError",
    "execute_operation",
)
