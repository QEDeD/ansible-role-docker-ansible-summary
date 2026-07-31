# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure DAS v1 lifecycle and retention transitions."""

import copy
import uuid

from .validation import (
    COMPARISON_SCHEMA_VERSION,
    DEFAULT_JOURNAL_MAX_RECORDS,
    DEFAULT_STATE_MAX_BYTES,
    SCHEMA_VERSION,
    ValidationError,
    canonical_store_bytes,
    phase_signature,
    validate_correlation_id,
    validate_instance_id,
    validate_observation,
    validate_record_id,
    validate_scope,
    validate_state_store,
)


class TransitionError(RuntimeError):
    """A modeled transition failure which must not mutate durable state."""

    def __init__(self, reason, persistence_outcome="conflict"):
        RuntimeError.__init__(self, reason)
        self.reason = reason
        self.persistence_outcome = persistence_outcome


def new_state_store(instance_id):
    """Return the exact uninitialized v1 state for an instance."""

    validate_instance_id(instance_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "instance_id": instance_id,
        "revision": 0,
        "latest_complete_post": None,
        "journal": [],
        "recently_pruned_record_ids": [],
    }


def generated_record_id():
    """Generate a record ID within the frozen public grammar."""

    return "das-" + uuid.uuid4().hex


def _record_by_id(store, record_id):
    for record in store["journal"]:
        if record["record_id"] == record_id:
            return record
    return None


def _baseline_id(store):
    baseline = store["latest_complete_post"]
    if baseline is None:
        return None
    return baseline["observation_id"]


def _phase_replay(store, record, operation, signature):
    phase = record[operation]
    stored_signature = record[operation + "_signature"]
    if phase is None:
        return None
    if stored_signature == signature:
        baseline = record[operation + "_baseline"]
        return {
            "outcome": "replay",
            "store": copy.deepcopy(store),
            "record": copy.deepcopy(record),
            "record_id": record["record_id"],
            "correlation_id": record["correlation_id"],
            "observation": copy.deepcopy(phase),
            "between_observation_delta": copy.deepcopy(
                record["between_observation_delta"]
            ),
            "run_window_delta": (
                copy.deepcopy(record["run_window_delta"])
                if operation == "post"
                else None
            ),
            "baseline": copy.deepcopy(baseline),
            "baseline_advanced": baseline["advanced"],
            "journal_status": record["status"],
            "persistence_outcome": "not_attempted",
            "replay_outcome": "idempotent",
            "pruned_record_ids": [],
        }
    raise TransitionError("signature_conflict")


def _resolve_identity(store, operation, record_id, signature):
    """Apply the before-discovery identity/replay rules."""

    record = _record_by_id(store, record_id)
    if record is None:
        if record_id in store["recently_pruned_record_ids"]:
            raise TransitionError("record_pruned")
        if operation == "post":
            raise TransitionError("unknown_record")
        return None

    replay = _phase_replay(store, record, operation, signature)
    if replay is not None:
        return replay
    if operation == "pre":
        # The only way a retained record can lack pre is a post-only record.
        raise TransitionError("signature_conflict")
    if record["status"] != "open" or record["pre"] is None:
        raise TransitionError("signature_conflict")
    return None


def prepare_transition(
    store,
    operation,
    scope,
    record_id=None,
    correlation_id=None,
    instance_id=None,
    record_id_factory=None,
    release_validation=False,
):
    """Perform all state-dependent checks that precede Docker discovery.

    The returned expected revision is the caller's optimistic commit token.
    A replay result has ``outcome == "replay"`` and requires no discovery.
    """

    validate_state_store(store, release=release_validation)
    if operation not in ("pre", "post"):
        raise ValidationError("invalid_operation", "operation")
    effective_instance = instance_id or store["instance_id"]
    validate_instance_id(effective_instance)
    if effective_instance != store["instance_id"]:
        raise TransitionError("unsafe_state_namespace", "failed")
    validate_scope(scope)
    validate_correlation_id(correlation_id)

    factory = record_id_factory or generated_record_id
    supplied_record_id = record_id is not None
    if record_id is None:
        record_id = factory()
    validate_record_id(record_id)

    record = _record_by_id(store, record_id)
    effective_correlation = correlation_id
    if operation == "post" and record is not None:
        if correlation_id is None:
            effective_correlation = record["correlation_id"]
        elif correlation_id != record["correlation_id"]:
            raise TransitionError("signature_conflict")
    signature = phase_signature(
        operation, effective_instance, scope, effective_correlation
    )

    # An omitted post ID deliberately starts a post-only record.  It does not
    # perform a lookup merely because a generated ID happens to be new.
    if operation == "post" and not supplied_record_id:
        if (
            _record_by_id(store, record_id) is not None
            or record_id in store["recently_pruned_record_ids"]
        ):
            raise TransitionError("signature_conflict")
        record = None
    else:
        replay = _resolve_identity(store, operation, record_id, signature)
        if replay is not None:
            replay["expected_revision"] = store["revision"]
            replay["phase_signature"] = signature
            return replay

    expected_revision = store["revision"]
    if operation == "post" and record is not None:
        expected_revision = record["expected_post_revision"]
        if expected_revision != store["revision"]:
            raise TransitionError("revision_conflict")

    return {
        "outcome": "proceed",
        "operation": operation,
        "instance_id": effective_instance,
        "record_id": record_id,
        "record_id_was_supplied": supplied_record_id,
        "correlation_id": effective_correlation,
        "scope": copy.deepcopy(scope),
        "phase_signature": signature,
        "expected_revision": expected_revision,
    }


def _default_comparator(before, after, instance_compatible=True):
    from .compare import compare_observations

    return compare_observations(
        before, after, instance_compatible=instance_compatible
    )


def _compare(before, after, comparator):
    compare = comparator or _default_comparator
    result = compare(before, after, instance_compatible=True)
    return copy.deepcopy(result)


def _derived_status(pre, post):
    if post is None:
        return "open"
    pre_complete = pre is not None and pre["status"] == "complete"
    post_complete = post["status"] == "complete"
    if pre_complete and post_complete:
        if pre["scope"] == post["scope"]:
            return "complete"
        return "scope_mismatch"
    if post_complete:
        return "incomplete_pre"
    if pre_complete:
        return "incomplete_post"
    return "incomplete_both"


def _append_recent_id(store, record_id, cap):
    recent = store["recently_pruned_record_ids"]
    if record_id in recent:
        recent.remove(record_id)
    recent.append(record_id)
    while len(recent) > cap:
        recent.pop(0)


def apply_retention(
    store,
    protected_record_id,
    journal_max_records=DEFAULT_JOURNAL_MAX_RECORDS,
    state_max_bytes=DEFAULT_STATE_MAX_BYTES,
    release_validation=False,
):
    """Prune a proposed store by count and exact canonical serialized bytes."""

    if (
        not isinstance(journal_max_records, int)
        or isinstance(journal_max_records, bool)
        or journal_max_records < 1
        or journal_max_records > 100
    ):
        raise ValidationError(
            "invalid_journal_max_records", "journal_max_records"
        )
    if (
        not isinstance(state_max_bytes, int)
        or isinstance(state_max_bytes, bool)
        or state_max_bytes < 1
    ):
        raise ValidationError("invalid_state_max_bytes", "state_max_bytes")
    candidate = copy.deepcopy(store)
    pruned = []

    def prune_oldest_full_record():
        for index, record in enumerate(candidate["journal"]):
            if record["record_id"] != protected_record_id:
                removed = candidate["journal"].pop(index)
                pruned.append(removed["record_id"])
                _append_recent_id(
                    candidate, removed["record_id"], journal_max_records
                )
                return True
        return False

    while len(candidate["journal"]) > journal_max_records:
        if not prune_oldest_full_record():
            raise TransitionError("state_size_limit_exceeded", "failed")
    while len(candidate["recently_pruned_record_ids"]) > journal_max_records:
        candidate["recently_pruned_record_ids"].pop(0)

    while True:
        encoded = canonical_store_bytes(candidate, release=release_validation)
        if len(encoded) <= state_max_bytes:
            return candidate, pruned
        if prune_oldest_full_record():
            continue
        if candidate["recently_pruned_record_ids"]:
            candidate["recently_pruned_record_ids"].pop(0)
            continue
        raise TransitionError("state_size_limit_exceeded", "failed")


def _make_result(store, record, operation, pruned_record_ids):
    baseline = record[operation + "_baseline"]
    return {
        "outcome": "commit",
        "store": store,
        "record": copy.deepcopy(record),
        "record_id": record["record_id"],
        "correlation_id": record["correlation_id"],
        "observation": copy.deepcopy(record[operation]),
        "between_observation_delta": copy.deepcopy(
            record["between_observation_delta"]
        ),
        "run_window_delta": (
            copy.deepcopy(record["run_window_delta"])
            if operation == "post"
            else None
        ),
        "baseline": copy.deepcopy(baseline),
        "baseline_advanced": baseline["advanced"],
        "journal_status": record["status"],
        "persistence_outcome": "committed",
        "replay_outcome": None,
        "pruned_record_ids": list(pruned_record_ids),
    }


def propose_transition(
    store,
    operation,
    observation,
    scope=None,
    record_id=None,
    correlation_id=None,
    instance_id=None,
    expected_revision=None,
    phase_signature_value=None,
    comparator=None,
    journal_max_records=DEFAULT_JOURNAL_MAX_RECORDS,
    state_max_bytes=DEFAULT_STATE_MAX_BYTES,
    record_id_factory=None,
    release_validation=False,
    prepared=None,
):
    """Propose one atomic store replacement from current committed state.

    ``expected_revision`` is the revision captured before discovery.  Identity
    and same-phase replay checks deliberately take precedence over that stale
    revision check, matching the commit-time race contract.
    """

    validate_state_store(store, release=release_validation)
    validate_observation(observation, release=release_validation)
    effective_instance = instance_id or store["instance_id"]
    effective_scope = scope or observation["scope"]
    validate_scope(effective_scope)
    if effective_scope != observation["scope"]:
        raise ValidationError("observation_scope_mismatch", "scope")

    # If no pre-discovery token was supplied, prepare against this same state.
    if prepared is None:
        prepared = prepare_transition(
            store,
            operation,
            effective_scope,
            record_id=record_id,
            correlation_id=correlation_id,
            instance_id=effective_instance,
            record_id_factory=record_id_factory,
            release_validation=release_validation,
        )
    elif (
        prepared.get("operation") != operation
        or prepared.get("instance_id") != effective_instance
        or prepared.get("scope") != effective_scope
    ):
        raise ValidationError("prepared_transition_mismatch", "prepared")
    if prepared["outcome"] == "replay":
        return prepared

    if phase_signature_value is not None:
        if phase_signature_value != prepared["phase_signature"]:
            raise TransitionError("signature_conflict")
    else:
        phase_signature_value = prepared["phase_signature"]
    if expected_revision is None:
        expected_revision = prepared["expected_revision"]

    # Re-run identity inspection on the state passed to the commit proposal.
    # This makes the function useful both before and after an injected
    # concurrent transaction.
    current_record = _record_by_id(store, prepared["record_id"])
    if current_record is not None and current_record[operation] is not None:
        replay = _phase_replay(
            store, current_record, operation, phase_signature_value
        )
        if replay is not None:
            replay["expected_revision"] = expected_revision
            replay["phase_signature"] = phase_signature_value
            return replay
    if (
        current_record is None
        and prepared["record_id"] in store["recently_pruned_record_ids"]
    ):
        raise TransitionError("record_pruned")
    if current_record is not None and current_record[operation] is None:
        if operation == "pre" or not prepared["record_id_was_supplied"]:
            raise TransitionError("signature_conflict")
        if prepared["correlation_id"] != current_record["correlation_id"]:
            raise TransitionError("signature_conflict")
    if store["revision"] != expected_revision:
        raise TransitionError("revision_conflict")

    candidate = copy.deepcopy(store)
    baseline_before_id = _baseline_id(candidate)
    new_revision = candidate["revision"] + 1
    record = _record_by_id(candidate, prepared["record_id"])

    if operation == "pre":
        if record is not None:
            raise TransitionError("signature_conflict")
        between = _compare(
            candidate["latest_complete_post"], observation, comparator
        )
        pre_baseline = {
            "advanced": False,
            "before": baseline_before_id,
            "after": baseline_before_id,
        }
        record = {
            "record_id": prepared["record_id"],
            "correlation_id": prepared["correlation_id"],
            "created_at": observation["observed_at"],
            "updated_at": observation["observed_at"],
            "expected_post_revision": new_revision,
            "pre_signature": phase_signature_value,
            "post_signature": None,
            "status": "open",
            "pre": copy.deepcopy(observation),
            "post": None,
            "between_observation_delta": between,
            "run_window_delta": None,
            "pre_baseline": pre_baseline,
            "post_baseline": None,
        }
        candidate["journal"].append(record)
    else:
        if record is None:
            # Deliberate post-only record.
            post_baseline = {
                "advanced": observation["status"] == "complete",
                "before": baseline_before_id,
                "after": (
                    observation["observation_id"]
                    if observation["status"] == "complete"
                    else baseline_before_id
                ),
            }
            record = {
                "record_id": prepared["record_id"],
                "correlation_id": prepared["correlation_id"],
                "created_at": observation["observed_at"],
                "updated_at": observation["observed_at"],
                "expected_post_revision": None,
                "pre_signature": None,
                "post_signature": phase_signature_value,
                "status": _derived_status(None, observation),
                "pre": None,
                "post": copy.deepcopy(observation),
                "between_observation_delta": None,
                "run_window_delta": None,
                "pre_baseline": None,
                "post_baseline": post_baseline,
            }
            candidate["journal"].append(record)
        else:
            if record["expected_post_revision"] != expected_revision:
                raise TransitionError("revision_conflict")
            if prepared["correlation_id"] != record["correlation_id"]:
                raise TransitionError("signature_conflict")
            run_window = _compare(record["pre"], observation, comparator)
            baseline_before_id = record["pre_baseline"]["before"]
            post_baseline = {
                "advanced": observation["status"] == "complete",
                "before": baseline_before_id,
                "after": (
                    observation["observation_id"]
                    if observation["status"] == "complete"
                    else baseline_before_id
                ),
            }
            record["updated_at"] = observation["observed_at"]
            record["post_signature"] = phase_signature_value
            record["post"] = copy.deepcopy(observation)
            record["run_window_delta"] = run_window
            record["post_baseline"] = post_baseline
            record["status"] = _derived_status(record["pre"], observation)

        if observation["status"] == "complete":
            candidate["latest_complete_post"] = copy.deepcopy(observation)

    candidate["revision"] = new_revision
    candidate, pruned = apply_retention(
        candidate,
        protected_record_id=record["record_id"],
        journal_max_records=journal_max_records,
        state_max_bytes=state_max_bytes,
        release_validation=release_validation,
    )
    retained_record = _record_by_id(candidate, record["record_id"])
    validate_state_store(candidate, release=release_validation)
    return _make_result(candidate, retained_record, operation, pruned)
