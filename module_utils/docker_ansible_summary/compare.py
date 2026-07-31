# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure comparison of canonical Docker Ansible Summary observations."""

from .constants import (
    ACTIVE_RUNTIME_STATES,
    CHANGE_KIND_ORDER,
    COMPARISON_SCHEMA_VERSION,
)
from .model import ModelError, clone


def _endpoint_fields(observation, prefix):
    if observation is None:
        return {
            "%s_observation_id" % prefix: None,
            "%s_observed_at" % prefix: None,
            "%s_scope" % prefix: None,
        }
    return {
        "%s_observation_id" % prefix: observation["observation_id"],
        "%s_observed_at" % prefix: observation["observed_at"],
        "%s_scope" % prefix: clone(observation["scope"]),
    }


def _scope_compatible(before, after):
    before_scope = before["scope"]
    after_scope = after["scope"]
    return (
        before_scope.get("comparison_schema_version")
        == COMPARISON_SCHEMA_VERSION
        and after_scope.get("comparison_schema_version")
        == COMPARISON_SCHEMA_VERSION
        and before_scope == after_scope
    )


def _restart_channel(before, after, field, is_count=False):
    old = before.get(field)
    new = after.get(field)
    if old is None or new is None:
        return "unknown"
    if is_count:
        return "positive" if new > old else "negative"
    return "positive" if new != old else "negative"


def restart_evidence(before, after):
    """Return the two exact restart-evidence channels for an eligible row."""

    return (
        _restart_channel(before, after, "started_at"),
        _restart_channel(before, after, "restart_count", is_count=True),
    )


def _ordered_kinds(kinds):
    selected = set(kinds)
    return [kind for kind in CHANGE_KIND_ORDER if kind in selected]


def _classify_pair(before, after):
    kinds = []
    degraded = False

    reference_changed = (
        before["full_image_reference"] != after["full_image_reference"]
    )
    content_changed = before["image_id"] != after["image_id"]
    recreated = before["container_id"] != after["container_id"]

    if recreated:
        kinds.append("recreated")
    if reference_changed or content_changed:
        kinds.append("image_changed")

    before_active = before["runtime_state"] in ACTIVE_RUNTIME_STATES
    after_active = after["runtime_state"] in ACTIVE_RUNTIME_STATES
    if not before_active and after_active:
        kinds.append("started")
    elif before_active and not after_active:
        kinds.append("stopped")
    elif before["runtime_state"] != after["runtime_state"]:
        kinds.append("state_changed")

    # Restart evidence is meaningful only for the same active container.  An
    # active-state transition may independently remain in the kinds list.
    if not recreated and before_active and after_active:
        start_channel, count_channel = restart_evidence(before, after)
        if "positive" in (start_channel, count_channel):
            kinds.append("restarted")
        elif not (
            start_channel == "negative" and count_channel == "negative"
        ):
            degraded = True

    if not kinds:
        kinds.append("unchanged")

    kinds = _ordered_kinds(kinds)
    return {
        "container_name": before["name"],
        "primary_kind": kinds[0],
        "kinds": kinds,
        "before": clone(before),
        "after": clone(after),
        "image_reference_changed": reference_changed,
        "image_content_changed": content_changed,
        "image_content_evidence": "image_id",
    }, degraded


def _classify_catalogues(before, after):
    before_containers = before["containers"]
    after_containers = after["containers"]
    if not isinstance(before_containers, dict) or not isinstance(
        after_containers, dict
    ):
        raise ModelError("complete observations require container mappings")

    changes = []
    degraded = False
    names = sorted(
        set(before_containers) | set(after_containers),
        key=lambda name: name.encode("ascii"),
    )
    for name in names:
        old = before_containers.get(name)
        new = after_containers.get(name)
        if old is None:
            changes.append(
                {
                    "container_name": name,
                    "primary_kind": "added",
                    "kinds": ["added"],
                    "before": None,
                    "after": clone(new),
                    "image_reference_changed": None,
                    "image_content_changed": None,
                    "image_content_evidence": None,
                }
            )
        elif new is None:
            changes.append(
                {
                    "container_name": name,
                    "primary_kind": "removed",
                    "kinds": ["removed"],
                    "before": clone(old),
                    "after": None,
                    "image_reference_changed": None,
                    "image_content_changed": None,
                    "image_content_evidence": None,
                }
            )
        else:
            delta, row_degraded = _classify_pair(old, new)
            # The map key is canonical identity even if a defensive caller
            # supplies a contradictory nested name.
            delta["container_name"] = name
            changes.append(delta)
            degraded = degraded or row_degraded
    return changes, degraded


def compare_observations(before, after, instance_compatible=True):
    """Compare two canonical observations and return a closed DeltaResult.

    ``before`` may be ``None`` to model an uninitialized baseline.  A missing
    target endpoint is not a comparison and is rejected; transition code keeps
    such a delta field null instead of inventing a comparability value.
    """

    if after is None:
        raise ModelError("the target observation is required")
    if before is not None and not isinstance(before, dict):
        raise ModelError("the source observation must be a mapping or null")
    if not isinstance(after, dict):
        raise ModelError("the target observation must be a mapping")

    result = {
        "comparability": None,
        "comparison_schema_version": COMPARISON_SCHEMA_VERSION,
        "from_observation_id": None,
        "from_observed_at": None,
        "from_scope": None,
        "to_observation_id": None,
        "to_observed_at": None,
        "to_scope": None,
        "changes": [],
        "warnings": [],
    }
    result.update(_endpoint_fields(before, "from"))
    result.update(_endpoint_fields(after, "to"))

    if after.get("status") != "complete" or (
        before is not None and before.get("status") != "complete"
    ):
        result["comparability"] = "incomplete"
        return result

    if before is None:
        result["comparability"] = "no_baseline"
        return result

    if not instance_compatible or not _scope_compatible(before, after):
        result["comparability"] = "incompatible_scope"
        return result

    changes, degraded = _classify_catalogues(before, after)
    result["comparability"] = "degraded" if degraded else "exact"
    result["changes"] = changes
    return result
