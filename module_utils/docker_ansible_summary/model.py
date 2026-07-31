# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Small model helpers shared by the pure DAS v1 layers."""

import copy
import json

from .constants import (
    MAX_WARNING_ENTRIES,
    MAX_WARNING_ITEM_BYTES,
    MAX_WARNING_SERIALIZED_BYTES,
)


class ModelError(ValueError):
    """Raised when a closed v1 model cannot be constructed safely."""


class PresentationCapacityError(ModelError):
    """Raised when distinct evidence cannot be represented in a fixed cell."""

    failure_reason = "presentation_capacity_exceeded"


def clone(value):
    """Return a defensive copy suitable for a machine-result envelope."""

    return copy.deepcopy(value)


def require_exact_fields(value, fields, label):
    """Reject missing and unknown fields in a closed v1 mapping."""

    if not isinstance(value, dict):
        raise ModelError("%s must be a mapping" % label)
    actual = frozenset(value)
    missing = sorted(fields - actual)
    unknown = sorted(actual - fields)
    if missing or unknown:
        parts = []
        if missing:
            parts.append("missing %s" % ", ".join(missing))
        if unknown:
            parts.append("unknown %s" % ", ".join(unknown))
        raise ModelError("%s has %s" % (label, "; ".join(parts)))


def normalize_warnings(*sources):
    """Return the exact, bounded, ASCII-byte-sorted warning union.

    This helper is intentionally defensive.  Role-generated warning templates
    are much smaller than these public model bounds, but renderers must never
    silently truncate malformed or caller-constructed internal models.
    """

    warnings = []
    for source in sources:
        if source is None:
            continue
        if not isinstance(source, (list, tuple)):
            raise ModelError("warnings must be a list")
        warnings.extend(source)

    unique = set()
    for warning in warnings:
        if not isinstance(warning, str):
            raise ModelError("warning items must be strings")
        try:
            encoded = warning.encode("ascii")
        except UnicodeEncodeError:
            raise ModelError("warning items must be printable ASCII")
        if any(byte < 0x20 or byte > 0x7E for byte in bytearray(encoded)):
            raise ModelError("warning items must be printable ASCII")
        if len(encoded) > MAX_WARNING_ITEM_BYTES:
            raise ModelError("warning item exceeds the v1 byte limit")
        unique.add(warning)

    normalized = sorted(unique, key=lambda item: item.encode("ascii"))
    if len(normalized) > MAX_WARNING_ENTRIES:
        raise ModelError("warning list exceeds the v1 entry limit")

    serialized = json.dumps(
        normalized, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(serialized) > MAX_WARNING_SERIALIZED_BYTES:
        raise ModelError("warning list exceeds the v1 serialized-byte limit")
    return normalized
