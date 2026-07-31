# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Loss-aware v1 image-reference parsing and report-wide projection."""

import hashlib
import re

from .model import ModelError, PresentationCapacityError


_IMAGE_ID_RE = re.compile(r"\Asha256:([0-9a-f]{64})\Z")
_TAG_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_COMPONENT_RE = re.compile(r"\A[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_DNS_LABEL_RE = re.compile(
    r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_ESCAPE_ATOM_RE = re.compile(r"\\x[0-9a-f]{2}")


def visible_escape(value):
    """Project arbitrary UTF-8 text to the exact visible ASCII vocabulary."""

    if not isinstance(value, str):
        raise ModelError("visible escaping requires a string")
    output = []
    reserved = frozenset((0x5C, 0x7C, 0x7E, 0x23, 0x3C, 0x3E))
    for byte in bytearray(value.encode("utf-8")):
        if 0x20 <= byte <= 0x7E and byte not in reserved:
            output.append(chr(byte))
        else:
            output.append("\\x%02x" % byte)
    return "".join(output)


def tail_weighted_elide(value, width):
    """Apply the frozen two-fifths/three-fifths middle-elision rule."""

    if len(value) <= width:
        return value
    if width < 2:
        raise PresentationCapacityError(
            "a readable value and elision marker do not fit"
        )
    left = max(1, (2 * (width - 1)) // 5)
    right = width - 1 - left
    suffix = value[-right:] if right else ""
    return value[:left] + "~" + suffix


def _authority_is_valid(value):
    host = value
    port = None
    if ":" in value:
        if value.count(":") != 1:
            return False
        host, port = value.rsplit(":", 1)
        if not port.isdigit() or (len(port) > 1 and port.startswith("0")):
            return False
        if not 1 <= int(port) <= 65535:
            return False

    if host == "localhost":
        return True
    labels = host.split(".")
    return len(labels) >= 2 and all(_DNS_LABEL_RE.match(item) for item in labels)


def _repository_is_valid(repository):
    components = repository.split("/")
    if not components or any(not item for item in components):
        return False

    first = components[0]
    authority_candidate = (
        len(components) >= 2
        and (first == "localhost" or "." in first or ":" in first)
    )
    if authority_candidate:
        if not _authority_is_valid(first):
            return False
        components = components[1:]
    return bool(components) and all(
        _COMPONENT_RE.match(item) for item in components
    )


def _opaque(reference):
    return {
        "kind": "opaque_reference",
        "disambiguation_reason": None,
        "repository": None,
        "repository_basename": None,
        "tag": None,
        "digest": None,
        "full_image_reference": reference,
        "compact_label": "o:" + visible_escape(reference),
    }


def parse_image_reference(full_image_reference):
    """Structurally classify one canonical configured reference.

    The returned mapping is a test-facing diagnostic record.  Classification
    is presentation-only and deliberately narrower than registry resolution.
    """

    if full_image_reference is None:
        return {
            "kind": "missing_reference",
            "disambiguation_reason": None,
            "repository": None,
            "repository_basename": None,
            "tag": None,
            "digest": None,
            "full_image_reference": None,
            "compact_label": "<unknown>",
        }
    if not isinstance(full_image_reference, str) or not full_image_reference:
        raise ModelError("a configured image reference must be a nonempty string")

    bare = _IMAGE_ID_RE.match(full_image_reference)
    if bare:
        digest = full_image_reference
        return {
            "kind": "bare_image_id",
            "disambiguation_reason": None,
            "repository": None,
            "repository_basename": None,
            "tag": None,
            "digest": digest,
            "full_image_reference": full_image_reference,
            "compact_label": "sha256:" + bare.group(1)[:12],
        }

    if full_image_reference.count("@") > 1:
        return _opaque(full_image_reference)

    pre_digest = full_image_reference
    digest = None
    if "@" in full_image_reference:
        pre_digest, digest = full_image_reference.split("@", 1)
        if not _IMAGE_ID_RE.match(digest):
            return _opaque(full_image_reference)

    final_slash = pre_digest.rfind("/")
    final_colon = pre_digest.rfind(":")
    tag = None
    repository = pre_digest
    if final_colon > final_slash:
        repository = pre_digest[:final_colon]
        tag = pre_digest[final_colon + 1 :]
        if not _TAG_RE.match(tag):
            return _opaque(full_image_reference)

    if not repository or not _repository_is_valid(repository):
        return _opaque(full_image_reference)

    basename = repository.rsplit("/", 1)[-1]
    if digest is not None and tag is not None:
        kind = "tagged_digest_reference"
        compact = "%s:%s@sha256:%s" % (
            basename,
            tag,
            digest[7:19],
        )
    elif digest is not None:
        kind = "digest_reference"
        compact = "%s@sha256:%s" % (basename, digest[7:19])
    elif tag is not None:
        kind = "tagged_reference"
        compact = "%s:%s" % (basename, tag)
    else:
        kind = "untagged_reference"
        compact = "%s <no explicit tag>" % basename

    return {
        "kind": kind,
        "disambiguation_reason": None,
        "repository": repository,
        "repository_basename": basename,
        "tag": tag,
        "digest": digest,
        "full_image_reference": full_image_reference,
        "compact_label": compact,
    }


def _identity_value(value):
    if isinstance(value, dict):
        return value.get("full_image_reference"), value.get("image_id")
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return value[0], value[1]
    raise ModelError(
        "image identities must be mappings or (reference, image_id) pairs"
    )


def _shortest_unique_prefix(values, minimum):
    distinct = sorted(set(values))
    if len(distinct) <= 1:
        return minimum
    maximum = max(len(item) for item in distinct)
    for length in range(minimum, maximum + 1):
        if len(set(item[:length] for item in distinct)) == len(distinct):
            return length
    raise PresentationCapacityError("canonical identities cannot be separated")


def _digest_stem(parsed):
    kind = parsed["kind"]
    if kind == "bare_image_id":
        return ("bare_image_id",)
    if kind == "digest_reference":
        return ("digest_reference", parsed["repository_basename"])
    if kind == "tagged_digest_reference":
        return (
            "tagged_digest_reference",
            parsed["repository_basename"],
            parsed["tag"],
        )
    return None


def _labels_for_parsed(parsed, digest_prefix_length):
    kind = parsed["kind"]
    basename = parsed["repository_basename"]
    repository = parsed["repository"]
    tag = parsed["tag"]
    digest = parsed["digest"]

    if kind == "bare_image_id":
        suffix = "sha256:" + digest[7 : 7 + digest_prefix_length]
        return suffix, suffix, None, suffix
    if kind == "tagged_reference":
        suffix = ":" + tag
    elif kind == "untagged_reference":
        suffix = " <no explicit tag>"
    elif kind == "digest_reference":
        suffix = "@sha256:" + digest[7 : 7 + digest_prefix_length]
    elif kind == "tagged_digest_reference":
        suffix = ":%s@sha256:%s" % (
            tag,
            digest[7 : 7 + digest_prefix_length],
        )
    else:
        raise ModelError("opaque and missing references have separate projection")
    return basename + suffix, repository + suffix, basename, suffix


def _escaped_atoms(value):
    atoms = []
    index = 0
    while index < len(value):
        candidate = value[index : index + 4]
        if len(candidate) == 4 and _ESCAPE_ATOM_RE.match(candidate):
            atoms.append(candidate)
            index += 4
        else:
            atoms.append(value[index])
            index += 1
    return atoms


def _take_atom_prefix(atoms, budget):
    result = []
    used = 0
    for atom in atoms:
        if used + len(atom) > budget:
            break
        result.append(atom)
        used += len(atom)
    return result


def _opaque_reduce(semantic_label, width):
    if len(semantic_label) <= width:
        return semantic_label
    if not semantic_label.startswith("o:") or width < 3:
        raise PresentationCapacityError("opaque marker cannot be represented")
    payload = semantic_label[2:]
    budget = width - 2
    if budget < 2:
        raise PresentationCapacityError("opaque payload cannot be represented")
    left_budget = max(1, (2 * (budget - 1)) // 5)
    right_budget = budget - 1 - left_budget
    atoms = _escaped_atoms(payload)
    left = _take_atom_prefix(atoms, left_budget)
    right = list(
        reversed(_take_atom_prefix(list(reversed(atoms)), right_budget))
    )
    return "o:" + "".join(left) + "~" + "".join(right)


def _structured_reduce(expanded, compact, basename, suffix, width):
    if len(expanded) <= width:
        return expanded
    if len(compact) <= width:
        return compact
    if (
        basename is not None
        and suffix
        and len(suffix) + 2 <= width
    ):
        prefix_width = width - len(suffix) - 1
        return basename[:prefix_width] + "~" + suffix
    return tail_weighted_elide(compact, width)


def _image_identity_hash(identity):
    reference, image_id = identity
    material = (reference or "") + "\0" + (image_id or "")
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def _image_id_token(image_id):
    match = _IMAGE_ID_RE.match(image_id or "")
    return match.group(1) if match else "<unknown>"


def project_image_labels(identities, width):
    """Assign deterministic, collision-safe labels report-wide.

    ``identities`` is a mapping from caller-owned cell keys to either canonical
    container mappings or ``(full_image_reference, image_id)`` pairs.  The
    return value uses the same keys and never mutates the canonical evidence.
    """

    if not isinstance(identities, dict):
        raise ModelError("image identities must be supplied as a mapping")
    if not isinstance(width, int) or isinstance(width, bool) or width < 1:
        raise ModelError("image label width must be a positive integer")

    by_key = {}
    distinct = {}
    for key, value in identities.items():
        identity = _identity_value(value)
        by_key[key] = identity
        distinct.setdefault(identity, parse_image_reference(identity[0]))

    # Digest prefixes are selected report-wide within otherwise equal compact
    # stems.  Equal digests intentionally share a prefix.
    digest_groups = {}
    for identity, parsed in distinct.items():
        stem = _digest_stem(parsed)
        if stem is not None:
            digest_groups.setdefault(stem, []).append(parsed["digest"][7:])
    digest_lengths = {
        stem: _shortest_unique_prefix(values, 12)
        for stem, values in digest_groups.items()
    }

    records = {}
    for identity, parsed in distinct.items():
        kind = parsed["kind"]
        if kind == "missing_reference":
            records[identity] = {
                "kind": kind,
                "compact": "<unknown>",
                "expanded": "<unknown>",
                "basename": None,
                "suffix": "",
                "expand": False,
            }
        elif kind == "opaque_reference":
            semantic = "o:" + visible_escape(identity[0])
            records[identity] = {
                "kind": kind,
                "compact": semantic,
                "expanded": semantic,
                "basename": None,
                "suffix": "",
                "expand": False,
            }
        else:
            prefix_length = digest_lengths.get(_digest_stem(parsed), 12)
            compact, expanded, basename, suffix = _labels_for_parsed(
                parsed, prefix_length
            )
            records[identity] = {
                "kind": kind,
                "compact": compact,
                "expanded": expanded,
                "basename": basename,
                "suffix": suffix,
                "expand": False,
            }

    # The same configured reference with multiple immutable IDs must expose
    # the shortest unique real image-ID prefix.
    reference_groups = {}
    for identity in distinct:
        reference_groups.setdefault(identity[0], []).append(identity)
    for reference, group in reference_groups.items():
        tokens = [_image_id_token(identity[1]) for identity in group]
        if len(set(tokens)) <= 1:
            continue
        real_tokens = [token for token in tokens if token != "<unknown>"]
        prefix_length = (
            _shortest_unique_prefix(real_tokens, 7) if real_tokens else 7
        )
        for identity, token in zip(group, tokens):
            selected = (
                token[:prefix_length] if token != "<unknown>" else token
            )
            addition = "@" + selected
            records[identity]["compact"] += addition
            records[identity]["expanded"] += addition
            records[identity]["suffix"] += addition

    # Only recognized labels with an actual compact collision expand their
    # complete repository context.
    compact_groups = {}
    for identity, record in records.items():
        compact_groups.setdefault(record["compact"], []).append(identity)
    for group in compact_groups.values():
        references = set(identity[0] for identity in group)
        if len(references) > 1:
            for identity in group:
                if records[identity]["kind"] not in (
                    "opaque_reference",
                    "missing_reference",
                    "bare_image_id",
                ):
                    records[identity]["expand"] = True

    candidates = {}
    for identity, record in records.items():
        if record["kind"] == "opaque_reference":
            candidates[identity] = _opaque_reduce(record["compact"], width)
        elif record["kind"] == "missing_reference":
            if len(record["compact"]) > width:
                raise PresentationCapacityError(
                    "the semantic unknown token cannot be represented"
                )
            candidates[identity] = record["compact"]
        else:
            expanded = (
                record["expanded"] if record["expand"] else record["compact"]
            )
            candidates[identity] = _structured_reduce(
                expanded,
                record["compact"],
                record["basename"],
                record["suffix"],
                width,
            )

    collision_groups = {}
    for identity, candidate in candidates.items():
        collision_groups.setdefault(candidate, []).append(identity)
    for group in collision_groups.values():
        if len(group) <= 1:
            continue
        hashes = [_image_identity_hash(identity) for identity in group]
        prefix_length = _shortest_unique_prefix(hashes, 4)
        readable_width = width - prefix_length - 1
        if readable_width < 1:
            raise PresentationCapacityError(
                "a readable label and unique hash suffix do not fit"
            )
        for identity, digest in zip(group, hashes):
            record = records[identity]
            if record["kind"] == "opaque_reference":
                readable = _opaque_reduce(record["compact"], readable_width)
            elif record["kind"] == "missing_reference":
                raise PresentationCapacityError(
                    "distinct missing references cannot be represented"
                )
            else:
                readable = _structured_reduce(
                    record["compact"],
                    record["compact"],
                    record["basename"],
                    record["suffix"],
                    readable_width,
                )
            candidates[identity] = (
                readable + "#" + digest[:prefix_length]
            )

    final_values = {}
    for identity, candidate in candidates.items():
        other = final_values.get(candidate)
        if other is not None and other != identity:
            raise PresentationCapacityError(
                "distinct identities still collide after projection"
            )
        final_values[candidate] = identity
    return {key: candidates[identity] for key, identity in by_key.items()}


def project_image_identities(identities, width):
    """Compatibility spelling for callers that emphasize canonical identity."""

    return project_image_labels(identities, width)


def project_image_diagnostics(identities, width):
    """Return test-only kind/reason records alongside final projected labels.

    These diagnostics deliberately do not enter ReportModel or persisted
    evidence.  Their purpose is to make semantic disambiguation independently
    testable without reverse-engineering a rendered cell.
    """

    labels = project_image_labels(identities, width)
    by_key = {key: _identity_value(value) for key, value in identities.items()}
    parsed = {
        key: parse_image_reference(identity[0])
        for key, identity in by_key.items()
    }

    compact_groups = {}
    reference_groups = {}
    for key, identity in by_key.items():
        compact_groups.setdefault(parsed[key]["compact_label"], []).append(key)
        reference_groups.setdefault(identity[0], []).append(key)

    diagnostics = {}
    for key, identity in by_key.items():
        reason = None
        same_reference = reference_groups[identity[0]]
        if len(set(by_key[item][1] for item in same_reference)) > 1:
            reason = "image_id_changed_under_equal_reference"

        compact_group = compact_groups[parsed[key]["compact_label"]]
        if len(set(by_key[item][0] for item in compact_group)) > 1:
            reason = "repository_context"

        # A literal hash marker can only be generated here: canonical
        # structured forms reject it and opaque references visibly escape it.
        if "#" in labels[key]:
            reason = "readable_compaction_collision"
        elif "~" in labels[key] and reason is None:
            reason = "width_reduction"

        diagnostics[key] = {
            "kind": parsed[key]["kind"],
            "disambiguation_reason": reason,
            "label": labels[key],
        }
    return diagnostics


def project_image_reference(full_image_reference, image_id, width):
    """Convenience projection for a single identity."""

    return project_image_labels(
        {"value": (full_image_reference, image_id)}, width
    )["value"]
