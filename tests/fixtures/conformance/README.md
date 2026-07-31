<!--
SPDX-FileCopyrightText: 2026 MDAD project contributors
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DAS rewrite synthetic fixtures

These fixtures are the implementation-test copy described in
[`PROVENANCE.md`](PROVENANCE.md). The frozen planning package remains the
normative contract.

- `schema.yml` defines the union fixture vocabulary and routes each family.
- `scenarios/` contains the 22 numbered conformance scenarios.
- `legacy/` contains the valid, missing, partial, and malformed legacy
  cutover variants referenced by scenario 22, plus a valid-source-conflict
  companion.
- `focused/` covers explicit pre/check/post-only paths, remaining change kinds,
  persistence/replay/retention invariants, normalization edge cases, and the
  strict boundary between native DAS state and MDAD-owned legacy cutover
  reporting, plus table/report models, execution/noise budgets, and structural
  image-display projection.

All values are invented. They must never be replaced with raw inventory,
managed-host fact files, controller logs, Docker inspect payloads, credentials,
or other secret-bearing data.

Timestamps, identifiers, digests, revisions, and expected ordering are fixed.
Numbered scenarios drive lifecycle transitions; legacy companions cover the
MDAD cutover boundary; focused matrices drive pure comparison, persistence,
normalization, role-contract, performance/noise, version-display, and
presentation tests.

## Validation

From the standalone role repository root, run:

```sh
python3 tests/fixtures/conformance/validate.py
```

The planning-only validator rejects duplicate YAML keys, malformed fixture
shapes and identifiers, missing coverage cases, and unexpected fixture counts.
It requires PyYAML and exits nonzero with file- and field-specific errors.
