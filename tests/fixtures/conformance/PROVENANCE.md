<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Conformance fixture provenance

This directory is an implementation-test copy of the frozen DAS Phase-3
conformance corpus from `matrix-docker-ansible-deploy`, commit
`32c7c106fe1b7f6a126f094774cb5531f44fb0e4`, plus the following
implementation-discovered fixture corrections applied identically in the
normative planning worktree:

- `focused/persistence.yml::canonical_byte_pressure_prunes_real_serialization`
  now binds its pre-only record timestamps to the aliased pre observation and
  carries the recomputed exact serialization hashes. Its corrected file
  SHA-256 is
  `2e1027f08764c5efbf7e1e6c3e23adc29e464a7bb2e8b57d20a03a8485033214`.
- `focused/execution-surface.yml::enabled_missing_inputs_fails_before_module`
  now expects one controller display action, matching the specification's
  required value-free `DAS input error` diagnostic and the presentation
  fixture. Its corrected file SHA-256 is
  `33b038f044540d04acc8c818ba179194ce017b462eccd28571fd725e60bb7dca`.
- `focused/normalization.yml::inspect_name_mismatch_is_scope_unknown` now
  records both `fixture-api.container_inspect` and `fixture-api.name` as
  evidence gaps. This matches the specification's atomic-chunk rule: an
  identity mismatch invalidates the inspect chunk as well as the mismatched
  name field. Its corrected file SHA-256 is
  `6d4512f518aea3a88873f96b28d319ce1d6f1ad064cd0c4a28bf5ccb5f691528`.

The copied fixture validator was also hardened to use absolute regular-
expression anchors. That validator-only change does not alter an oracle; its
SHA-256 is
`2fd948510f46491bbea6cdb8c3d8b8548fb3874c7b33b61a4a0014df625186ed`.

The planning package and its explicitly recorded corrections remain the
normative design record. This copy lets the standalone role validate itself
without creating a runtime or publication dependency on either MDAD or MASH.
Fixture files retain their original copyright and SPDX license notices.
