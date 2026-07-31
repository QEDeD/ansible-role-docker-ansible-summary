# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Standard-library helpers shared by role-contract tests."""

from pathlib import Path


ROLE_ROOT = Path(__file__).resolve().parents[1]


def read_role_file(relative_path):
    """Return one UTF-8 role file without relying on the process cwd."""

    return (ROLE_ROOT / relative_path).read_text(encoding="utf-8")
