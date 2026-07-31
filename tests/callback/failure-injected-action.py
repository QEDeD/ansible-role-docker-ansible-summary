# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Harness-only action shadow for a post-commit renderer fault."""

from __future__ import absolute_import, division, print_function

import importlib.util
import os


def _production_action():
    role_root = os.environ["DAS_CALLBACK_FAILURE_PRODUCTION_ROLE_ROOT"]
    source = os.path.join(
        role_root,
        "action_plugins",
        "docker_ansible_summary.py",
    )
    specification = importlib.util.spec_from_file_location(
        "_das_callback_production_action",
        source,
    )
    if specification is None or specification.loader is None:
        raise ImportError("production DAS action plugin is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


_PRODUCTION_ACTION = _production_action()


class ActionModule(_PRODUCTION_ACTION.ActionModule):
    """Run production behavior except for one explicit renderer exception."""

    def _render(self, host, inputs, machine):
        if (
            os.environ.get("DAS_CALLBACK_FAILURE_INJECTION")
            == "render_failed"
        ):
            raise RuntimeError("harness-only renderer fault")
        return super(ActionModule, self)._render(host, inputs, machine)
