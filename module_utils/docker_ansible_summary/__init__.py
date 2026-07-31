# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure controller-side primitives for Docker Ansible Summary v1."""

from .compare import compare_observations
from .image import project_image_diagnostics, project_image_labels
from .model import ModelError, PresentationCapacityError
from .render import render_report
from .report import build_report_model

__all__ = (
    "ModelError",
    "PresentationCapacityError",
    "build_report_model",
    "compare_observations",
    "project_image_diagnostics",
    "project_image_labels",
    "render_report",
)
