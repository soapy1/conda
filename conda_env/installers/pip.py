# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""DEPRECATED: Use `conda.installers.pip` instead.

Pip-flavored installer.
"""

from conda.deprecations import deprecated
from conda.installers.pip import _pip_install_via_requirements, install  # noqa

deprecated.module("24.9", "25.3", addendum="Use `conda.installers.pip` instead.")
