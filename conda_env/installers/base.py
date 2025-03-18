# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""DEPRECATED: Use `conda.installers.base` instead.

Dynamic installer loading.
"""

from conda.deprecations import deprecated
from conda.installers.base import get_installer  # noqa
from conda.exceptions import InvalidInstaller  # noqa

deprecated.module("24.9", "25.3", addendum="Use `conda.installers.base` instead.")

ENTRY_POINT = "conda_env.installers"
