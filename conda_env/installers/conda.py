# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""DEPRECATED: Use `conda.installers.conda` instead.

Conda-flavored installer.
"""

from conda.deprecations import deprecated
from conda.installers.conda import _solve, dry_run, install  # noqa

deprecated.module("24.9", "25.3", addendum="Use `conda.installers.conda` instead.")
