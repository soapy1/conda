# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl


@hookimpl
def conda_installers():
    from ...env.installers.pip import dry_run, install

    yield CondaInstaller(
        name="pip",
        types=("pip",),
        install=install,
        dry_run=dry_run,
    )