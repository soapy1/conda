# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl


@hookimpl
def conda_installers():
    from ...env.installers.pip import dry_run as pip_dry_run
    from ...env.installers.pip import install as pip_install

    # In this demo, swap the meaning of "pip" and "pypi"
    yield CondaInstaller(
        name="pypi_pip",
        types=("pip","pypi"),
        install=pip_install,
        dry_run=pip_dry_run,
    )
