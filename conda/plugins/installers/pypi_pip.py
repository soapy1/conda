# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl


@hookimpl
def conda_installers():
    from ...env.installers.pip import install

    yield CondaInstaller(
        name="pypi-pip",
        types=("pip", "pypi"),
        install=install,
    )
