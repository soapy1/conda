# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl
from ...models.environment import EnvironmentConfig

def uv_install(prefix: str, specs: list[str], config: EnvironmentConfig, **kwargs) -> dict:
    print("pretending to install stuff with uv")
    return {}


def uv_dry_run(prefix: str, specs: list[str], config: EnvironmentConfig, **kwargs) -> dict:
    print("pretending to (dry-run) install stuff with uv")
    return {}


@hookimpl
def conda_installers():
    from ...env.installers.pip import dry_run, install

    yield CondaInstaller(
        name="pip",
        types=("pip","pypi"),
        install=install,
        dry_run=dry_run,
    )

    yield CondaInstaller(
        name="uv",
        types=("uv","pypi"),
        install=uv_install,
        dry_run=uv_dry_run,
    )