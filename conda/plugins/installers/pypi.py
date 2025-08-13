# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, CondaSetting, hookimpl
from ...models.environment import EnvironmentConfig
from ...common.configuration import PrimitiveParameter

def uv_install(prefix: str, specs: list[str], config: EnvironmentConfig, **kwargs) -> dict:
    print("pretending to install stuff with uv")
    for spec in specs:
        print(f"  - {spec}")
    return {}


def uv_dry_run(prefix: str, specs: list[str], config: EnvironmentConfig, **kwargs) -> dict:
    print("pretending to (dry-run) install stuff with uv")
    for spec in specs:
        print(f"  - {spec}")
    return {}


@hookimpl
def conda_installers():
    from ...env.installers.pip import dry_run as pip_dry_run
    from ...env.installers.pip import install as pip_install

    # In this demo, swap the meaning of "pip" and "pypi"
    yield CondaInstaller(
        name="pypi",
        types=("pip","pypi"),
        install=pip_install,
        dry_run=pip_dry_run,
    )

    yield CondaInstaller(
        name="uv",
        types=("uv", "pip"),
        install=uv_install,
        dry_run=uv_dry_run,
    )
