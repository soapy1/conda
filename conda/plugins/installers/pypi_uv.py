# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl
from ...models.environment import Environment, EnvironmentConfig

UV_INSTALLABLE_TYPES = (
    "pip",
    "pypi",
    "uv",
)


def uv_install(env: Environment, prune: bool = False, **kwargs) -> dict:
    result = {"install": []}
    # TODO: need to do something here about preferred type for overlapping tools
    for install_type in UV_INSTALLABLE_TYPES:
        install_packages = env.external_packages.get(install_type, None)
        if install_packages:
            print("pretending to install stuff with uv")
            for spec in install_packages:
                print(f"  - {spec}")
            result["install"].extend(install_packages)
    return result


def uv_dry_run(env: Environment, prune: bool = False, **kwargs) -> dict:
    result = {"dry-run": []}
    # TODO: need to do something here about preferred type for overlapping tools
    for install_type in UV_INSTALLABLE_TYPES:
        install_packages = env.external_packages.get(install_type, None)
        if install_packages:
            print("pretending to DRY-install stuff with uv")
            for spec in install_packages:
                print(f"  - {spec}")
            result["dry-run"].extend(install_packages)
    return result


@hookimpl
def conda_installers():
    yield CondaInstaller(
        name="pypi-uv",
        types=UV_INSTALLABLE_TYPES,
        install=uv_install,
        dry_run=uv_dry_run,
    )
