# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from .. import CondaInstaller, hookimpl
from ...models.environment import EnvironmentConfig

def uv_install(prefix: str, specs: list[str], *args, **kwargs) -> dict:
    print("pretending to install stuff with uv")
    for spec in specs:
        print(f"  - {spec}")
    return {}


def uv_dry_run(prefix: str, specs: list[str], *args, **kwargs) -> dict:
    print("pretending to (dry-run) install stuff with uv")
    for spec in specs:
        print(f"  - {spec}")
    return {}


@hookimpl
def conda_installers():
    yield CondaInstaller(
        name="pypi_uv",
        types=("uv", "pip", "pypi"),
        install=uv_install,
        dry_run=uv_dry_run,
    )
