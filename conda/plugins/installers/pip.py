# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the pip installer for conda env files."""

from collections.abc import Iterable

from ...core.path_actions import Action
from .. import hookimpl
from ..types import CondaInstaller


def install(prefix: str, packages: Iterable[str]) -> Iterable[Action]:
    return []


def dry_run(prefix: str, packages: Iterable[str]) -> Iterable[Action]:
    return []


@hookimpl
def conda_installers():
    yield CondaInstaller(
        name="pypi_pip",
        install=install,
        dry_run=dry_run,
    )
