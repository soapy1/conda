# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Detect whether pre-releases should be enabled."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...base.context import context
from ...base.constants import PrereleaseChoice
from .. import hookimpl
from ..types import CondaVirtualPackage

if TYPE_CHECKING:
    from collections.abc import Iterable


@hookimpl
def conda_virtual_packages() -> Iterable[CondaVirtualPackage]:
    if context.prerelease == PrereleaseChoice.DISALLOW:
        return

    yield CondaVirtualPackage(
        name="prerelease",
        version=None,
        build=None,
    )
