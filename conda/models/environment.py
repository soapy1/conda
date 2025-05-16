# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda environment data model"""

from dataclasses import dataclass, field
from typing import Any
from .match_spec import MatchSpec
from .records import PackageRecord
from ..base.context import context


@dataclass
class Environment:
    # Map of other package types that conda can install. For example pypi packages.
    # TODO: not sure if this is an ok way to capture this information
    external_packages: dict[str, list]  | None = None

    # Environment level configuration, eg. channels, solver options, etc.
    environment_config: dict[str, Any] = field(default_factory=dict)

    # Environment name. One name or prefix is required.
    name: str |  None = None

    # Prefix the environment is installed into. One name or prefix is required.
    prefix: str | None = None

    # The platform this environment may be installed on. Defaults to the 
    # current platform.
    platform: str = context.subdir

    # The complete list of specs for the environment.
    # eg. after a solve, or from an explicit environemnt spec
    records: list[PackageRecord] | None = None

    # User requested specs for this environment.
    specs: list[MatchSpec] | None = None

    # Environment variables to be applied to the environment.
    variables: dict[str, str] | None = None
