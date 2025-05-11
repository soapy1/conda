# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda environment data model"""

from dataclasses import field
from typing import Any
from .match_spec import MatchSpec
from .records import PackageRecord


class Environment:

    def __init__(
            self, name=None, prefix=None, requirements=None, specs=None, configuration=None, variables=None
        ):
        self.name = name
        self.prefix = prefix
        self.requirements = requirements or []
        self.specs = specs or []
        self.configuration = configuration or {}
        self.variables = variables or {}

    # Environment name. One name or prefix is required.
    name: str |  None = None

    # Prefix the environment is installed into. One name or prefix is required.
    prefix: str | None = None

    # User requested specs for this environment.
    requirements: list[MatchSpec] | None = None

    # The complete list of specs for the environment.
    # eg. after a solve, or from an explicit environemnt spec
    specs: list[PackageRecord] | None = None

    # Merged configuration for the environment.
    configuration: dict[str, Any] | None = field(default_factory=dict)

    # Environment variables to be applied to the environment.
    variables: dict[str, str] | None = None
