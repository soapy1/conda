# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda environment data model"""

from ..base.context import context

from dataclasses import dataclass, field
from typing import Any
from .match_spec import MatchSpec
from .records import PackageRecord


@dataclass
class Environment:

    def __init__(
            self, name=None, prefix=None, requirements=None, specs=None, configuration=None, variables=None
        ):
        # TODO: make this configuration/context overwriting less janky
        # The approach is to:
        #   1. let the plugin provide a dict of configuration to the environment
        #   2. the environment can choose how to merge the provided config into the 
        #      context object.
        #   3. store the merged context object as a configuration that can be used
        #      as a source of truth later
        # get the configuration from the context
        context_config = context.to_dict()
        # overwrite global config with incoming configuration
        context_config.update(configuration)

        self.name = name
        self.prefix = prefix
        self.requirements = requirements or []
        self.specs = specs or []
        self.configuration = context_config
        self.variables = variables or {}

    # Environment name. One name or prefix is required.
    name: str |  None = None

    # Prefix the environment is installed into. One name or prefix is required.
    prefix: str | None = None

    # User requested specs for this environment.
    specs: list[MatchSpec] | None = None

    # Map of other package types that conda can install. For example pypi packages.
    # TODO: not sure if this is an ok way to capture this information
    external_packages: dict[str, list]  | None = None

    # The complete list of specs for the environment.
    # eg. after a solve, or from an explicit environemnt spec
    records: list[PackageRecord] | None = None

    # Merged configuration for the environment.
    configuration: dict[str, Any] | None = field(default_factory=dict)

    # Environment variables to be applied to the environment.
    variables: dict[str, str] | None = None
