# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda environment data model"""

from dataclasses import dataclass, field
from logging import getLogger
from typing import Any

from .match_spec import MatchSpec
from ..base.context import context
from ..exceptions import CondaError


log = getLogger(__name__)


@dataclass
class Environment:
    # Map of other package types that conda can install. For example pypi packages.
    # TODO: not sure if this is an ok way to capture this information
    external_packages: dict[str, list]  | None = None

    # Environment level configuration, eg. channels, solver options, etc.
    environment_config: dict[str, Any] = field(default_factory=dict)

    # The complete list of specs for the environment.
    # eg. after a solve, or from an explicit environemnt spec
    explicit_specs: list[MatchSpec] | None = None

    # Environment name. One name or prefix is required.
    name: str |  None = None

    # Prefix the environment is installed into. One name or prefix is required.
    prefix: str | None = None

    # The platform this environment may be installed on. Defaults to the 
    # current platform.
    platform: str = context.subdir

    # User requested specs for this environment.
    requested_specs: list[MatchSpec] | None = None

    # Environment variables to be applied to the environment.
    variables: dict[str, str] | None = None

    @classmethod
    def merge(cls, *environments: Environment, validate: bool = True) -> Environment:
        """
        Keeps first name and/or prefix. Both if their basename match. Otherwise name wins.
        Keeps first description, channel_options, solver_options.
        Keeps max last_modified.
        Concatenates and deduplicates requirements and constraints.
        Reduces configuration and variables (last key wins).
        """
        name = None
        prefix = None
        platform = None
        names = [env.name for env in environments if env.name]
        prefixes = [env.prefix for env in environments if env.prefix]
        platforms = [env.platform for env in environments if env.platform]

        # Ensure that all environments have the same platform
        if len(platforms) == len(set(platforms)):
            platform = platforms[0]
        else:
            # TODO: maybe a better thing to do here?
            raise CondaError("Incompatible platforms")
        
        if names:
            name = names[0]
            if len(names) > 1:
                log.debug("Several names passed %s. Picking first one %s", names, name)
        
        if prefixes:
            prefix = prefixes[0]
            if len(prefixes) > 1:
                log.debug(
                    "Several prefixes passed %s. Picking first one %s", prefixes, prefix
                )
        
        if name and prefix and name != prefix.name and name != "base":
            log.warning("Picked name %s and prefix %s do not match. Overriding prefix")
            prefix = None

        requested_specs = list(
            dict.fromkeys(
                requirement for env in environments for requirement in env.requested_specs
            )
        )

        explicit_specs = list(
            dict.fromkeys(
                requirement for env in environments for requirement in env.explicit_specs
            )
        )

        variables = {k: v for env in environments for (k, v) in env.variables.items()}
        external_packages = {k: v for env in environments for (k, v) in env.external_packages.items()}
        environment_config = {k: v for env in environments for (k, v) in env.environment_config.items()}

        return cls(
            environment_config=environment_config,
            external_packages= external_packages,
            explicit_specs=explicit_specs,
            name=name,
            platform=platform,
            prefix=prefix,
            requested_specs=requested_specs,
            variables=variables,
        )