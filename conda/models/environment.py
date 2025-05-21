# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda environment data model"""

from dataclasses import dataclass, field
from logging import getLogger
from typing import Any

from .match_spec import MatchSpec
from ..base.context import context
from ..exceptions import (
    CondaError,
    CondaValueError,
    NeedsNameOrPrefix,
)


log = getLogger(__name__)


@dataclass
class Environment:
    # Environment level configuration, eg. channels, solver options, etc.
    config: dict[str, Any] = field(default_factory=dict)

    # Map of other package types that conda can install. For example pypi packages.
    # TODO: not sure if this is an ok way to capture this information
    external_packages: dict[str, list]  = field(default_factory=dict)

    # The complete list of specs for the environment.
    # eg. after a solve, or from an explicit environemnt spec
    explicit_specs: list[MatchSpec] = field(default_factory=list)

    # Environment name. One name or prefix is required.
    name: str |  None = None

    # Prefix the environment is installed into. One name or prefix is required.
    prefix: str | None = None

    # The platform this environment may be installed on. Defaults to the 
    # current platform.
    platform: str = context.subdir

    # TODO: find a better name
    # User requested specs for this environment.
    requested_specs: list[MatchSpec] = field(default_factory=list)

    # Environment variables to be applied to the environment.
    variables: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        # an environment must have a name of prefix
        if not self.name and not self.prefix:
            raise NeedsNameOrPrefix("'Environment' needs either 'name' or 'prefix'.")

        # an environment must not mix explicit_specs and requested_specs types
        if len(self.explicit_specs) > 0 and len(self.requested_specs) > 0:
            raise CondaValueError(
                "cannot mix specifications with conda package filenames"
            )
    
    @classmethod
    def merge(cls, *environments):
        """
        Keeps first name and/or prefix. Both if their basename match. Otherwise name wins.
        Concatenates and deduplicates requirements.
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
        
        # TODO: fix this check
        if name and prefix and not prefix.endswith(name) and name != "base":
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
        config = {k: v for env in environments for (k, v) in env.config.items()}

        return cls(
            config=config,
            external_packages= external_packages,
            explicit_specs=explicit_specs,
            name=name,
            platform=platform,
            prefix=prefix,
            requested_specs=requested_specs,
            variables=variables,
        )