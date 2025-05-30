# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Explicit environment implementation for conda."""

from __future__ import annotations

from .env import Environment as EnvironmentYaml
from ..base.context import context
from ..core.prefix_data import PrefixData
from ..core.package_cache_data import PackageCacheData, ProgressiveFetchExtract
from ..models.environment import Environment
from ..models.match_spec import MatchSpec
from ..models.records import PackageRecord


class ExplicitEnvironment(EnvironmentYaml):
    """
    A specialized Environment class for explicit environments.

    This class represents environments created from @EXPLICIT files that should
    bypass the solver according to CEP-23.
    """

    def __init__(
        self,
        name: str = None,
        dependencies: list[str] = None,
        channels: list[str] = None,
        prefix: str = None,
        filename: str = None,
        **kwargs,
    ):
        """
        Initialize an explicit environment.

        Parameters
        ----------
        name : str, optional
            The name of the environment
        dependencies : List[str], optional
            The list of package specifications (URLs in this case)
        channels : List[str], optional
            The list of channels
        prefix : str, optional
            The installation prefix
        filename : str, optional
            The path to the explicit file this environment was created from
        """
        super().__init__(
            name=name,
            dependencies=dependencies,
            channels=channels,
            prefix=prefix,
            **kwargs,
        )
        self.explicit_specs = dependencies or []
        self.explicit_filename = filename
        if prefix is None:
            if name is not None:
                self.prefix = PrefixData.from_name(name).prefix_path
            else:
                self.prefix = context.target_prefix

    def to_environment(self) -> Environment:
        """
        Convert the explicit environment to a core Environment object.
        """
        fetch_specs = [MatchSpec(spec) for spec in self.dependencies.get("conda", [])]
        if context.dry_run:
            return None
        pfe = ProgressiveFetchExtract(fetch_specs)
        pfe.execute()
        explicit_packages = tuple(
            next(PackageCacheData.query_all(spec), None) for spec in fetch_specs
        )
        return Environment(
            prefix=self.prefix,
            platform=context.subdir,
            name=self.name,
            config={"channels": self.channels},
            explicit_packages=explicit_packages,
        )
