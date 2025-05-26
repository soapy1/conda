# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the conda env spec for environment.yml files."""

from .. import CondaEnvironmentSpecifier, hookimpl
from ...exceptions import PluginError


@hookimpl
def conda_environment_specifiers():
    from ...env.specs.yaml_file import YamlFileSpec

    def to_environment(source):
        env = YamlFileSpec(source)
        if env.can_handle():
            return env.environment
        else:
            raise PluginError("environment.yaml plugin can not be used for source `{source}`.")


    yield CondaEnvironmentSpecifier(
        name="environment.yml",
        to_environment=to_environment,
    )
