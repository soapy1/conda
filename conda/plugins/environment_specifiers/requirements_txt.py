# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the conda env spec for requirements.txt files."""

from .. import CondaEnvironmentSpecifier, hookimpl
from ...exceptions import PluginError


@hookimpl
def conda_environment_specifiers():
    from ...env.specs.requirements import RequirementsSpec

    def to_environment(source):
        env = RequirementsSpec(source)
        if env.can_handle():
            return env.environment
        else:
            raise PluginError("requirements.txt plugin can not be used for source `{source}`.")


    yield CondaEnvironmentSpecifier(
        name="requirements.txt",
        to_environment=to_environment,
    )
