# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the conda env spec for requirements.txt files."""

from .. import CondaEnvironmentSpecifier, hookimpl
from ...exceptions import PluginError


@hookimpl
def conda_environment_specifiers():
    from ...env.specs.binstar import BinstarSpec

    def to_environment(source):
        env = BinstarSpec(source)
        if env.can_handle():
            return env.environment
        else:
            raise PluginError("binstar plugin can not be used for source `{source}`.")

    yield CondaEnvironmentSpecifier(
        name="binstar",
        to_environment=to_environment,
    )
