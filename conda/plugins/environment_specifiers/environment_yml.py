# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
**EXPERIMENTAL**
Register the conda env spec for environment.yml files.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .. import hookimpl
from ..types import CondaEnvironmentSpecifier

if TYPE_CHECKING:
    from typing import Final


ENVIRONMENT_YAML_PLUGIN_NAME: Final = "environment.yaml"


@hookimpl()
def conda_environment_specifiers():
    from ...env.specs.yaml_file import YamlFileSpec

    yield CondaEnvironmentSpecifier(
        name=ENVIRONMENT_YAML_PLUGIN_NAME,
        environment_spec=YamlFileSpec,
    )
