# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
**EXPERIMENTAL**
Register the conda env spec for requirements.txt files.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import ClassVar

from .. import CondaEnvironmentSpecifier, hookimpl
from ...base.context import context
from ...env.specs.requirements import RequirementsSpec
from ...gateways.disk.read import yield_lines
from ...models.environment import Environment
from ...models.match_spec import MatchSpec
from ..types import EnvironmentSpecBase


class RequirementsSpecPlugin(EnvironmentSpecBase):
    extensions: ClassVar[set[str]] = {".txt"}

    def __init__(self, filename):
        self.filename = filename

    def can_handle(self) -> bool:
        """
        Validates that this spec can process the environment definition.
        This checks if:
            * a filename was provided
            * the file has a supported extension

        :return: True if the file can be handled, False otherwise
        """
        # Return early if no filename was provided
        if self.filename is None:
            return False

        # Extract the file extension (e.g., '.txt' or '' if no extension)
        _, file_ext = os.path.splitext(self.filename)

        # Check if the file has a supported extension
        if not any(spec_ext == file_ext for spec_ext in self.extensions):
            self.msg = f"File {self.filename} does not have a supported extension: {', '.join(self.extensions)}"
            return False

        # Ensure this is not an explicit file. Requirements.txt and explicit files
        # may sometimes share file extension.
        dependencies_list = list(yield_lines(self.filename))
        if "@EXPLICIT" in dependencies_list:
            return False

        return True

    @property
    def environment(self) -> Environment:
        """
        Build an environment from the requirements file.

        :return: An Environment object containing the package specifications
        :raises ValueError: If the file cannot be read
        """
        dependencies = []
        with open(self.filename) as reqfile:
            for line in reqfile:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dependencies.append(line)
        return Environment(name=self.name, dependencies=dependencies)



@hookimpl
def conda_environment_specifiers():
    yield CondaEnvironmentSpecifier(
        name="requirements.txt",
        environment_spec=RequirementsSpec,
    )
