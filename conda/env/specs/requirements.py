# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Define requirements.txt spec."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import ClassVar

from ...deprecations import deprecated
from ...gateways.disk.read import yield_lines
from ..env import Environment


class RequirementsSpec:
    """
    Reads dependencies from requirements files (including explicit files)
    and returns an Environment object from it.
    """

    msg: str | None = None
    extensions: ClassVar[set[str]] = {".txt"}

    @deprecated.argument("24.7", "26.3", "name")
    def __init__(
        self, filename: str | None = None, name: str | None = None, **kwargs
    ) -> None:
        """Initialize the requirements specification.

        :param filename: Path to the requirements file
        :param name: (Deprecated) Name of the environment
        :param kwargs: Additional arguments
        """
        self.filename = filename
        self._name = name

    @property
    @deprecated("25.9", "26.3", addendum="This attribute is not used anymore.")
    def name(self):
        return self._name

    @name.setter
    @deprecated("25.9", "26.3", addendum="This attribute is not used anymore.")
    def name(self, value):
        self._name = value

    @deprecated("25.9", "26.3", addendum="This method is not used anymore.")
    def _valid_file(self) -> bool:
        """Check if the file exists.

        :return: True if the file exists, False otherwise
        """
        if os.path.exists(self.filename):
            return True
        else:
            self.msg = "There is no requirements.txt"
            return False

    @deprecated("25.9", "26.3", addendum="This method is not used anymore.")
    def _valid_name(self) -> bool:
        """Check if the name is valid.

        :return: True if the name is valid, False otherwise
        """
        if self._name:
            return True
        self.msg = "The environment does not have a name"
        return False

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
    def environment(self):
        dependencies = []
        with open(self.filename) as reqfile:
            for line in reqfile:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dependencies.append(line)
        return Environment(name=self.name, dependencies=dependencies)
