# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Define requirements.txt spec."""

import os

from ...deprecations import deprecated
from ..env import Environment


class RequirementsSpec:
    """
    Reads dependencies from a requirements.txt file
    and returns an Environment object from it.
    """

    msg = None
    extensions = {".txt"}

    @deprecated.argument("24.7", "26.3", "name")
    def __init__(self, filename=None, name=None, **kwargs):
        self.filename = filename
        self.msg = None


    def can_handle(self):
        for ext in RequirementsSpec.extensions:
            if self.filename.endswith(ext) and os.path.exists(self.filename):
                return True

        return False

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
