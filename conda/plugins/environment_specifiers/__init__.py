# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the built-in environment specifier hook implementations."""

from . import binstar, environment_yml, requirements_txt, my_simple_spec

#: The list of environment speficier plugins for easier registration with pluggy
plugins = [binstar, requirements_txt, environment_yml, my_simple_spec]
