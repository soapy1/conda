# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Register the built-in env_spec hook implementations."""

from . import requirements, yaml_file

#: The list of env_spec plugins for easier registration with pluggy
plugins = [requirements, yaml_file]