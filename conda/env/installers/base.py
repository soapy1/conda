# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Dynamic installer loading."""

import importlib

from ...base.context import context
from ...exceptions import InvalidInstaller, PluginError


def get_installer(name):
    """
        Gets the installer for the given environment.

    Raises: InvalidInstaller if unable to load installer
    """
    # Return the conda module for conda installers
    if name == "conda":
        return importlib.import_module(f"conda.env.installers.{name}")

    # If not using the conda installer, load the installer from the plugin manager
    try:
        return context.plugin_manager.get_installer(name).installer()
    except PluginError:
        raise InvalidInstaller(name)
