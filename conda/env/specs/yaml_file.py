# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Define YAML spec."""

import os
import re

from ruamel.yaml.error import YAMLError

from ...base.context import context
from ...common.serialize import yaml_safe_load
from ...exceptions import EnvironmentFileEmpty, EnvironmentFileNotFound
from ...gateways.connection.download import download_text
from ...gateways.connection.session import CONDA_SESSION_SCHEMES
from ...models.environment import Environment
from ...models.match_spec import MatchSpec
from ...plugins.types import EnvironmentSpecBase


VALID_KEYS = ("name", "dependencies", "prefix", "channels", "variables")


def _expand_channels(data):
    """Expands ``Environment`` variables for the channels found in the ``yaml`` data"""
    data["channels"] = [
        os.path.expandvars(channel) for channel in data.get("channels", [])
    ]


class YamlFileSpec(EnvironmentSpecBase):
    _environment = None
    extensions = {".yaml", ".yml"}

    def __init__(self, filename=None, **kwargs):
        self.filename = filename
        self.msg = None

    def _validate_keys(self, data):
        """Check for unknown keys, remove them and print a warning"""
        invalid_keys = []
        new_data = data.copy() if data else {}
        for key in data.keys():
            if key not in VALID_KEYS:
                invalid_keys.append(key)
                new_data.pop(key)

        if invalid_keys:
            verb = "are" if len(invalid_keys) != 1 else "is"
            plural = "s" if len(invalid_keys) != 1 else ""
            print(
                f"\nEnvironmentSectionNotValid: The following section{plural} on "
                f"'{self.filename}' {verb} invalid and will be ignored:"
            )
            for key in invalid_keys:
                print(f" - {key}")
            print()

        deps = data.get("dependencies", [])
        depsplit = re.compile(r"[<>~\s=]")
        is_pip = lambda dep: "pip" in depsplit.split(dep)[0].split("::")
        lists_pip = any(is_pip(dep) for dep in deps if not isinstance(dep, dict))
        for dep in deps:
            if isinstance(dep, dict) and "pip" in dep and not lists_pip:
                print(
                    "Warning: you have pip-installed dependencies in your environment file, "
                    "but you do not list pip itself as one of your conda dependencies.  Conda "
                    "may not use the correct pip to install your packages, and they may end up "
                    "in the wrong place.  Please add an explicit pip dependency.  I'm adding one"
                    " for you, but still nagging you."
                )
                new_data["dependencies"].insert(0, "pip")
                break
        return new_data

    def _load_environment(self):
        """Load environment from file."""
        url_scheme = self.filename.split("://", 1)[0]

        if url_scheme in CONDA_SESSION_SCHEMES:
            yamlstr = download_text(self.filename)
        elif not os.path.exists(self.filename):
            raise EnvironmentFileNotFound(self.filename)
        else:
            with open(self.filename, "rb") as fp:
                yamlb = fp.read()
                try:
                    yamlstr = yamlb.decode("utf-8")
                except UnicodeDecodeError:
                    yamlstr = yamlb.decode("utf-16")
        
        data = yaml_safe_load(yamlstr)
        if data is None:
            raise EnvironmentFileEmpty(self.filename)
        data = self._validate_keys(data)
        _expand_channels(data)

        env_config = {}
        if data.get("channels", None) is not None:
            env_config["channels"] = data.get("channels")

        deps = data.get("dependencies", {})
        env = Environment(
            name=data.get("name"),
            prefix=data.get("prefix"),
            variables=data.get("variables"),
            environment_config=env_config,
        )

        specs = []
        external_packages = {}
        for dep in deps:
            if isinstance(dep, dict):
                external_packages.update(dep)
            elif isinstance(dep, str):
                specs.append(MatchSpec(dep))

        env.specs = specs
        env.external_packages = external_packages
        return env
        
    def can_handle(self):
        """
        Validates loader can process environment definition.
        This can handle if:
            * the provided file exists
            * the provided file ends in the supported file extensions (.yaml or .yml)
            * the env file can be interpreted and transformed into
              a `conda.env.env.Environment`

        :return: True or False
        """
        # Extract the file extension (e.g., '.txt' or '' if no extension)
        _, file_ext = os.path.splitext(self.filename)

        # Check if the file has a supported extension and exists
        if not any(spec_ext == file_ext for spec_ext in YamlFileSpec.extensions):
            return False

        try:
            self._environment = self._load_environment()
            return True
        except EnvironmentFileNotFound as e:
            self.msg = str(e)
            return False
        except EnvironmentFileEmpty as e:
            self.msg = e.message
            return False
        except (TypeError, YAMLError):
            self.msg = f"{self.filename} is not a valid yaml file."
            return False

    @property
    def environment(self):
        if not self._environment:
            self.can_handle()
        return self._environment
