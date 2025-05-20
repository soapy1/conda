from pydantic import BaseModel
import os
import fsspec

from ...common.path import expand
from ...plugins.types import EnvironmentSpecBase


# it would be neat to be able to provide some built in/reusable fields?
class EnvironmentSpecPluginSpecifiers(BaseModel):
    """An model representing the metadata required to specify an environment spec."""

    # name of environment spec plugin to use, required
    name: str

    # version of the environment spec plugin to use
    # does this belong here?
    version: str | None = None


class EnvironmentSpec(EnvironmentSpecBase):
    def __init__(self, source):
        self.source = expand(source)

    def read_data(self):
        fs = fsspec.filesystem("file")
        with fs.open(self.source, "rb") as src:
            data = src.read()
        return data

    def is_file_supported(self) -> bool:
        """
        Validates loader can process environment definition.
        This can handle if:
                * the file exists
                * the file can be read
                * the file has the correct plugin name and version

        :return: True if the file can be parsed and handled, False otherwise
        """
        if not os.path.exists(self.source):
            return False
        try:
            data = self.read_data()
            plugin_specifier = self.model.model_validate_json(data)
            # TODO: this requires the EnvironmentSpecPluginSpecifiers to always 
            # be avilable at the "plugin" field :x
            if plugin_specifier.plugin.name != self.name:
                return False
            # TODO: check version constraint?
        except Exception:
            return False

        return True
