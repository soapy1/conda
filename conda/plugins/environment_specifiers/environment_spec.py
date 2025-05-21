from pydantic import BaseModel
import fsspec

from ..types import EnvironmentSpecBase
from ...models.version import VersionOrder


# NOTE: This depends on pydantic. Conda probably shouldn't rely on pydantic
# in this way.
# it would be neat to be able to provide some built in/reusable fields?
class EnvironmentSpecPluginSpecifiers(BaseModel):
    """An model representing the metadata required to specify an environment spec."""

    # name of environment spec plugin to use, required
    name: str

    # version of the environment spec plugin to use
    # does this belong here?
    version: str | None = None


class EnvironmentSpecBaseModel(BaseModel):
    plugin: EnvironmentSpecPluginSpecifiers


class EnvironmentSpec(EnvironmentSpecBase):
    def __init__(self, source, **kwargs):
        self.source = source

    @property
    def name(self):
        raise NotImplementedError
    
    @property
    def version(self):
        raise NotImplementedError
    
    @property
    def version_constraint(self):
        """The supported versions of the plugin, optional"""
        return None
    
    @property
    def model(self):
        raise NotImplementedError

    def read_data(self):
        fs = fsspec.filesystem("file")
        with fs.open(self.source, "rb") as src:
            data = src.read()
        return data
    
    def to_model(self):
        data = self.read_data()
        return self.model.model_validate_json(data)

    def can_handle(self) -> bool:
        # try to read the data into the model
        try:
            data = self.model.model_validate_json(self.read_data())
        except Exception as e:
            return False
        
        # make sure name matches
        if data.plugin.name != self.name:
            return False
        
        # make sure version constraint is satisfied
        if self.version_constraint is not None:
            # if the input does not specify a version, fail
            if data.plugin.version is None:
                return False
            
            # janky way to compare versions that relies
            # on formatting being exactly correct. It only
            # # supports "<" or ">" comparators. Taking
            # this approach for demo purposes. 
            version_comparer = self.version_constraint[0]
            target_version = self.version_constraint[1:]
            
            if version_comparer == ">" and VersionOrder(data.plugin.version) <= VersionOrder(target_version):
                return False
            
            if version_comparer == "<" and  VersionOrder(data.plugin.version) >= VersionOrder(target_version):
                return False

        return True
