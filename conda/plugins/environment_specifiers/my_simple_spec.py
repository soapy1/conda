from pydantic import BaseModel

from .. import CondaEnvironmentSpecifier, hookimpl
from ...env.env import Environment

from ...sdk.environment_spec.environment_spec import (
    EnvironmentSpecPluginSpecifiers,
    EnvironmentSpec
)


class MySimpleEnvironment(BaseModel):
    """An model representing a mysimple environment file."""

    # not sure about how this composition should work
    plugin: EnvironmentSpecPluginSpecifiers

    # required
    # using name instead of prefix because of a bug gh-254
    name: str

    # optional
    conda_deps: list[str] = []


class MySimpleSpec(EnvironmentSpec):
    # I'm not totally against the idea of having a plugin author
    # fill in stuff like the plugin name, etc that will inform
    # some built in checks. This implementation, is pretty clucky
    # and I'm sure there is something better.
    name = "mysimplespec"

    model = MySimpleEnvironment
    
    @property
    def environment(self) -> Environment:
        """Returns the Environment representation of the environment spec file"""
        data = MySimpleEnvironment.model_validate_json(self.read_data())

        return Environment(
            name=data.name,
            dependencies=data.conda_deps,
        )


@hookimpl
def conda_environment_specifiers():
    yield CondaEnvironmentSpecifier(
        name=MySimpleSpec.name,
        environment_spec=MySimpleSpec,
    )
