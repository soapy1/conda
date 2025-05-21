from .. import CondaEnvironmentSpecifier, hookimpl
from ...env.env import Environment
from .environment_spec import (
    EnvironmentSpec,
    EnvironmentSpecBaseModel
)


class MyEnvModel(EnvironmentSpecBaseModel):
    # name of the conda environment, required
    # using name instead of prefix because of a bug gh-254
    name: str

    # conda package to install, optional
    conda_deps: list[str] = []


class MyEnv(EnvironmentSpec):
    name = "myenv"
    version = "1.0.0"
    version_constraint = ">1.0.0"

    model = MyEnvModel

    @property
    def environment(self) -> Environment:
        data = self.to_model()
        return Environment(
            name=data.name,
            dependencies=data.conda_deps,
        )


@hookimpl
def conda_environment_specifiers():
    yield CondaEnvironmentSpecifier(
        name="myenv",
        environment_spec=MyEnv,
    )
