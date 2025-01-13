import os
from enum import Enum
from devsecops_engine_tools.engine_utilities.input_validations.env_utils import EnvVariables


class EnvVariables:
    @staticmethod
    def get_value(env_name):
        env_var = os.environ.get(env_name)
        if env_var is None:
            raise ValueError(f"La variable de entorno {env_name} no está definida")
        return env_var


class BaseEnum(Enum):
    @property
    def env_name(self):
        return self._value_.replace(".", "_").upper()

    def value(self):
        return EnvVariables.get_value(self.env_name)


class SystemVariables(BaseEnum):
    github_access_token = "github.access.token"
    github_workspace = "github.workspace"
    github_job = "github.job"
    github_server_url = "github.server.url"
    github_repository = "github.repository"
    github_event_number = "github.event.number"
    github_event_base_ref = "github.event.base.ref"
    github_ref = "github.ref"


class BuildVariables(BaseEnum):
    github_run_id = "github.run.id"
    github_run_number = "github.run.number"
    github_workflow = "github.workflow"
    github_repository = "github.repository"
    github_ref = "github.ref"
    runner_temp = "runner.temp"
    github_sha = "github.sha"
    GitHub = "GitHub"


class ReleaseVariables(BaseEnum):
    github_workflow = "github.workflow"
    github_env = "github.env"
    github_run_number = "github.run.number"


class AgentVariables(BaseEnum):
    runner_workspace = "runner.workspace"
    github_workspace = "github.workspace"
    runner_os = "runner.os"
    runner_tool_cache = "runner.tool.cache"


class VMVariables(BaseEnum):
    Vm_Product_Type_Name = "Vm.Product.Type.Name"
    Vm_Product_Name = "Vm.Product.Name"
    Vm_Product_Description = "Vm.Product.Description"
