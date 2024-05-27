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
    GH_AccessToken = "GH.AccessToken"
    GH_DefaultWorkingDirectory = "GH.DefaultWorkingDirectory"
    GH_HostType = "GH.HostType"
    GH_TeamFoundationCollectionUri = "GH.TeamFoundationCollectionUri"
    GH_TeamProject = "GH.TeamProject"
    GH_TargetBranchName = "GH.PullRequest.TargetBranchName"
    GH_SourceBranch = "GH.PullRequest.SourceBranch"


class BuildVariables(BaseEnum):
    GH_Build_BuildId = "GH.Build.BuildId"
    GH_Build_BuildNumber = "GH.Build.BuildNumber"
    GH_Build_DefinitionName = "GH.Build.DefinitionName"
    GH_Build_Repository_Name = "GH.Build.Repository.Name"
    GH_Build_SourceBranch = "GH.Build.SourceBranch"
    GH_Build_SourceBranchName = "GH.Build.SourceBranchName"
    GH_Build_SourceVersion = "GH.Build.SourceVersion"
    GH_Build_Repository_Provider = "GH.Build.Repository.Provider"


class ReleaseVariables(BaseEnum):
    GH_Release_Definitionname = "GH.Release.DefinitionName"
    GH_Release_Releaseid = "GH.Release.ReleaseId"
    GH_Environment = "GH.ENV"


class AgentVariables(BaseEnum):
    GH_Agent_BuildDirectory = "GH.Agent.BuildDirectory"
    GH_Agent_WorkFolder = "GH.Agent.WorkFolder"
    GH_Agent_TempDirectory = "GH.Agent.TempDirectory"
    GH_Agent_OS = "GH.Agent.OS"
