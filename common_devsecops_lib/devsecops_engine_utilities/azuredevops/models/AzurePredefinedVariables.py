from enum import Enum
from devsecops_engine_utilities.input_validations.env_utils import EnvVariables

""" Info de https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch
Build variables (DevOps Services) https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml """


class BaseEnum(Enum):
    @property
    def env_name(self):
        return self._value_.replace(".", "_").upper()

    def value(self):
        return EnvVariables.get_value(self.env_name)


class SystemVariables(BaseEnum):
    System_AccessToken = "System.AccessToken"
    System_CollectionId = "System.CollectionId"
    System_DefaultWorkingDirectory = "System.DefaultWorkingDirectory"
    System_StageName = "System.StageName"


class BuildVariables(BaseEnum):
    Build_DefinitionName = "Build.DefinitionName"
    Build_StagingDirectory = "Build.StagingDirectory"
    Build_Repository_Name = "Build.Repository.Name"
    Build_SourceBranch = "Build.SourceBranch"
    Build_SourceBranchName = "Build.SourceBranchName"


class ReleaseVariables(BaseEnum):
    Artifact_Path = "Artifact.Path"
    System_TeamProject = "System.TeamProject"
    System_TeamProjectId = "System.TeamProjectId"
