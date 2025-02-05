import os
from enum import Enum
from devsecops_engine_tools.engine_utilities.input_validations.env_utils import EnvVariables

""" Info de https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch
Build variables (DevOps Services) https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml """


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
    System_AccessToken = "System.AccessToken"
    System_CollectionId = "System.CollectionId"
    System_DefaultWorkingDirectory = "System.DefaultWorkingDirectory"
    System_StageName = "System.StageName"
    System_HostType = "System.HostType"
    System_TeamFoundationCollectionUri = "System.TeamFoundationCollectionUri"
    System_TeamProject = "System.TeamProject"
    System_TeamProjectId = "System.TeamProject"
    System_PullRequestId = "System.PullRequest.PullRequestId"
    System_TargetBranchName = "System.PullRequest.TargetBranchName"
    System_SourceBranch = "System.PullRequest.SourceBranch"


class BuildVariables(BaseEnum):
    Build_BuildId = "Build.BuildId"
    Build_BuildNumber = "Build.BuildNumber"
    Build_DefinitionName = "Build.DefinitionName"
    Build_Project_Name = "Build.ProjectName"
    Build_Repository_Name = "Build.Repository.Name"
    Build_SourceBranch = "Build.SourceBranch"
    Build_SourceBranchName = "Build.SourceBranchName"
    Build_StagingDirectory = "Build.StagingDirectory"
    Build_SourceVersion = "Build.SourceVersion"
    Build_Repository_Provider = "Build.Repository.Provider"


class ReleaseVariables(BaseEnum):
    Release_Definitionname = "Release.DefinitionName"
    Release_Releaseid = "Release.ReleaseId"
    Artifact_Path = "ARTIFACT_PATH"
    Environment = "ENV"


class AgentVariables(BaseEnum):
    Agent_BuildDirectory = "Agent.BuildDirectory"
    Agent_WorkFolder = "Agent.WorkFolder"
    Agent_TempDirectory = "Agent.TempDirectory"
    Agent_OS = "Agent.OS"

class VMVariables(BaseEnum):
    Vm_Product_Type_Name = "Vm.Product.Type.Name"
    Vm_Product_Name = "Vm.Product.Name"
    Vm_Product_Description = "Vm.Product.Description"
