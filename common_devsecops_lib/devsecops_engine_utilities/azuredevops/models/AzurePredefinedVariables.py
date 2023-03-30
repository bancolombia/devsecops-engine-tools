from enum import Enum

""" Info de https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch
Build variables (DevOps Services) https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml """


class BuildVariables(Enum):
    Build_DefinitionName = "Build.DefinitionName".replace(".", "_").upper()
    Build_StagingDirectory = "Build.StagingDirectory".replace(".", "_").upper()
    Build_Repository_Name = "Build.Repository.Name".replace(".", "_").upper()
    Build_SourceBranch = "Build.SourceBranch".replace(".", "_").upper()
    Build_SourceBranchName = "Build.SourceBranchName".replace(".", "_").upper()


class SystemVariables(Enum):
    System_DefaultWorkingDirectory = "System.DefaultWorkingDirectory".replace(
        ".", "_"
    ).upper()
    System_StageName = "System.StageName".replace(".", "_").upper()
