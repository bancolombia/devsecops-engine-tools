from enum import Enum

class BuildVariables(Enum):
    
    Build_DefinitionName = 'Build.DefinitionName'.replace('.','_').upper()
    Build_StagingDirectory = 'Build.StagingDirectory'.replace('.','_').upper()
    Build_Repository_Name = 'Build.Repository.Name'.replace('.','_').upper()
    Build_SourceBranch = 'Build.SourceBranch'.replace('.','_').upper()
    Build_SourceBranchName = 'Build.SourceBranchName'.replace('.','_').upper()
 

class SystemVariables(Enum):
    
    System_DefaultWorkingDirectory = 'System.DefaultWorkingDirectory'.replace('.','_').upper()
    System_StageName = 'System.StageName'.replace('.','_').upper()
    


    
