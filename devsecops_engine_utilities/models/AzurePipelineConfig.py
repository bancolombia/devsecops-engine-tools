import os
from devsecops_engine_utilities.models.PredefinedVariables import BuildVariables, SystemVariables

class AzurePipelineConfig:
    """ Info de https://learn.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch 
     Build variables (DevOps Services) https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml """

    def __init__(self, pipeline_name:str = None, default_working_directory:str = None, staging_directory:str= None):
        self.pipeline_name = pipeline_name
        self.default_working_directory = default_working_directory
        self.staging_directory = staging_directory



    def get_pipeline_config(self):
        self.pipeline_name = os.environ[BuildVariables.Build_DefinitionName]   
        self.staging_directory = os.environ[BuildVariables.Build_StagingDirectory]   
        self.default_working_directory  = os.environ[SystemVariables.System_DefaultWorkingDirectory]   
