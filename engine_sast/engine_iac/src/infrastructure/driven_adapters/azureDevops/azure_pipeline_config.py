import os
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    BuildVariables,
    SystemVariables,
)


def get_pipeline_config(pipeline_config):
    pipeline_config.pipeline_name = os.environ[
        BuildVariables.Build_DefinitionName.value
    ]
    pipeline_config.staging_directory = os.environ[
        BuildVariables.Build_StagingDirectory.value
    ]
    pipeline_config.default_working_directory = os.environ[
        SystemVariables.System_DefaultWorkingDirectory.value
    ]
    return pipeline_config
