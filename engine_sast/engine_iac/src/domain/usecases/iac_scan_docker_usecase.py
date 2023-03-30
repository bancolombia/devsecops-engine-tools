from devsecops_engine_utilities.azuredevops.infrastructure.AzureDevopsRemoteConfig import (
    AzureDevopsRemoteConfig,
)
from engine_sast.engine_iac.src.domain.model.PipelineConfig import PipelineConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_pipeline_config import (
    get_pipeline_config,
)


ORGANIZATION = "grupobancolombia"
PROJECT = "Vicepresidencia Servicios de Tecnología"
REMOTE_CONFIG_REPO = "NU0429001_DevSecOps_Remote_Config"
REMOTE_CONFIG_PATH = "/SAST/IAC/Rules.json"
USER = "cesospin"
TOKEN_AZURE = ""


pipeline_config = PipelineConfig()
pipeline = get_pipeline_config(pipeline_config=pipeline_config)
print(pipeline.default_working_directory)

test_azure_devops_remote_config = AzureDevopsRemoteConfig(
    api_version=7.0, verify_ssl=False
)
test_azure_devops_remote_config.organization = ORGANIZATION
test_azure_devops_remote_config.project = PROJECT
test_azure_devops_remote_config.repository_id = REMOTE_CONFIG_REPO
test_azure_devops_remote_config.path_file = REMOTE_CONFIG_PATH
test_azure_devops_remote_config.user = USER
test_azure_devops_remote_config.token = TOKEN_AZURE
response = test_azure_devops_remote_config.get_source_item()
print(response.json())
