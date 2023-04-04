from devsecops_engine_utilities.azuredevops.infrastructure.AzureDevopsRemoteConfig import (
    AzureDevopsRemoteConfig,
)
from engine_sast.engine_iac.src.domain.model.PipelineConfig import PipelineConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_pipeline_config import (
    get_pipeline_config,
)
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.checkov_run import (
    create_config_file,
    run_checkov,
)
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)


ORGANIZATION = "grupobancolombia"
PROJECT = "Vicepresidencia Servicios de Tecnología"
REMOTE_CONFIG_REPO = "NU0429001_DevSecOps_Remote_Config"
REMOTE_CONFIG_PATH = "/SAST/IAC/Rules.json"
USER = ""
TOKEN_AZURE = ""
REMOTE_CONFIG_CHECKOV_VERSION = "CHECKOV_VERSION"
REMOTE_CONFIG_CHECKOV_RULES = "RULES"


pipeline_config = PipelineConfig()
pipeline = get_pipeline_config(pipeline_config=pipeline_config)
azure_devops_remote_config = AzureDevopsRemoteConfig(api_version=7.0, verify_ssl=False)
azure_devops_remote_config.organization = ORGANIZATION
azure_devops_remote_config.project = PROJECT
azure_devops_remote_config.repository_id = REMOTE_CONFIG_REPO
azure_devops_remote_config.path_file = REMOTE_CONFIG_PATH
azure_devops_remote_config.user = USER
azure_devops_remote_config.token = TOKEN_AZURE
data_file = azure_devops_remote_config.get_source_item().json()
checkov_config = CheckovConfig(
    path_config_file="",
    checks=data_file[REMOTE_CONFIG_CHECKOV_RULES],
    soft_fail=False,
    directories=pipeline.default_working_directory,
)
checkov_config.create_config_dict()
create_config_file(checkov_config=checkov_config)
run_checkov(checkov_config=checkov_config)
