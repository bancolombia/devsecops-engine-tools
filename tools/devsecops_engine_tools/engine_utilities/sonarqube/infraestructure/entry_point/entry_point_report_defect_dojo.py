import sys
import argparse
from engine_core.src.domain.model.gateway import(
    SecretsManagerGateway
)
from engine_core.src.domain.model.gateway import(
    DevopsPlatformGateway
)
from engine_core.src.domain.model.gateway import(
    VulnerabilityManagementGateway
)
from engine_utilities.sonarqube.helper.repository import(
    set_repository,
    set_environment
)
from engine_utilities.azuredevops.models.AzurePredefinedVariables import(
    BuildVariables
)

def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote_config_repo", type=str, required=True, help="")
    args = parser.parse_args()
    return {
        "remote_config_repo": args.remote_config_repo
    }

# Description: Entry point to report sonarqube defects to Defect Dojo.s
def init_report_defect_dojo(
    secrets_manager_gateway: SecretsManagerGateway,
    devops_platform_gateway: DevopsPlatformGateway,
    vulnerability_management: VulnerabilityManagementGateway
):
    args = get_inputs_from_cli(sys.argv[1:])
    config_tool = devops_platform_gateway.get_remote_config(
        args["remote_config_repo"],
        "/resources/ConfigTool.json")
    secrets = secrets_manager_gateway.get_secret(config_tool)
    token_defect_dojo = secrets['token_defect_dojo']
    token_cmdb= secrets['token_cmdb']
    compact_remote_config_url = devops_platform_gateway.get_base_compact_remote_config_url(args["remote_config_repo"])
    source_code_management_uri = set_repository(BuildVariables.Build_DefinitionName.value(), BuildVariables.Build_Repository_Name.value())
    vulnerability_management.send_report(compact_remote_config_url, source_code_management_uri, 'Development', token_defect_dojo, token_cmdb, config_tool)