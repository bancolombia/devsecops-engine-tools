import argparse
import argparse
import configparser
from engine_sast.engine_iac.src.domain.usecases.iac_scan import IacScan
from devsecops_engine_utilities.azuredevops.infrastructure.AzureDevopsRemoteConfig import (
    AzureDevopsRemoteConfig,
)
from engine_sast.engine_iac.src.domain.model.PipelineConfig import PipelineConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_pipeline_config import (
    get_pipeline_config,
)
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import CheckovConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.checkov_run import CheckovTool
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_organization", type=str, required=True, help="")
    parser.add_argument("--azure_project", type=str, help="repositorio")
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
    parser.add_argument("--azure_user", type=str, required=True, help="")
    parser.add_argument("--azure_token_azure", type=str, required=True, help="")
    parser.add_argument("--remote_config_checkov_version", type=str, required=False, help="")
    parser.add_argument("--remote_config_checkov_rules_docker", type=str, required=True, help="")
    parser.add_argument("--remote_config_checkov_rules_k8s", type=str, required=True, help="")
    args = parser.parse_args()
    return (
        args.azure_organization,
        args.azure_project,
        args.azure_remote_config_repo,
        args.azure_remote_config_path,
        args.azure_user,
        args.azure_token_azure,
        args.remote_config_checkov_version,
        args.remote_config_checkov_rules_docker,
        args.remote_config_checkov_rules_k8s,
    )


def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_organization = config.get("enginesast.engineiac", "azure_organization", fallback=None)
    azure_project = config.get("enginesast.engineiac", "azure_project", fallback=None)
    azure_remote_config_repo = config.get("enginesast.engineiac", "azure_remote_config_repo", fallback=None)
    azure_remote_config_path = config.get("enginesast.engineiac", "azure_remote_config_path", fallback=None)
    azure_user = config.get("enginesast.engineiac", "azure_user", fallback=None)
    azure_token = config.get("enginesast.engineiac", "azure_token", fallback=None)
    remote_config_checkov_version = config.get("enginesast.engineiac", "remote_config_checkov_version", fallback=None)
    remote_config_checkov_rules_docker = config.get(
        "enginesast.engineiac", "remote_config_checkov_rules_docker", fallback=None
    )
    remote_config_checkov_rules_k8s = config.get(
        "enginesast.engineiac", "remote_config_checkov_rules_k8s", fallback=None
    )
    return (
        azure_organization,
        azure_project,
        azure_remote_config_repo,
        azure_remote_config_path,
        azure_user,
        azure_token,
        remote_config_checkov_version,
        remote_config_checkov_rules_docker,
        remote_config_checkov_rules_k8s,
    )


def init_engine_azure(
    azure_organization,
    azure_project,
    azure_remote_config_repo,
    azure_remote_config_path,
    azure_user,
    azure_token,
    remote_config_checkov_version,
    remote_config_checkov_rules_docker,
    remote_config_checkov_rules_k8s,
):
    pipeline_config = PipelineConfig()
    pipeline = get_pipeline_config(pipeline_config=pipeline_config)
    azure_devops_remote_config = AzureDevopsRemoteConfig(
        api_version=7.0, verify_ssl=False, organization=azure_organization, project=azure_project
    )
    azure_devops_remote_config.repository_id = azure_remote_config_repo
    azure_devops_remote_config.path_file = azure_remote_config_path
    azure_devops_remote_config.user = azure_user
    azure_devops_remote_config.token = azure_token
    data_file = azure_devops_remote_config.get_source_item()
    data_file = data_file.json()
    checkov_config_docker_scan = CheckovConfig(
        path_config_file="",
        config_file_name=remote_config_checkov_rules_docker,
        checks=data_file[remote_config_checkov_rules_docker],
        soft_fail=False,
        directories=pipeline.default_working_directory,
    )
    checkov_config_docker_scan.create_config_dict()
    checkov_run_docker = CheckovTool(checkov_config=checkov_config_docker_scan)
    checkov_run_docker.create_config_file()
    iac_scan_docker_scan = IacScan(checkov_run_docker)
    iac_scan_docker_scan.process()

    checkov_config_k8s_scan = CheckovConfig(
        path_config_file="",
        config_file_name=remote_config_checkov_rules_k8s,
        checks=data_file[remote_config_checkov_rules_k8s],
        soft_fail=False,
        directories=pipeline.default_working_directory,
    )

    checkov_config_k8s_scan.create_config_dict()
    checkov_run_k8s = CheckovTool(checkov_config=checkov_config_k8s_scan)
    checkov_run_k8s.create_config_file()
    iac_scan_k8s_scan = IacScan(checkov_run_k8s)
    iac_scan_k8s_scan.process()
