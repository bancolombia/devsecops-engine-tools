import configparser
import threading
import platform
import queue
import json
import os
import re
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.usecases.iac_scan import (
    IacScan,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.checkov_run import (
    CheckovTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    ReleaseVariables,
)
from devsecops_engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_utilities.ssh.managment_private_key import (
    create_ssh_private_file,
    add_ssh_private_key,
    decode_base64,
    config_knowns_hosts,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_devops_config import (
    AzureDevopsIntegration,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovDeserializeConfig import (
    CheckovDeserializeConfig,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.config import (
    remote_config,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.exclusions import (
    exclusion,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovDeserealizator import (
    CheckovDeserealizator,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
)

ENGINESAST_ENGINEIAC = "enginesast.engineiac"


def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_remote_config_repo = config.get(
        ENGINESAST_ENGINEIAC, "azure_remote_config_repo", fallback=None
    )
    azure_remote_config_path = config.get(
        ENGINESAST_ENGINEIAC, "azure_remote_config_path", fallback=None
    )
    tool = config.get(ENGINESAST_ENGINEIAC, "tool", fallback=None)
    environment = config.get(ENGINESAST_ENGINEIAC, "environment", fallback=None)
    return (
        azure_remote_config_repo,
        azure_remote_config_path,
        tool,
        environment,
    )


def async_scan(queue, iac_scan: IacScan):
    result = []
    output = iac_scan.process()
    result.append(json.loads(output))
    queue.put(result)


def search_folders(search_pattern, ignore_pattern):
    current_directory = os.getcwd()
    patron = (
        "(?i)(?!.*(?:"
        + "|".join(ignore_pattern)
        + ")).*?("
        + "|".join(search_pattern)
        + ").*$"
    )
    folders = [
        carpeta
        for carpeta in os.listdir(current_directory)
        if os.path.isdir(os.path.join(current_directory, carpeta))
    ]
    matching_folders = [
        os.path.normpath(os.path.join(current_directory, carpeta))
        for carpeta in folders
        if re.match(patron, carpeta)
    ]
    return matching_folders


def init_engine_sast_rm(
    remote_config_repo, remote_config_path, tool, environment, secret_tool
):
    Printers.print_logo_tool()
    azure_devops_integration = AzureDevopsIntegration()
    azure_devops_integration.get_azure_connection()
    data_file_tool = azure_devops_integration.get_remote_json_config(
        remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    )
    # data_file_tool = json.loads(remote_config)  # -> Esto es para pruebas locales
    data_config = CheckovDeserializeConfig(
        json_data=data_file_tool, tool=tool, environment=environment
    )
    data_config.exclusions = azure_devops_integration.get_remote_json_config(
        remote_config_repo=remote_config_repo,
        remote_config_path=data_config.exclusions_path,
    )
    data_config.scope_pipeline = ReleaseVariables.Release_Definitionname.value()
    # data_config.exclusions = json.loads(exclusion)  # -> Esto es para pruebas locales
    if data_config.exclusions.get("All") is not None:
        data_config.exclusions_all = data_config.exclusions.get("All").get(tool)
    if data_config.exclusions.get(data_config.scope_pipeline) is not None:
        data_config.exclusions_scope = data_config.exclusions.get(
            data_config.scope_pipeline
        ).get(tool)
    folders_to_scan = search_folders(
        data_config.search_pattern, data_config.ignore_search_pattern
    )

    # Create configuration external checks
    agent_env = None
    try:
        if data_config.use_external_checks_git == "True" and platform.system() in (
            "Linux",
            "Darwin",
        ):
            config_knowns_hosts(
                data_config.repository_ssh_host, data_config.repository_public_key_fp
            )
            ssh_key_content = decode_base64(secret_tool, "repository_ssh_private_key")
            ssh_key_file_path = "/tmp/ssh_key_file"
            create_ssh_private_file(ssh_key_file_path, ssh_key_content)
            ssh_key_password = decode_base64(secret_tool, "repository_ssh_password")
            agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

        # Create configuration dir external checks
        if data_config.use_external_checks_dir == "True":
            github_api = GithubApi(secret_tool["github_token"])
            github_api.download_latest_release_assets(
                data_config.external_dir_owner,
                data_config.external_dir_repository,
                "/tmp",
            )

    except Exception as ex:
        print(
            AzureMessageLoggingPipeline.WarningLogging.get_message(
                f"An error ocurred configuring external checks {ex}"
            )
        )

    output_queue = queue.Queue()
    # Crea una lista para almacenar los hilos
    threads = []
    for folder in folders_to_scan:
        for rule in data_config.rules_data_type:
            checkov_config = CheckovConfig(
                path_config_file="",
                config_file_name=rule,
                checks=[
                    key
                    for key, value in data_config.rules_data_type[rule].items()
                    if value["environment"].get(environment)
                ],
                soft_fail=False,
                directories=folder,
                external_checks_git=[f"{data_config.external_checks_git}/kubernetes"]
                if data_config.use_external_checks_git == "True"
                and agent_env is not None
                and rule == "RULES_K8S"
                else [],
                env=agent_env,
                external_checks_dir=f"/tmp/{data_config.external_asset_name}"
                if data_config.use_external_checks_dir == "True" and rule == "RULES_K8S"
                else [],
            )
            checkov_config.create_config_dict()
            checkov_run = CheckovTool(checkov_config=checkov_config)
            checkov_run.create_config_file()
            iac_scan = IacScan(checkov_run)
            data_config.rules_all.update(data_config.rules_data_type[rule])
            t = threading.Thread(
                target=async_scan,
                args=(
                    output_queue,
                    iac_scan,
                ),
            )
            t.start()
            threads.append(t)
    # Espera a que todos los hilos terminen
    for t in threads:
        t.join()
    # Recopila las salidas de las tareas
    result_scans = []
    while not output_queue.empty():
        result = output_queue.get()
        result_scans.extend(result)

    checkov_deserealizator = CheckovDeserealizator()
    vulnerabilities_list = checkov_deserealizator.get_list_vulnerability(
        result_scans, data_config.rules_all
    )

    totalized_exclusions = []
    totalized_exclusions.extend(
        map(lambda elem: Exclusions(**elem), data_config.exclusions_all)
    ) if data_config.exclusions_all is not None else None
    totalized_exclusions.extend(
        map(lambda elem: Exclusions(**elem), data_config.exclusions_scope)
    ) if data_config.exclusions_scope is not None else None

    input_core = InputCore(
        totalized_exclusions=totalized_exclusions,
        level_compliance_defined=data_config.level_compliance,
        path_file_results=generate_file_from_tool(
            tool, result_scans, data_config.rules_all
        ),
        custom_message_break_build=data_config.message_info_sast_rm,
        scope_pipeline=data_config.scope_pipeline,
    )
    return vulnerabilities_list, input_core
