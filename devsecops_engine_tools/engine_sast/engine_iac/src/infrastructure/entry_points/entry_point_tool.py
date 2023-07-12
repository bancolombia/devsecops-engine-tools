import argparse
import configparser
import threading
import queue
import json
import os
import re
from engine_sast.engine_iac.src.domain.usecases.iac_scan import IacScan
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import CheckovConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.checkov_run import CheckovTool
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import ReleaseVariables
from engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_devops_config import (
    AzureDevopsIntegration,
)
from engine_sast.engine_iac.src.domain.model.ResultScanObject import ResultScanObject
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovDeserializeConfig import (
    CheckovDeserializeConfig,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
    parser.add_argument("--tool", type=str, required=True, help="")
    parser.add_argument("--environment", type=str, required=True, help="")

    args = parser.parse_args()
    return (
        args.azure_remote_config_repo,
        args.azure_remote_config_path,
        args.tool,
        args.environment,
    )


def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_remote_config_repo = config.get("enginesast.engineiac", "azure_remote_config_repo", fallback=None)
    azure_remote_config_path = config.get("enginesast.engineiac", "azure_remote_config_path", fallback=None)
    tool = config.get("enginesast.engineiac", "tool", fallback=None)
    environment = config.get("enginesast.engineiac", "environment", fallback=None)
    return (
        azure_remote_config_repo,
        azure_remote_config_path,
        tool,
        environment,
    )


def async_scan(queue, iacScan: IacScan):
    result = []
    output = iacScan.process()
    result.append(json.loads(output))
    queue.put(result)


def search_folders(search_pattern, ignore_pattern):
    current_directory = os.getcwd()
    patron = "(?i)(?!.*" + "|".join(ignore_pattern) + ").*?(" + "|".join(search_pattern) + ").*"
    folders = [
        carpeta for carpeta in os.listdir(current_directory) if os.path.isdir(os.path.join(current_directory, carpeta))
    ]
    matching_folders = [
        os.path.normpath(os.path.join(current_directory, carpeta)) for carpeta in folders if re.match(patron, carpeta)
    ]
    return matching_folders


def init_engine_sast_rm(remote_config_repo, remote_config_path, tool, environment):
    Printers.print_logo_tool()
    azure_devops_integration = AzureDevopsIntegration()
    azure_devops_integration.get_azure_connection()
    # data_file_tool = azure_devops_integration.get_remote_json_config(
    #     remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    # )
    data_file_tool = json.loads(remote_config)
    data_config = CheckovDeserializeConfig(json_data=data_file_tool, tool=tool, environment=environment)
    # data_config.exclusions = json.loads(azure_devops_integration.get_remote_json_config(
    #     remote_config_repo=remote_config_repo, remote_config_path=data_config.exclusions_path
    # ))
    data_config.scope_pipeline = ReleaseVariables.Release_Definitionname.value()
    data_config.exclusions = json.loads(exclusion)
    if data_config.exclusions.get("All") is not None:
        data_config.exclusions_all = data_config.exclusions.get("All").get(tool)
    if data_config.exclusions.get(data_config.scope_pipeline) is not None:
        data_config.exclusions_scope = data_config.exclusions.get(data_config.scope_pipeline).get(tool)
    folders_to_scan = search_folders(data_config.search_pattern, data_config.ignore_search_pattern)
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

    result_scan_object = ResultScanObject(
        scope_pipeline=data_config.scope_pipeline,
        rules_scan_list=result_scans,
        rules_scaned=data_config.rules_all,
        exclusions_all=data_config.exclusions_all,
        exclusions_scope=data_config.exclusions_scope,
    )
    return result_scan_object
