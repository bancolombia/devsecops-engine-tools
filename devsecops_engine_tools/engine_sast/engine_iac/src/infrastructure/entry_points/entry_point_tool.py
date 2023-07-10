import argparse
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

from engine_sast.engine_iac.src.infrastructure.entry_points.config import remote_config
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_devops_config import (
    AzureDevopsIntegration,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
    parser.add_argument("--tool", type=str, required=True, help="")

    args = parser.parse_args()
    return (
        args.azure_remote_config_repo,
        args.azure_remote_config_path,
        args.tool,
    )


def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_remote_config_repo = config.get("enginesast.engineiac", "azure_remote_config_repo", fallback=None)
    azure_remote_config_path = config.get("enginesast.engineiac", "azure_remote_config_path", fallback=None)
    tool = config.get("enginesast.engineiac", "tool", fallback=None)
    return (
        azure_remote_config_repo,
        azure_remote_config_path,
        tool,
    )


def async_scan(queue, iacScan: IacScan, rules):
    result = []
    output = iacScan.process()
    result.append([json.loads(output), rules])
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


def init_engine_sast_rm(remote_config_repo, remote_config_path, tool):
    Printers.print_logo_tool()
    azure_devops_integration = AzureDevopsIntegration()
    azure_devops_integration.get_azure_connection()
    # data_file_tool = azure_devops_integration.get_remote_json_config(
    #    remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    # )[tool]
    data_file_tool = json.loads(remote_config)[tool]
    folders_to_scan = search_folders(data_file_tool["SEARCH_PATTERN"], data_file_tool["IGNORE_SEARCH_PATTERN"])

    output_queue = queue.Queue()
    # Crea una lista para almacenar los hilos
    threads = []
    for folder in folders_to_scan:
        for rule in data_file_tool["RULES"]:
            checkov_config = CheckovConfig(
                path_config_file="",
                config_file_name=rule,
                checks=list(data_file_tool["RULES"][rule].keys()),
                soft_fail=False,
                directories=folder,
            )
            checkov_config.create_config_dict()
            checkov_run = CheckovTool(checkov_config=checkov_config)
            checkov_run.create_config_file()
            iac_scan = IacScan(checkov_run)
            t = threading.Thread(target=async_scan, args=(output_queue, iac_scan, data_file_tool["RULES"][rule]))
            t.start()
            threads.append(t)
    # Espera a que todos los hilos terminen
    for t in threads:
        t.join()
    # Recopila las salidas de las tareas
    results = []
    while not output_queue.empty():
        result = output_queue.get()
        results.extend(result)
    return result
