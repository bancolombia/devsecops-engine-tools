import argparse
import argparse
import configparser
import threading
import queue
import json
from prettytable import PrettyTable, DOUBLE_BORDER
from engine_sast.engine_iac.src.domain.usecases.iac_scan import IacScan
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import CheckovConfig
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.checkov_run import CheckovTool
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    ReleaseVariables,
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


def extract_check_id_checkov(chekov_ouput_json, rules_docs_json: dict, myTable: PrettyTable):
    check_severity_dict = {"High": 0, "Medium": 0, "Low": 0}
    count_rows = 0
    if chekov_ouput_json is not None and "results" in chekov_ouput_json:
        for vuls in chekov_ouput_json["results"]["failed_checks"]:
            check_severity_dict[rules_docs_json[vuls["check_id"]]["severity"]] += 1
            myTable.add_row(
                [
                    rules_docs_json[vuls["check_id"]]["severity"],
                    rules_docs_json[vuls["check_id"]]["checkID"],
                    vuls["resource"],
                    vuls["file_path"],
                ]
            )
            count_rows = +1
    return [check_severity_dict, count_rows]


def print_table(myTable: PrettyTable):
    myTable.align["Severity"] = "l"
    myTable.align["CheckID"] = "l"
    myTable.align["Resource"] = "l"
    myTable.align["guideline"] = "l"
    myTable.set_style(DOUBLE_BORDER)
    print(myTable)


def async_scan(queue, iacScan: IacScan, rules):
    result = []
    output = iacScan.process()
    result.append([json.loads(output), rules])
    queue.put(result)


def init_engine_sast_rm(remote_config_repo, remote_config_path, tool):
    Printers.print_logo_tool()
    azure_devops_integration = AzureDevopsIntegration()
    azure_devops_integration.get_azure_connection()
    data_file_tool = azure_devops_integration.get_remote_json_config(
        remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    )[tool]
    output_queue = queue.Queue()
    # Crea una lista para almacenar los hilos
    threads = []
    for rule in data_file_tool["RULES"]:
        checkov_config = CheckovConfig(
            path_config_file="",
            config_file_name=rule,
            checks=list(data_file_tool["RULES"][rule].keys()),
            soft_fail=False,
            directories=ReleaseVariables.Artifact_Path.value(),
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

    # Imprime los resultados
    myTable = PrettyTable(["Severity", "CheckID", "Resource", "file_path"])
    for i, result in enumerate(results):
        extract_check_id_checkov(result[0], result[1], myTable)
    print_table(myTable)
