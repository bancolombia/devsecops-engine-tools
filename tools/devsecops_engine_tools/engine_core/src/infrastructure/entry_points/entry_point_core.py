import argparse
import sys

from devsecops_engine_tools.engine_core.src.domain.usecases.break_build import (
    BreakBuild,
)
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan import (
    HandleScan,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path", type=str, required=True, help="")
    parser.add_argument("--tool", type=str, required=True, help="")
    parser.add_argument("--environment", type=str, required=True, help="")
    parser.add_argument("--send_to_defectdojo", type=bool, required=False, help="")
    parser.add_argument("--defect_dojo_mapping_path", type=str, required=False, help="")
    parser.add_argument("--token_cmdb", required=False, help="")
    parser.add_argument("--token_defect_dojo", required=False, help="")

    args = parser.parse_args()
    return {
        "azure_remote_config_repo": args.azure_remote_config_repo,
        "azure_remote_config_path": args.azure_remote_config_path,
        "tool": args.tool,
        "environment": args.environment,
        "send_to_defectdojo": args.send_to_defectdojo,
        "defect_dojo_mapping_path": args.defect_dojo_mapping_path,
        "token_cmdb": args.token_cmdb,
        "token_defect_dojo": args.token_defect_dojo,
    }


def init_engine_core(vulnerability_management_gateway: any, deserializer_gateway: any):
    args = get_inputs_from_cli(sys.argv[1:])
    instance = HandleScan(
        vulnerability_management_gateway, deserializer_gateway, dict_args=args
    )
    vulnerabilities_list, input_core = instance.process()
    BreakBuild(vulnerabilities_list=vulnerabilities_list, input_core=input_core)
