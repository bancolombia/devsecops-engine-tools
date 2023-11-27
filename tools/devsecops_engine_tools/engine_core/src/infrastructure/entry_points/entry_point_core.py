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
    parser.add_argument("--tool", type=str, required=True, help="")
    parser.add_argument("--environment", type=str, required=True, help="")
    parser.add_argument("--use_secrets_manager", type=bool, required=True, help="")
    parser.add_argument("--send_to_defectdojo", type=bool, required=False, help="")
    parser.add_argument("--token_cmdb", required=False, help="")
    parser.add_argument("--token_defect_dojo", required=False, help="")

    args = parser.parse_args()
    return {
        "azure_remote_config_repo": args.azure_remote_config_repo,
        "tool": args.tool,
        "environment": args.environment,
        "use_secrets_manager": args.use_secrets_manager,
        "send_to_defectdojo": args.send_to_defectdojo,
        "token_cmdb": args.token_cmdb,
        "token_defect_dojo": args.token_defect_dojo,
    }


def init_engine_core(
    vulnerability_management_gateway: any,
    deserializer_gateway: any,
    secrets_manager_gateway: any,
):
    args = get_inputs_from_cli(sys.argv[1:])
    instance = HandleScan(
        vulnerability_management_gateway,
        deserializer_gateway,
        secrets_manager_gateway,
        dict_args=args,
    )
    vulnerabilities_list, input_core = instance.process()
    BreakBuild(vulnerabilities_list=vulnerabilities_list, input_core=input_core)
