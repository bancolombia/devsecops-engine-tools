# STD libraries

# 3RD party libraries
import argparse

# local imports
from devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan import (
    DastScan,
)


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser(
        description="Argumentos requeridos para ejecutar la herrameinta de DAST"
    )
    # OAuth args
    parser.add_argument("-cid", "--client_id", required=False, help="CLIENT ID")
    parser.add_argument("-cs", "--client_secret", required=False, help="CLIENT SECRET")
    parser.add_argument("-tid", "--tenant_id", required=False, help="TENANT ID")
    parser.add_argument(
        "-user", "--username", required=False, help="username ambientes bc"
    )
    parser.add_argument("-pss", "--password", required=False, help="password")
    parser.add_argument("-of", "--other_flags", required=False, help="otros flags")
    parser.add_argument("-gt", "--git_token", required=False, help="git token")
    parser.add_argument("-gu", "--git_username", required=False, help="git username")
    parser.add_argument("-rt", "--repo_templates", required=False, help="repo name")

    args, unknown_args = parser.parse_known_args()

    config = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant_id": args.tenant_id,
        "username": args.username,
        "password": args.password,
        "git_token": args.git_token,
        "git_username": args.git_username,
        "repo_templates": args.repo_templates,
    }

    return config


def init_engine_dast(devops_platform_gateway, tool_gateway, dict_args, secret_tool):
    dast_scan = DastScan(tool_gateway, devops_platform_gateway)
    return dast_scan.process(dict_args, secret_tool)
