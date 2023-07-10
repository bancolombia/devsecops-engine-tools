import argparse

# from engine_sast.engine_iac.src.infrastructure.entry_points.config import remote_config


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--azure_remote_config_repo", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path_exclusions", type=str, required=True, help="")
    parser.add_argument("--azure_remote_config_path_iac", type=str, required=True, help="")
    parser.add_argument("--tool", type=str, required=True, help="")
    parser.add_argument("--environment", type=str, required=True, help="")

    args = parser.parse_args()
    return (
        args.azure_remote_config_repo,
        args.azure_remote_config_path_exclusions,
        args.azure_remote_config_path_iac,
        args.tool,
        args.environment,
    )


# def init_engine_core(remote_config_repo, remote_config_path, tool):
#     result_list = runner_engine_iac() # lista con [[escaneo_docker1,reglas],[escaneo_k8s1,reglas2]]
#     list_exclusiones = exclusions()
#     use_case_break_build(list_vulnerabilities,umbrales)
#     print("init_engine_core")
