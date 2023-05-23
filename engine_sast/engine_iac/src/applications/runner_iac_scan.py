from engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import (
    get_inputs_from_cli,
    get_inputs_from_config_file,
    init_engine_azure,
)


def main():
    try:
        (
            azure_organization,
            azure_project,
            azure_remote_config_repo,
            azure_remote_config_path,
            azure_user,
            azure_token,
            remote_config_checkov_version,
            remote_config_checkov_rules_docker,
            remote_config_checkov_rules_k8s,
        ) = (
            get_inputs_from_config_file() or get_inputs_from_cli()
        )
        init_engine_azure(
            azure_organization=azure_organization,
            azure_project=azure_project,
            azure_remote_config_repo=azure_remote_config_repo,
            azure_remote_config_path=azure_remote_config_path,
            azure_user=azure_user,
            azure_token=azure_token,
            remote_config_checkov_version=remote_config_checkov_version,
            remote_config_checkov_rules_docker=remote_config_checkov_rules_docker,
            remote_config_checkov_rules_k8s=remote_config_checkov_rules_k8s,
        )

    except ValueError as e:
        error_message = str(e)
        print(f"Error: {error_message}")
        # Manejar el error según sea necesario


if __name__ == "__main__":
    main()
