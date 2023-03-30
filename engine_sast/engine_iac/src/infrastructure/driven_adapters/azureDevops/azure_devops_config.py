from devsecops_engine_utilities.azuredevops.infrastructure.AzureDevopsRemoteConfig import (
    AzureDevopsRemoteConfig,
)


def get_source_azure_item(
    api_version,
    verify_ssl,
    organization,
    project,
    repository_id,
    path_file,
    user,
    token,
):
    azure_devops_remote_config = AzureDevopsRemoteConfig(
        api_version=7.0, verify_ssl=False
    )
    return azure_devops_remote_config.get_source_item(
        api_version=api_version,
        verify_ssl=verify_ssl,
        organization=organization,
        project=project,
        repository_id=repository_id,
        path_file=path_file,
        user=user,
        token=token,
    )
