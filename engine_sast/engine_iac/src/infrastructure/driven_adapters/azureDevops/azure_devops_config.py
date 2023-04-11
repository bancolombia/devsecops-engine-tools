from devsecops_engine_utilities.azuredevops.infrastructure.AzureDevopsRemoteConfig import (
    AzureDevopsRemoteConfig,
)

from engine_sast.engine_iac.src.domain.model.gateways.remote_config_gateway import RemoteConfigGateway


class AzureDevopsIntegration(RemoteConfigGateway):
    def get_remote_config(self, config_remote: AzureDevopsRemoteConfig):
        self.azure_devops_remote_config = AzureDevopsRemoteConfig(
            api_version=config_remote.api_version, verify_ssl=False
        )
        return self.azure_devops_remote_config.get_source_item(
            api_version=config_remote.api_version,
            verify_ssl=config_remote.verify_ssl,
            organization=config_remote.organization,
            project=config_remote.project,
            repository_id=config_remote.repository_id,
            path_file=config_remote.path_file,
            user=config_remote.user,
            token=config_remote.token,
        )
