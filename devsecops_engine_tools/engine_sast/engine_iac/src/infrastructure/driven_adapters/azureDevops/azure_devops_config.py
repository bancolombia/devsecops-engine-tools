import json
from azure.devops.connection import Connection
from msrest.authentication import BasicTokenAuthentication
from engine_sast.engine_iac.src.domain.model.gateways.remote_config_gateway import RemoteConfigGateway
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
)


class AzureDevopsIntegration(RemoteConfigGateway):
    def get_azure_connection(self):
        try:
            system_AccessToken = SystemVariables.System_AccessToken.value()
            system_TeamFoundationCollectionUri = SystemVariables.System_TeamFoundationCollectionUri.value()
            credentials = BasicTokenAuthentication(
                {"access_token": system_AccessToken})
            self.connection = Connection(
                base_url=system_TeamFoundationCollectionUri,
                creds=credentials)
            return self.connection
        except Exception as e:
            raise Exception(
                "Error al obtener la conexión de Azure DevOps: " + str(e))

    def get_remote_json_config(self, remote_config_repo, remote_config_path):
        try:
            git_client = self.connection.clients.get_git_client()
            system_TeamProjectId = SystemVariables.System_TeamProjectId.value()
            file_content = git_client.get_item_text(
                repository_id=remote_config_repo, path=remote_config_path, project=system_TeamProjectId
            )
            data = json.loads(b"".join(file_content).decode("utf-8"))
            return data
        except Exception as e:
            # Arrojar una excepción personalizada
            raise Exception(
                "Error al obtener el archivo de configuración remoto: " + str(e))
