import json
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
)
logger = MyLogger.__call__().get_logger()

class AzureDevopsApi():

    def __init__(self,
                 personal_access_token: str,
                 project_remote_config: str,
                 organization_url: str):

        self.__personal_access_token = personal_access_token
        self.__organization_url = organization_url
        self.__project_remote_config = project_remote_config

    def get_azure_connection(self) -> Connection:
        try:
            credentials = BasicAuthentication(
                username="",
                password=self.__personal_access_token)

            connection = Connection(
                base_url=self.__organization_url,
                creds=credentials)

            return connection
        except Exception as e:
            raise Exception(
                "Error al obtener la conexión de Azure DevOps: " + str(e)
                )

    def get_remote_json_config(self, connection: Connection,
                               repository_id,
                               remote_config_path):
        try:
            git_client = connection.clients.get_git_client()
            file_content = git_client.get_item_text(
                repository_id=repository_id,
                path=remote_config_path,
                project=self.__project_remote_config
            )
            data = json.loads(b"".join(file_content).decode("utf-8"))
            return data
        except Exception as e:
            # Arrojar una excepción personalizada
            logger.error(str(e))
            raise Exception(
                "Error al obtener el archivo de configuración remoto: " + str(e)
                )
