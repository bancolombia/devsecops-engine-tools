import json
from azure.devops.connection import Connection
from msrest.authentication import BasicTokenAuthentication
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
)
logger = MyLogger.__call__().get_logger()

class AzureDevopsApi():
    #TODO: Singleton

    def __init__(self,
                 personal_access_token: str,
                 system_team_project_id: str,
                 organization_url: str):

        self.__personal_access_token = personal_access_token
        self.__organization_url = organization_url
        self.__system_team_project_id = system_team_project_id
        self.__connection = self.__get_azure_connection()

    def __get_azure_connection(self) -> Connection:
        try:
            credentials = BasicTokenAuthentication(
                {"access_token": self.__personal_access_token})

            connection = Connection(
                base_url=self.__organization_url,
                creds=credentials)

            return connection
        except Exception as e:
            raise Exception(
                "Error al obtener la conexión de Azure DevOps: " + str(e)
                )

    def get_remote_json_config(self, remote_config_repo, remote_config_path):
        try:
            git_client = self.__connection.clients.get_git_client()
            logger.info(f"paso: {git_client}") 
            raise("paso")
            file_content = git_client.get_item_text(
                repository_id=remote_config_repo,
                path=remote_config_path,
                project=self.__system_team_project_id
            )
            data = json.loads(b"".join(file_content).decode("utf-8"))
            return data
        except Exception as e:
            # Arrojar una excepción personalizada
            logger.error(str(e))
            raise Exception(
                "Error al obtener el archivo de configuración remoto: " + str(e)
                )
