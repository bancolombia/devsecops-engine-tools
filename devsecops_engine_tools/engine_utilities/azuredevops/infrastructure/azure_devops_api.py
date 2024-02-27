import json
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError
from urllib.parse import urlsplit, unquote
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities.settings import SETTING_LOGGER

logger = MyLogger.__call__(**SETTING_LOGGER).get_logger()


class AzureDevopsApi:
    def __init__(
        self,
        personal_access_token: str = "",
        project_remote_config: str = "",
        organization_url: str = "",
        compact_remote_config_url: str = "",
        repository_id: str = "",
        remote_config_path: str = "",
    ):
        self.__personal_access_token = personal_access_token
        self.__organization_url = organization_url
        self.__project_remote_config = project_remote_config
        self.__compact_remote_config_url = compact_remote_config_url
        self.__repository_id = repository_id
        self.__remote_config_path = remote_config_path

    def segment_url(self):
        if self.__compact_remote_config_url:
            url_parts = urlsplit(self.__compact_remote_config_url)
            path = unquote(url_parts.path)
            path_parts = path.split("/")
            self.__organization_url = url_parts.scheme + "://" + url_parts.netloc + "/"
            self.__project_remote_config = path_parts[1]
            self.__repository_id = path_parts[3]
            query_parts = url_parts.query.split("=")
            self.__remote_config_path = query_parts[1]

    def get_azure_connection(self) -> Connection:
        self.segment_url()
        try:
            credentials = BasicAuthentication(username="", password=self.__personal_access_token)

            connection = Connection(base_url=self.__organization_url, creds=credentials)

            return connection
        except Exception as e:
            raise ApiError("Error getting Azure DevOps connection: " + str(e))

    def get_remote_json_config(self, connection: Connection):
        try:
            git_client = connection.clients.get_git_client()
            file_content = git_client.get_item_text(
                repository_id=self.__repository_id,
                path=self.__remote_config_path,
                project=self.__project_remote_config,
            )
            data = json.loads(b"".join(file_content).decode("utf-8"))
            return data
        except Exception as e:
            # Arrojar una excepción personalizada
            logger.error(str(e))
            raise ApiError("Error getting remote configuration file: " + str(e))
