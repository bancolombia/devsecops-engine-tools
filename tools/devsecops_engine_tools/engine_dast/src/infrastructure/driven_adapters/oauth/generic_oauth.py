import requests
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_gateway import (
    AuthenticationGateway
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class GenericOauth(AuthenticationGateway):
    def __init__(self, data, endpoint):
        self.data: dict = data
        self.endpoint: str = endpoint
        self.config = {}

    def process_data(self):

        self.config = {
            "method": self.data.get("method", "POST"),
            "path": self.data.get("path", ""),
            "grant_type": self.data.get("grant_type",""),
            "scope": self.data.get("scope", None),
            "headers": self.data.get("headers", {}),
            "client_secret": self.data.get("client_secret", ""),
            "client_id": self.data.get("client_id", "")
        }
        return self.config

    def get_access_token(self):
        auth_config = self.process_data()

        if auth_config["grant_type"].lower() == "client_credentials":
            return self.get_access_token_client_credentials()
        else:
            raise ValueError("OAuth: Grant type is not supported yet")

    def get_credentials(self):
        return self.get_access_token()

    def get_access_token_client_credentials(self):
        """Obtain access token using client credentials flow."""
        try:
            required_keys = ["client_id", "client_secret"]
            if not all(key in self.config for key in required_keys):
                raise ValueError("One or more keys is missing in OAuth config")

            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "grant_type": "client_credentials",
                "scope": self.config["scope"]
            }

            if self.config["path"].startswith("http"): url = self.config["path"]
            else: url = self.endpoint + self.config["path"]
            
            headers = self.config["headers"]
            response = requests.request(
                self.config["method"], url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                result = response.json()["access_token"]
                return ("Authorization",f"Bearer {result}")
            else:
                print(
                    "OAuth: Can't obtain access token"
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            logger.warning("OAuth: Can't obtain access token: {0}".format(e))