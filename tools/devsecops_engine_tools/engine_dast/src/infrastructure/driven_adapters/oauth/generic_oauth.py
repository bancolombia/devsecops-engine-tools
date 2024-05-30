import requests
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_method import (
    AuthenticationGateway
)

class GenericOauth(AuthenticationGateway):
    def __init__(self, data):
        self.data: dict = data
        self.config = {}

    def process_data(self):

        self.config = {
            "client_id": self.data["security_auth"]["client_id"],
            "client_secret": self.data["security_auth"]["client_secret"],
            "endpoint": self.data["security_auth"]["endpoint"],
            "username": self.data["security_auth"].get("username"),
            "password": self.data["security_auth"].get("password"),
            "scope": self.data["security_auth"].get("scope")
        }

        return self.config

    def get_access_token(self):
        auth_config = self.process_data()

        if auth_config["username"] and auth_config["password"]:
            return self.get_access_token_resource_owner()
        else:
            return self.get_access_token_client_credentials()

    def get_credentials(self):
        return self.get_access_token()

    def get_access_token_client_credentials(self):
        """Obtain access token using client credentials flow."""
        try:
            required_keys = ["client_id", "client_secret", "tenant_id"]
            if not all(key in self.config for key in required_keys):
                raise ValueError("One or more keys is missing in OAuth config")

            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "tenant_id": self.config["tenant_id"],
                "grant_type": "client_credentials",
                "scope": self.config["scope"],
            }

            url = self.config["endpoint"]
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.request(
                "POST", url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                result = response.json()["access_token"]
                return result
            else:
                print(
                    "Can't obtain access token"
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            print("Can't obtain accesstoken: {0}".format(e))

    def get_access_token_resource_owner(self):
        """Obtain access token using resource owner flow."""
        try:
            required_keys = [
                "client_id",
                "client_secret",
                "tenant_id",
                "username",
                "password"
            ]
            if not all(key in self.config for key in required_keys):
                raise ValueError("Falta una o más claves de configuración.")

            url = self.config["endpoint"]
            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "grant_type": "password",
                "scope": self.config["scope"],
                "username": self.config["username"],
                "password": self.config["password"],
            }

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.request(
                "POST", url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                result = response.json()["access_token"]
                return result
            else:
                print(
                    "[graph] No se obtuvo el access "
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            print("[graph] No se obtuvo el access " "token Excepcion: {0}".format(e))