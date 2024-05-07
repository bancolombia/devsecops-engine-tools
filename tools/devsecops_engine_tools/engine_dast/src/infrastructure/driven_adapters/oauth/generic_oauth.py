import requests
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.authentication_method import (
    AuthenticationGateway
)

class GenericOauth(AuthenticationGateway):
    def __init__(self, data):
        self.data: dict = data

    def process_data(self):
        client_id = self.data["security_auth"]["client_id"]
        client_secret = self.data["security_auth"]["client_secret"]
        tenant_id = self.data["security_auth"]["tenant_id"]
        username = self.data["security_auth"].get("username")
        password = self.data["security_auth"].get("password")

        config = {
            "client_id": client_id,
            "client_secret": client_secret,
            "tenant_id": tenant_id,
            "username": username,
            "password": password,
        }

        return config

    def get_access_token(self):
        auth_config = self.process_data()

        if auth_config["username"] and auth_config["password"]:
            return self.get_access_token_resource_owner()
        else:
            return self.get_access_token_client_credentials()

    def get_credentials(self):
        pass

    def get_access_token_client_credentials(self):
        """Obtener access token desde microsoft graph."""
        try:
            # Verifica que el diccionario de configuración contenga todas las claves necesarias
            required_keys = ["client_id", "client_secret", "tenant_id"]
            if not all(key in self.config for key in required_keys):
                raise ValueError("Falta una o más claves de configuración.")

            tenant_id = self.config["tenant_id"]
            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "tenant_id": self.config["tenant_id"],
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }

            url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
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

    def get_access_token_resource_owner(self):
        """Obtener access token desde microsoft graph."""
        try:
            # Verifica que el diccionario de configuración contenga todas las claves necesarias
            required_keys = [
                "client_id",
                "client_secret",
                "tenant_id",
                "username",
                "password",
            ]
            if not all(key in self.config for key in required_keys):
                raise ValueError("Falta una o más claves de configuración.")

            tenant_id = self.config["tenant_id"]

            url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
            data = {
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
                "grant_type": "password",
                "scope": "https://graph.microsoft.com/.default",
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
