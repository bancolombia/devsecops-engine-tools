import requests
import argparse
import sys


class OauthObject:
    def __init__(self, target_config: dict, data_config_cli: dict):
        self.target_config = target_config
        self.data_config_cli = data_config_cli

    def get_auth_config(self):
        config = {"access_token": self.get_access_token()}
        return config

    def get_access_token(self):
        if self.data_config_cli["username"] and self.data_config_cli["password"]:
            return self.get_access_token_resource_owner()
        else:
            return self.get_access_token_client_credentials()

    def get_access_token_client_credentials(self) -> str:
        """"""
        try:
            # Verifica que el diccionario de configuración contenga todas las claves necesarias
            required_keys = ["client_id", "client_secret", "tenant_id"]
            if not all(key in self.data_config_cli for key in required_keys):
                raise ValueError("Falta una o más claves de configuración para OAUth.")

            tenant_id = self.data_config_cli["tenant_id"]
            data = {
                "client_id": self.data_config_cli["client_id"],
                "client_secret": self.data_config_cli["client_secret"],
                "tenant_id": self.data_config_cli["tenant_id"],
                "grant_type": "client_credentials",
                "scope": self.target_config["security_auth"]["scope"],
            }

            url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.request(
                "POST", url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                access_token = response.json()["access_token"]
                return access_token
            else:
                print(
                    "[graph] No se obtuvo el access "
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            print("[graph] No se obtuvo el access " "token Excepcion: {0}".format(e))

    def get_access_token_resource_owner(self) -> str:
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
            if not all(key in self.data_config_cli for key in required_keys):
                raise ValueError("Falta una o más claves de configuración.")

            tenant_id = self.data_config_cli["tenant_id"]
            url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
            data = {
                "client_id": self.data_config_cli["client_id"],
                "client_secret": self.data_config_cli["client_secret"],
                "grant_type": "password",
                "scope": self.target_config["security_auth"]["scope"],
                "username": self.data_config_cli["username"],
                "password": self.data_config_cli["password"],
            }

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.request(
                "POST", url, headers=headers, data=data, timeout=5
            )
            if 200 <= response.status_code < 300:
                access_token = response.json()["access_token"]
                return access_token
            else:
                print(
                    "[graph] No se obtuvo el access "
                    "token Unknown status "
                    "code {0}: -> {1}".format(response.status_code, response.text)
                )
        except (ConnectionError, ValueError, KeyError) as e:
            print("[graph] No se obtuvo el access " "token Excepcion: {0}".format(e))
