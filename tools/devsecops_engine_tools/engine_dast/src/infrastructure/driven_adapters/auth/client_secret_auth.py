import argparse
import requests
import sys


def get_inputs_from_cli_client_credentials(args):
    parser = argparse.ArgumentParser(description="Parse OAUTH ARGS")
    parser.add_argument("-cid", "--client_id", required=True, help="CLIENT ID")
    parser.add_argument("-cs", "--client_secret", required=True, help="CLIENT SECRET")
    parser.add_argument("-tid", "--tenant_id", required=True, help="TENANT ID")
    args = parser.parse_args()
    config = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant_id": args.tenant_id,
    }

    return config


def get_inputs_from_cli_resource_owner(args):
    parser = argparse.ArgumentParser(description="Parse OAUTH ARGS")
    parser.add_argument("-cid", "--client_id", required=True, help="CLIENT ID")
    parser.add_argument("-cs", "--client_secret", required=True, help="CLIENT SECRET")
    parser.add_argument("-tid", "--tenant_id", required=True, help="TENANT ID")
    parser.add_argument(
        "-user", "--username", required=False, help="username ambientes bc"
    )
    parser.add_argument("-pss", "--password", required=False, help="password")

    args = parser.parse_args()
    config = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant_id": args.tenant_id,
        "username": args.username,
        "password": args.password,
    }

    return config


def get_access_token_client_credentials(config):
    """Obtener access token desde microsoft graph."""
    try:
        # Verifica que el diccionario de configuración contenga todas las claves necesarias
        required_keys = ["client_id", "client_secret", "tenant_id"]
        if not all(key in config for key in required_keys):
            raise ValueError("Falta una o más claves de configuración.")

        tenant_id = config["tenant_id"]
        data = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "tenant_id": config["tenant_id"],
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }

        url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = requests.request("POST", url, headers=headers, data=data, timeout=5)
        if 200 <= response.status_code < 300:
            result = response.json()["access_token"]
            return
        else:
            print(
                "[graph] No se obtuvo el access "
                "token Unknown status "
                "code {0}: -> {1}".format(response.status_code, response.text)
            )
    except (ConnectionError, ValueError, KeyError) as e:
        print("[graph] No se obtuvo el access " "token Excepcion: {0}".format(e))


def get_access_token_resource_owner(config):
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
        if not all(key in config for key in required_keys):
            raise ValueError("Falta una o más claves de configuración.")

        tenant_id = config["tenant_id"]

        url = "https://login.microsoftonline.com/" f"{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "grant_type": "password",
            "scope": "https://graph.microsoft.com/.default",
            "username": config["username"],
            "password": config["password"],
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        response = requests.request("POST", url, headers=headers, data=data, timeout=5)
        if 200 <= response.status_code < 300:
            result = response.json()["access_token"]
            return
        else:
            print(
                "[graph] No se obtuvo el access "
                "token Unknown status "
                "code {0}: -> {1}".format(response.status_code, response.text)
            )
    except (ConnectionError, ValueError, KeyError) as e:
        print("[graph] No se obtuvo el access " "token Excepcion: {0}".format(e))


def main():
    config = get_inputs_from_cli_resource_owner(sys.argv[1:])
    get_access_token_client_credentials(config)
    get_access_token_resource_owner(config)


if __name__ == "__main__":
    main()
