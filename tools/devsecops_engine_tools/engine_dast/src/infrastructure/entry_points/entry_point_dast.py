#standard libraries
from ast import parse
import sys

#third party libraries
import argparse
import configparser
import json
#local imports
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei import (
    Nuclei,
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_deserializer import (
    NucleiDesealizator,
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters import auth
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.auth.oauth import (
    Oauthauthenticator
    )
from devsecops_engine_tools.engine_dast.src.domain.usecases.nuclei_process import (
    NucleiProcess,
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.url_validator import (
    url_validator,
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.azureDevops.azure_Devops_config import (
    AzureDevopsIntegration
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.entry_points.config_dast.example1 import (
    config_site
    )
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.exclusions import (
    exclusion
    )
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.git.repo_cloner import (
    repo_cloner
    )
from devsecops_engine_utilities.utils.printers import (
    Printers,
    )
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    ReleaseVariables,
    )
from devsecops_engine_utilities.utils.printers import Printers


def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser(
        description="Argumentos requeridos para ejecutar la herrameinta de DAST"
    )
    #OAuth args
    parser.add_argument(
        "-cid",
        "--client_id", 
        required=False, 
        help="CLIENT ID"
    )
    parser.add_argument(
        "-cs", 
        "--client_secret", 
        required=False, 
        help="CLIENT SECRET")
    parser.add_argument(
        "-tid", 
        "--tenant_id", 
        required=False, 
        help="TENANT ID")
    parser.add_argument(
        "-user", 
        "--username", 
        required=False, 
        help="username ambientes bc"
    )
    parser.add_argument(
        "-pss", 
        "--password", 
        required=False, 
        help="password"
    )
    parser.add_argument(
        "-of", 
        "--other_flags", 
        required=False, 
        help="otros flags"
    )
    parser.add_argument(
        "-gt",
        "--git_token",
        required=False,
        help="git token"
    )
    parser.add_argument(
        "-gu",
        "--git_username",
        required=False,
        help="git username"
    )
    parser.add_argument(
        "-rt",
        "--repo_templates",
        required=False,
        help="repo name"
    )
    
    args, unknown_args = parser.parse_known_args()

    config = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "tenant_id": args.tenant_id,
        "username": args.username,
        "password": args.password,
        "git_token": args.git_token,
        "git_username": args.git_username,
        "repo_templates": args.repo_templates
    }

    return config

def init_engine_dast(remote_config_repo=None, remote_config_path=None, environment=None):
    #azure_devops_integration = AzureDevopsIntegration()
    #azure_devops_integration.get_azure_connection()
    #data_file_tool = azure_devops_integration.get_remote_json_config(
    #    remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    #)
    target_config = json.loads(config_site) # config for current Web App or API
    
    data_config_cli = get_inputs_from_cli(sys.argv[1:]) #secrets variables for authentication
    authentication_handler = Oauthauthenticator(target_config=target_config, data_config_cli=data_config_cli)
    auth_config = authentication_handler.get_auth_config() #Auth config for current scan

    repo_templates = repo_cloner(data_config_cli) #repo with templates for current scan
    url = target_config["endpoint"]
    
    if url_validator(url): #url validation
        Printers.print_logo_tool()
        nuclei_handler = Nuclei(target_config, auth_config)

        json_data = nuclei_handler.nuclei(
            url=url, templates=repo_templates)

        nuclei_data = NucleiDesealizator(json_data)
        nuclei_process = NucleiProcess(nuclei_data.scan)
        nuclei_process.get_result_scans()
        vuln_list = nuclei_process.get_list_vulnerabilities()
        nuclei_process.print_table(vuln_list)
