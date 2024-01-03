import argparse
import configparser
import json
import os
import re


from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import BuildVariables
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azureDevops.azure_devops_config import (
    AzureDevopsIntegration,
)
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model import LevelCompliance
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.deserialize_tool import DeserializeTool
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.install_tool import InstallTool
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.usecases.secret_scan import SecretScan
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.TrufflehogDeserealizator import TrufflehogDeserealizator
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.TrufflehogDeserializeConfig import TrufflehogDeserializeConfig
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.TrufflehogInstall import TrufflehogInstall
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.TrufflehogRun import TrufflehogRun


ENGINESAST_ENGINESECRET = "enginesast.enginesecret"

def get_inputs_from_config_file():
    config = configparser.ConfigParser()
    config.read("devsecops_engine.ini", encoding="utf-8")
    azure_remote_config_repo = config.get(
        ENGINESAST_ENGINESECRET, "azure_remote_config_repo", fallback=None
    )
    azure_remote_config_path = config.get(
        ENGINESAST_ENGINESECRET, "azure_remote_config_path", fallback=None
    )
    tool = config.get(ENGINESAST_ENGINESECRET, "tool", fallback=None)
    environment = config.get(ENGINESAST_ENGINESECRET, "environment", fallback=None)
    return (
        azure_remote_config_repo,
        azure_remote_config_path,
        tool,
        environment,
    )


# def secret_scan():
#     result = []
#     output = secret_scan.process()
#     result.append(json.loads(output))


def engine_secret_scan(remote_config_repo, remote_config_path, tool):
    # desde el entrypoint no se llaman driven adapters, estos son llamados desde los gateways 
    # y hacen su magia. Quien llama los driven adapters es el gateway.

    # desde el entry point se llaman los usecases, que son los que llaman a los gateways.
    Printers.print_logo_tool()
    azure_devops_integration = AzureDevopsIntegration()
    azure_devops_integration.get_azure_connection()
    data_file_tool = azure_devops_integration.get_remote_json_config(
        remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    )
    data_config = TrufflehogDeserializeConfig(
        json_data=data_file_tool, tool=tool
    )
    data_config.scope_pipeline = BuildVariables.Build_DefinitionName.value()
    print("CHECKING AND INSTALLING TRUFFLEHOG")
    classe2 = TrufflehogInstall(tool)
    trufflehog_tool = InstallTool(classe2)
    trufflehog_tool.check_version()
    
    print("TRUFFLEHOG INSTALLED")
    result = []
    classe = TrufflehogRun(tool)
    secret_scan = SecretScan(classe)
    exclude_path = secret_scan.create_exclude_file()
    output = secret_scan.process(exclude_path)
    decode_output = output.decode('utf-8')
    
    if decode_output == '':
        vulnerabilities_list = {"SourceMetadata":{"Data":{"Filesystem":{"file":"","line":0}}},"SourceID":0,"SourceType":0,"SourceName":"","DetectorType":0,"DetectorName":"","DecoderName":"","Verified":True,"Raw":"","RawV2":"","Redacted":"","ExtraData":{},"StructuredData":None}
    else:
        object_json = decode_output.strip().split('\n')
        json_list = [json.loads(objeto) for objeto in object_json]
        for json_obj in json_list:
            result.append(json_obj)
        
    trufflehog_deserealizator = TrufflehogDeserealizator()
    deserialize_tool = DeserializeTool(trufflehog_deserealizator)
    vulnerabilities_list = deserialize_tool.get_list_vulnerability(
        result
    )
    
    # for vuln in vulnerabilities_list:
    #     print(vuln)
    
    # file_name = "results.json"
    # with open(file_name, "w") as json_file:
    #             json.dump(result, json_file, indent=4)

    # absolute_path = os.path.abspath(file_name)
        
    input_core = InputCore(
        totalized_exclusions=[],
        level_compliance_defined=data_config.level_compliance,
        path_file_results=vulnerabilities_list,
        custom_message_break_build=data_config.message_info_sast_rm,
        scope_pipeline=data_config.scope_pipeline
    )
    
    return vulnerabilities_list, input_core
    # azure_devops_integration = AzureDevopsIntegration()
    # azure_devops_integration.get_azure_connection()
    # data_file_tool = azure_devops_integration.get_remote_json_config(
    #     remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    # )
    # # data_file_tool = json.loads(remote_config) #-> Esto es para pruebas locales
    # data_config = TrufflehogDeserializeConfig(
    #     json_data=data_file_tool, tool=tool
    # )

    # data_config.scope_pipeline = ReleaseVariables.Release_Definitionname.value()

    # data_config.exclusions = azure_devops_integration.get_remote_json_config(
    #     remote_config_repo=remote_config_repo,
    #     remote_config_path=data_config.exclusions_path,
    # )
    # # data_config.exclusions = json.loads(exclusion) #-> Esto es para pruebas locales
    # if data_config.exclusions.get("All") is not None:
    #     data_config.exclusions_all = data_config.exclusions.get("All").get(tool)
    # if data_config.exclusions.get(data_config.scope_pipeline) is not None:
    #     data_config.exclusions_scope = data_config.exclusions.get(
    #         data_config.scope_pipeline
    #     ).get(tool)

    # result_scan_object = ResultScanObject(
    #     scope_pipeline=data_config.scope_pipeline,
    #     results_scan_list=result_scans,
    #     rules_scaned=data_config.rules_all,
    #     exclusions_all=data_config.exclusions_all,
    #     exclusions_scope=data_config.exclusions_scope,
    #     level_compliance=data_config.level_compliance,
    # )
    # return result_scan_object

    return None
