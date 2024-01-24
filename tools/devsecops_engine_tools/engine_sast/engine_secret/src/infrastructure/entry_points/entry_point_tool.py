import configparser
import json
import sys

from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import BuildVariables
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.azure.azure_devops import (
    AzureDevops,
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

def engine_secret_scan(remote_config_repo, remote_config_path, tool):
    azure_devops_integration = AzureDevops()
    
    data_file_tool = azure_devops_integration.get_remote_config(
        remote_config_repo=remote_config_repo, remote_config_path=remote_config_path
    )
    data_config = TrufflehogDeserializeConfig(
        json_data=data_file_tool, tool=tool
    )
    data_config.scope_pipeline = BuildVariables.Build_DefinitionName.value()
    
    tool_install = TrufflehogInstall(tool)
    trufflehog_tool = InstallTool(tool_install)
    trufflehog_tool.check_version_tool()
    
    result = []
    classe = TrufflehogRun(tool)
    secret_scan = SecretScan(classe)
    decode_output = secret_scan.process()

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
    sys.stdout.reconfigure(encoding='utf-8')
    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=data_config.level_compliance,
        path_file_results=vulnerabilities_list,
        custom_message_break_build=data_config.message_info_sast_rm,
        scope_pipeline=data_config.scope_pipeline
    )
    
    return vulnerabilities_list, input_core
