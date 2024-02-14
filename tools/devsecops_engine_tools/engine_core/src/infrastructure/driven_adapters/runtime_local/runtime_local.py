from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)

@dataclass
class RuntimeLocal(DevopsPlatformGateway):
    def get_remote_config(self, repository, path):
        base_compact_remote_config_url = f"file:///{path}"
        return base_compact_remote_config_url

    def message(self, type, message):
        return message

    def result_pipeline(self, type):
        return type

    def get_source_code_management_uri(self):
        return "file:///"

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return f"file:///{remote_config_repo}"
    
    def get_variable(self, variable_name):
        return "master"
