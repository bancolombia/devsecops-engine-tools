from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)

class DeserializeConfigTool:
    def __init__(self, json_data, tool, devops_platform_gateway: DevopsPlatformGateway):
        self.version = json_data[tool]["VERSION"]
        self.ignore_search_pattern = json_data[tool]["IGNORE_SEARCH_PATTERN"]
        self.message_info_sast_build = json_data[tool]["MESSAGE_INFO_SAST_BUILD"]
        self.level_compliance = Threshold(json_data[tool]['THRESHOLD'])
        self.scope_pipeline = devops_platform_gateway.get_variable("BUILD_REPOSITORY_NAME")
