from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

class ConfigTool:
    def __init__(self, json_data, tool, scope):
        self.ignore_search_pattern = json_data["IGNORE_SEARCH_PATTERN"]
        self.message_info_engine_code = json_data["MESSAGE_INFO_ENGINE_CODE"]
        self.threshold = Threshold(json_data["THRESHOLD"])
        self.target_branches = json_data["TARGET_BRANCHES"]
        self.exclude_path = json_data[tool]["EXCLUDE_PATH"]
        self.scope_pipeline = scope
