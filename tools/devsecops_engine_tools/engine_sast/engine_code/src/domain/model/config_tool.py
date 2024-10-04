from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

class ConfigTool:
    def __init__(self, json_data, scope):
        self.data = json_data
        self.exclude_folder = self.data["EXCLUDE_FOLDER"]
        self.ignore_search_pattern = self.data["IGNORE_SEARCH_PATTERN"]
        self.target_branches = self.data["TARGET_BRANCHES"]
        self.message_info_engine_code = self.data["MESSAGE_INFO_ENGINE_CODE"]
        self.threshold = Threshold(self.data["THRESHOLD"])
        self.scope_pipeline = scope