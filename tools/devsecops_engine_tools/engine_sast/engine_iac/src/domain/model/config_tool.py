from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


class ConfigTool:
    def __init__(self, json_data):
        self.search_pattern = json_data["SEARCH_PATTERN"]
        self.ignore_search_pattern = json_data["IGNORE_SEARCH_PATTERN"]
        self.update_service_file_name_cft = json_data["UPDATE_SERVICE_WITH_FILE_NAME_CFT"]
        self.message_info_engine_iac = json_data["MESSAGE_INFO_ENGINE_IAC"]
        self.threshold = Threshold(json_data["THRESHOLD"])
        self.scope_pipeline = ""
        self.scope_service = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
