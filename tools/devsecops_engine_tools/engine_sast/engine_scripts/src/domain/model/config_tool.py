from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


class ConfigTool:
    def __init__(self, json_data):
        self.ignore_search_pattern = json_data["IGNORE_SEARCH_PATTERN"]
        self.update_service_file_name_cft = json_data.get(
            "UPDATE_SERVICE_WITH_FILE_NAME_CFT", False
        )
        self.message_info_engine_scripts = json_data["MESSAGE_INFO_ENGINE_SCRIPTS"]
        self.threshold = Threshold(json_data["THRESHOLD"])
        self.scope_pipeline = ""
        self.scope_service = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
