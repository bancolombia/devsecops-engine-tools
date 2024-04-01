from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold

class DeserializeConfigTool:
    def __init__(self, json_data, tool):
        self.ignore_search_pattern = json_data[tool]["IGNORE_SEARCH_PATTERN"]
        self.message_info_sast_build = json_data[tool]["MESSAGE_INFO_SAST_BUILD"]
        self.level_compliance = Threshold(json_data[tool]['THRESHOLD'])
        self.scope_pipeline = ''
        self.exclude_path = json_data[tool]["EXCLUDE_PATH"]
        self.number_threads = json_data[tool]["NUMBER_THREADS"]
