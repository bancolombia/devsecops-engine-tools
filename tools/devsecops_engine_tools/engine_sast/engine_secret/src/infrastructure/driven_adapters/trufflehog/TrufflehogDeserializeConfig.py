from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.LevelCompliance import LevelCompliance


class TrufflehogDeserializeConfig:
    def __init__(self, json_data, tool):
        self.version = json_data[tool]["VERSION"]
        self.search_pattern = json_data[tool]["SEARCH_PATTERN"]
        self.ignore_search_pattern = json_data[tool]["IGNORE_SEARCH_PATTERN"]
        self.exclusions_path = ""
        self.message_info_sast_rm = json_data[tool]["MESSAGE_INFO_SAST_RM"]
        self.level_compliance = LevelCompliance(json_data[tool]["LEVEL_COMPLIANCE"])
        self.rules_data_type = ""
        self.scope_pipeline = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
        self.rules_all = {}
