from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.LevelCompliance import LevelCompliance


class CheckovDeserializeConfig:
    def __init__(self, json_data, tool, environment):
        self.version = json_data[tool]["VERSION"]
        self.search_pattern = json_data[tool]["SEARCH_PATTERN"]
        self.ignore_search_pattern = json_data[tool]["IGNORE_SEARCH_PATTERN"]
        self.exclusions_path = json_data[tool]["EXCLUSIONS_PATH"]
        self.level_compliance = LevelCompliance(json_data[tool]["LEVEL_COMPLIANCE"][environment])
        self.rules_data_type = json_data[tool]["RULES"]
        self.scope_pipeline = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
        self.rules_all = {}
