from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import BuildVariables

class DeserializeConfigTool:
    def __init__(self, json_data, tool):
        self.version = json_data[tool]["VERSION"]
        self.search_pattern = ""
        self.ignore_search_pattern = json_data[tool]["IGNORE_SEARCH_PATTERN"]
        self.exclusions_path = ""
        self.message_info_sast_rm = json_data[tool]["MESSAGE_INFO_SAST_RM"]
        self.level_compliance = Threshold(json_data[tool]['THRESHOLD'])
        self.rules_data_type = ""
        self.scope_pipeline = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
        self.rules_all = {}
