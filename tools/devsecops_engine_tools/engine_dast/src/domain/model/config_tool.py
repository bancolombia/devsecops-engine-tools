from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


class ConfigTool:
    def __init__(self, json_data, tool):
        self.version = json_data[tool].get("VERSION")
        self.exclusions_path = json_data[tool].get("EXCLUSIONS_PATH")
        self.use_external_checks_dir = json_data[tool].get("USE_EXTERNAL_CHECKS_DIR")
        self.external_dir_owner = json_data[tool].get("EXTERNAL_DIR_OWNER")
        self.external_dir_repository = json_data[tool].get("EXTERNAL_DIR_REPOSITORY")
        self.external_asset_name = json_data[tool].get("EXTERNAL_DIR_ASSET_NAME")
        self.message_info_dast = json_data["MESSAGE_INFO_DAST"]
        self.threshold = Threshold(json_data["THRESHOLD"])
        self.scope_pipeline = ""
        self.exclusions = None
        self.exclusions_all = None
        self.exclusions_scope = None
