from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
import json
import os


@dataclass
class RuntimeLocal(DevopsPlatformGateway):

    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    ICON_FAIL = "\u2718"
    ICON_SUCCESS = "\u2714"


    def get_remote_config(self, repository, path):
        with open(f"{repository}/{path}") as f:
            return json.load(f)

    def message(self, type, message):
        if type == "succeeded":
            return f"{self.OKGREEN}{message}{self.ENDC}"
        elif type == "info":
            return f"{self.BOLD}{message}{self.ENDC}"
        elif type == "warning":
            return f"{self.WARNING}{message}{self.ENDC}"
        elif type == "error":
            return f"{self.FAIL}{message}{self.ENDC}"

    def result_pipeline(self, type):
        if type == "failed":
            return f"{self.FAIL}{self.ICON_FAIL}Failed{self.ENDC}"
        elif type == "succeeded":
            return f"{self.OKGREEN}{self.ICON_SUCCESS}Succeeded{self.ENDC}"

    def get_source_code_management_uri(self):
        return os.environ.get("DET_SOURCE_CODE_MANAGEMENT_URI")

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return os.environ.get("DET_BASE_COMPACT_REMOTE_CONFIG_URL")

    def get_variable(self, variable):
        if variable == "branch_name":
            return os.environ.get("DET_BRANCH_NAME")
        elif variable == "build_id":
            return os.environ.get("DET_BUILD_ID")
        elif variable == "build_execution_id":
            return os.environ.get("DET_BUILD_EXECUTION_ID")
        elif variable == "commit_hash":
            return os.environ.get("DET_COMMIT_HASH")
        elif variable == "environment":
            return os.environ.get("DET_ENVIRONMENT")
        elif variable == "release_id":
            return os.environ.get("DET_RELEASE_ID")
        elif variable == "branch_tag":
            return os.environ.get("DET_BRANCH_TAG")
        elif variable == "access_token":
            return os.environ.get("DET_ACCESS_TOKEN")
        elif variable == "pipeline_name":
            return os.environ.get("DET_PIPELINE_NAME")
        elif variable == "stage":
            return os.environ.get("DET_STAGE")
        elif variable == "path_directory":
            return os.environ.get("DET_PATH_DIRECTORY")
        elif variable == "os":
            return os.environ.get("DET_OS")
        elif variable == "work_folder":
            return os.environ.get("DET_WORK_FOLDER")
        elif variable == "temp_directory":
            return os.environ.get("DET_TEMP_DIRECTORY")
        elif variable == "agent_directory":
            return os.environ.get("DET_AGENT_DIRECTORY")
