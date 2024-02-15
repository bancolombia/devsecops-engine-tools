from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
import json
import os

@dataclass
class RuntimeLocal(DevopsPlatformGateway):

    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
            return f"{self.FAIL}Failed{self.ENDC}"
        elif type == "succeeded":
            return f"{self.OKGREEN}Succeeded{self.ENDC}"

    def get_source_code_management_uri(self):
        return "file:///"

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return f"file:///{remote_config_repo}"
    
    def get_variable(self, variable_name):
        if variable_name == "pipeline":
            return os.environ.get("DET_PIPELINE_NAME")
        elif variable_name == "branch_name":
            return os.environ.get("DET_BRANCH_NAME")
        elif variable_name == "build_id":
            return os.environ.get("DET_BUILD_ID")
        elif variable_name == "build_execution_id":
            return os.environ.get("DET_BUILD_EXECUTION_ID")
        elif variable_name == "commit_hash":
            return os.environ.get("DET_COMMIT_HASH")
        elif variable_name == "environment":
            return os.environ.get("DET_ENVIRONMENT")
        elif variable_name == "release_id":
            return os.environ.get("DET_RELEASE_ID")
        elif variable_name == "branch_tag":
            return os.environ.get("DET_BRANCH_TAG")
        elif variable_name == "access_token":
            return os.environ.get("DET_ACCESS_TOKEN")
