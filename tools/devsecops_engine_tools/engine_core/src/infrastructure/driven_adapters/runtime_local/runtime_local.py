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


    def get_remote_config(self, repository, path, branch=""):
        remote_config_path = f"{repository}/{path}"

        with open(remote_config_path, 'r', encoding='utf-8') as f:
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
        elif type == "succeeded_with_issues":
            return f"{self.WARNING}{self.ICON_SUCCESS}Succeeded with issues{self.ENDC}"

    def get_source_code_management_uri(self):
        return os.environ.get("DET_SOURCE_CODE_MANAGEMENT_URI")
    
    def get_build_pipeline_execution_url(self):
        return os.environ.get("DET_BUILD_PIPELINE_EXECUTION_URL")

    def get_base_compact_remote_config_url(self, remote_config_repo):
        return f"{os.environ.get('DET_BASE_COMPACT_REMOTE_CONFIG_URL')}?path=/"

    def get_variable(self, variable):
        env_variables = {
            "branch_name" : "DET_BRANCH_NAME",
            "build_id" : "DET_BUILD_ID",
            "build_execution_id" : "DET_BUILD_EXECUTION_ID",
            "commit_hash" : "DET_COMMIT_HASH",
            "environment" : "DET_ENVIRONMENT",
            "release_id" : "DET_RELEASE_ID",
            "branch_tag" : "DET_BRANCH_TAG",
            "access_token" : "DET_ACCESS_TOKEN",
            "organization" : "DET_ORGANIZATION",
            "project_name" : "DET_PROJECT_NAME",
            "repository" : "DET_REPOSITORY",
            "pipeline_name" : "DET_PIPELINE_NAME",
            "stage" : "DET_STAGE",
            "path_directory" : "DET_PATH_DIRECTORY",
            "os" : "DET_OS",
            "temp_directory" : "DET_TEMP_DIRECTORY",
            "target_branch" : "DET_TARGET_BRANCH",
            "source_branch" : "DET_SOURCE_BRANCH",
            "repository_provider" : "DET_REPOSITORY_PROVIDER",
            "vm_product_type_name" : "DET_VM_PRODUCT_TYPE_NAME",
            "vm_product_name" : "DET_VM_PRODUCT_NAME",
            "vm_product_description" : "DET_VM_PRODUCT_DESCRIPTION",
        }
        return os.environ.get(env_variables[variable], None)