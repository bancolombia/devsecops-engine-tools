import subprocess
import json
import platform
import requests
import os
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_deserealizator import (
    KicsDeserealizator
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KicsTool(ToolGateway):
    TOOL_KICS = "KICS"
    scan_type_platform_mapping = {
        "openapi": "OpenAPI",
        "terraform": "Terraform",
        "k8s": "Kubernetes",
        "docker": "Dockerfile",
        "cloudformation": "CloudFormation",
        "ansible": "Ansible",
        "azureresourcemanager": "AzureResourceManager",
        "bicep": "Bicep",
        "buildah": "Buildah",
        "cicd": "CICD",
        "crossplane": "Crossplane",
        "dockercompose": "DockerCompose",
        "grpc": "GRPC",
        "googledeploymentmanager": "GoogleDeploymentManager",
        "knative": "Knative",
        "pulumi": "Pulumi",
        "serverlessfw": "ServerlessFW"
    }

    def download(self, file, url):
        try:
            response = requests.get(url)
            with open(file, "wb") as f:
                f.write(response.content)
        except Exception as ex:
            logger.error(f"An error ocurred downloading {file} {ex}")

    def execute_kics(self, folders_to_scan, prefix, platform_to_scan, work_folder, os_platform, queries):
        folders = ','.join(folders_to_scan)
        queries = ','.join([list(query.values())[0] for query in queries])
        mapped_platforms = [
            self.scan_type_platform_mapping.get(platform.lower(), platform)
            for platform in platform_to_scan
        ]
        platforms = ','.join(mapped_platforms)

        command = [
            prefix,
            "scan",
            "-p",
            folders,
            "-t",
            platforms,
            "--include-queries",
            queries,
            "-q",
            f"{work_folder}\\kics-devsecops\\assets\\queries" if os_platform == "Windows"
            else f"{work_folder}/kics-devsecops/assets/queries",
            "--report-formats",
            "json",
            "-o",
            work_folder
        ]
        try:
            subprocess.run(command, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during KICS execution: {e}")

    def load_results(self, work_folder, queries):
        try:
            results_path = os.path.join(work_folder, "results.json")
            with open(results_path, "r") as f:
                data = json.load(f)

            for finding in data.get("queries", []):
                query_ids = {list(query.values())[0] for query in queries}
                if finding.get("query_id") in query_ids:
                    finding["custom_vuln_id"] = next(
                        key for query in queries for key, value in query.items() if value == finding.get("query_id")
                    )

            with open(results_path, "w") as f:
                json.dump(data, f, indent=4)

            return data
        except Exception as ex:
            logger.error(f"An error occurred loading or modifying KICS results {ex}")
            return None

    def get_assets(self, kics_version, work_folder):
        name_zip = "assets_compressed.zip"
        assets_url = f"https://github.com/Checkmarx/kics/releases/download/v{kics_version}/extracted-info.zip"
        self.download(name_zip, assets_url)

        directory_assets = f"{work_folder}/kics-devsecops"
        utils = Utils()
        utils.unzip_file(name_zip, directory_assets)

    def validate_kics(self, command_prefix):
        try:
            result = subprocess.run([command_prefix, "version"], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            else:
                logger.error(f"KICS binary not valid: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error validating KICS binary: {e}")

    def get_queries(self, config_tool, platform_to_scan):
        try:
            queries = []
            for platform in platform_to_scan:
                platform = platform.strip().upper()
                if f"RULES_{platform}" not in config_tool[self.TOOL_KICS]["RULES"]:
                    logger.error(f"Platform {platform} not found in RULES")
                queries = [{key: value["checkID"]} for key, value in config_tool[self.TOOL_KICS]["RULES"][f"RULES_{platform}"].items()]
            return queries
        except Exception as e:
            logger.error(f"Error writing queries file: {e}")

    def run_tool(
            self, config_tool, folders_to_scan, work_folder, platform_to_scan, **kwargs
    ):
        kics_version = config_tool[self.TOOL_KICS]["CLI_VERSION"]
        path_kics = config_tool[self.TOOL_KICS]["PATH_KICS"]
        download_kics_assets = config_tool[self.TOOL_KICS]["DOWNLOAD_KICS_ASSETS"]
        
        os_platform = platform.system()
        path_kics = path_kics.replace("/", "\\") if os_platform == "Windows" else path_kics
        work_folder = work_folder.replace("/", "\\") if os_platform == "Windows" else work_folder
        
        command_prefix = f"{work_folder}\\{path_kics}.exe" if os_platform == "Windows" else f"{work_folder}/{path_kics}"
        
        if not self.validate_kics(command_prefix):
            logger.info("KICS binary not found or invalid, downloading assets...")

        if download_kics_assets:
            self.get_assets(kics_version, work_folder)

        queries = self.get_queries(config_tool, platform_to_scan)
        self.execute_kics(folders_to_scan, command_prefix, platform_to_scan, work_folder, os_platform, queries)
        data = self.load_results(work_folder, queries)
        
        if data:
            kics_deserealizator = KicsDeserealizator()
            total_vulnerabilities = kics_deserealizator.calculate_total_vulnerabilities(data)
            path_file = os.path.join(work_folder, "results.json")

            if total_vulnerabilities == 0:
                return [], path_file

            filtered_results = kics_deserealizator.get_findings(data)
            finding_list = kics_deserealizator.get_list_finding(filtered_results)

            return finding_list, path_file
        return [], None