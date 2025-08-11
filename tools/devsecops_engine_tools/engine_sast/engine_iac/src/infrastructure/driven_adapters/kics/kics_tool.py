import subprocess
import json
import platform
import requests
import os
import shutil
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.context_iac import ContextIac
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_deserealizator import (
    KicsDeserealizator,
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
        "serverlessfw": "ServerlessFW",
    }

    def run_tool(
        self, config_tool, folders_to_scan, work_folder, platform_to_scan, **kwargs
    ):
        kics_version = config_tool[self.TOOL_KICS]["CLI_VERSION"]
        path_kics = config_tool[self.TOOL_KICS]["PATH_KICS"]
        download_kics_assets = config_tool[self.TOOL_KICS]["DOWNLOAD_KICS_ASSETS"]
        exclude_paths = config_tool[self.TOOL_KICS]["EXCLUDE_PATHS"]

        os_platform = platform.system()
        path_kics = (
            path_kics.replace("/", "\\") if os_platform == "Windows" else path_kics
        )
        work_folder = (
            work_folder.replace("/", "\\") if os_platform == "Windows" else work_folder
        )
        command_prefix = (
            f"{work_folder}\\{path_kics}.exe"
            if os_platform == "Windows"
            else f"{work_folder}/{path_kics}"
        )
        valid, command_prefix = self._validate_kics(command_prefix)
        if not valid:
                return [], None

        if download_kics_assets:
            self._get_assets(kics_version, work_folder)

        queries = self._get_queries(config_tool, platform_to_scan)
        self._execute_kics(
            folders_to_scan,
            command_prefix,
            platform_to_scan,
            work_folder,
            os_platform,
            queries,
            exclude_paths,
        )
        data = self._load_results(work_folder, queries)

        if data:
            kics_deserealizator = KicsDeserealizator()
            total_vulnerabilities = kics_deserealizator.calculate_total_vulnerabilities(
                data
            )
            path_file = os.path.join(work_folder, "results.json")

            if total_vulnerabilities == 0:
                return [], path_file

            filtered_results = kics_deserealizator.get_findings(data)
            finding_list = kics_deserealizator.get_list_finding(filtered_results)

            return finding_list, path_file
        return [], None

    def get_iac_context_from_results(self, path_file_results):
        with open(path_file_results, "r") as file:
            context_results_scan_list = json.load(file)
            context_iac_list = []
            
            for query in context_results_scan_list.get("queries", []):
                for file in query.get("files", []):
                    context_iac = ContextIac(
                        id = file.get("similarity_id", ""),
                        check_name = query.get("query_name", ""),
                        check_class = query.get("category", ""),
                        severity = query.get("severity", ""),
                        where = f"{file.get("file_name", "")} (line {file.get("line", "")}): expected value: {file.get("expected_value", "")}, actual value: {file.get("actual_value", "")}",
                        resource = file.get("issue_type", "unknown"),
                        description = query.get("description", ""),
                        module="engine_iac",
                        tool="Kics",
                    )
                    context_iac_list.append(context_iac)

            print("===== BEGIN CONTEXT OUTPUT =====")
            print(
                json.dumps(
                    {"iac_context": [obj.__dict__ for obj in context_iac_list]},
                    indent=4,
                )
            )
            print("===== END CONTEXT OUTPUT =====")

    def _validate_kics(self, command_prefix):
        try:
            kics_in_path = shutil.which("kics.exe" if platform.system() == "Windows" else "kics")
            if kics_in_path:
                command_prefix = kics_in_path
                return True, command_prefix
            else:
                result = subprocess.run(
                    [command_prefix, "version"], capture_output=True, text=True
                )
                if result.returncode == 0:
                    return True, command_prefix
                else:
                    logger.error(f"KICS binary not valid: {result.stderr}")
                    return False, ""
        except Exception as e:
            logger.error(f"Error validating KICS binary: {e}")

    def _get_assets(self, kics_version, work_folder):
        name_zip = "assets_compressed.zip"
        assets_url = f"https://github.com/Checkmarx/kics/releases/download/v{kics_version}/extracted-info.zip"
        self._download(name_zip, assets_url)

        directory_assets = f"{work_folder}/kics-devsecops"
        utils = Utils()
        utils.unzip_file(name_zip, directory_assets)

    def _download(self, file, url):
        try:
            response = requests.get(url)
            with open(file, "wb") as f:
                f.write(response.content)
        except Exception as ex:
            logger.error(f"An error ocurred downloading {file} {ex}")

    def _get_queries(self, config_tool, platform_to_scan):
        try:
            queries = []
            for platform in platform_to_scan:
                platform = platform.strip().upper()
                if f"RULES_{platform}" not in config_tool[self.TOOL_KICS]["RULES"]:
                    logger.error(f"Platform {platform} not found in RULES")
                queries = [
                    {key: [value["checkID"], value["overrideID"]],
                            "severity": value["severity"]}
                           for key, value in config_tool[self.TOOL_KICS]["RULES"][f"RULES_{platform}"].items()
                           ]
            return queries
        except Exception as e:
            logger.error(f"Error writing queries file: {e}")

    def _find_exclude_paths(self, base_path, exclude_paths):
        exclude_dirs = []
        try:
            for root, dirs, files in os.walk(base_path):
                for dir_name in dirs:
                    if dir_name.lower() in exclude_paths:
                        rel_path = os.path.relpath(os.path.join(root, dir_name), base_path)
                        exclude_dirs.append(rel_path)
            return exclude_dirs
        except Exception as e: 
            logger.error(f"Error finding exclude paths: {e}")
            return []
        
    def _execute_kics(
        self,
        folders_to_scan,
        prefix,
        platform_to_scan,
        work_folder,
        os_platform,
        queries,
        exclude_paths
    ):
        folders = ','.join(folders_to_scan)
        queries_flat = [
            uuid
            for query in queries
            for uuid in list(query.values())[0]
            if uuid
        ] if queries else []
        queries = ','.join(queries_flat)
        mapped_platforms = [ 
            self.scan_type_platform_mapping.get(platform.lower(), platform) 
            for platform in platform_to_scan ] if platform_to_scan != ["all"] else list(self.scan_type_platform_mapping.values())
        platforms = ','.join(mapped_platforms)
        exclude_paths_str = ",".join(self._find_exclude_paths(folders, exclude_paths)) if exclude_paths else ""
        queries_path = f"{work_folder}\\kics-devsecops\\assets\\queries" if os_platform == "Windows" else f"{work_folder}/kics-devsecops/assets/queries"

        command = [
            prefix,
            "scan",
            "-p", folders,
            "--exclude-paths", exclude_paths_str,
            "-t", platforms,
            "--include-queries", queries,
            "-q", queries_path,
            "--report-formats", "json",
            "-o", work_folder
        ]
        try:
            subprocess.run(command, capture_output=True, text=True, cwd=folders)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during KICS execution: {e}")
            return []
            
    def _load_results(self, work_folder, queries):
        try:
            results_path = os.path.join(work_folder, "results.json")
            with open(results_path, "r") as f:
                data = json.load(f)

            query_id_to_info = {}
            for query in queries:
                severity = query.get("severity")
                for custom_id, ids in query.items():
                    if custom_id == "severity":
                        continue
                    for query_id in ids:
                        if query_id != "":
                            query_id_to_info[query_id] = {
                                "severity": severity,
                                "custom_id": custom_id
                            }

            for finding in data.get("queries", []):
                query_id = finding.get("query_id")
                if query_id in query_id_to_info:
                    info = query_id_to_info[query_id]
                    finding["severity"] = info["severity"].upper()
                    finding["custom_id"] = info["custom_id"]
                    finding["query_name"] = f"{info['custom_id']}: {finding.get('query_name', '')}"

            with open(results_path, "w") as f:
                json.dump(data, f, indent=4)

            return data
        except Exception as ex:
            logger.error(f"An error occurred loading or modifying KICS results {ex}")
            return None