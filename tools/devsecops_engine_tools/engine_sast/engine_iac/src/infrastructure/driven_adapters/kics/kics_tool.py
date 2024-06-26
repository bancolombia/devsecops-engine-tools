import subprocess
import json
import platform
import requests
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_deserealizator import (
    KicsDeserealizator
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KicsTool(ToolGateway):

    def download(self, file, url):
        try:
            response = requests.get(url)
            with open(file, "wb") as f:
                f.write(response.content)
        except Exception as ex:
            logger.error(f"An error ocurred downloading {file} {ex}")

    def install_tool(self, file, url, github_api: GithubApi):
        kics = "./kics_bin/kics"
        installed = subprocess.run(
            ["which", kics],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self.download(file, url)
                github_api.unzip_file(file, "kics_bin")
                subprocess.run(["chmod", "+x", kics])
            except Exception as e:
                logger.error(f"Error installing KICS: {e}")

    def install_tool_windows(self, file, url, github_api: GithubApi):
        try:
            subprocess.run(
                ["./kics_bin/kics.exe", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self.download(file, url)
                github_api.unzip_file(file, "kics_bin")

            except Exception as e:
                logger.error(f"Error installing KICS: {e}")

    def execute_kics(self, folders_to_scan, prefix):
        for folder in folders_to_scan:
            command = [prefix,
                       "scan", "-p", folder, "-q", "./kics_assets/assets",
                       "--report-formats", "json", "-o", "./"]
            try:
                subprocess.run(command, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Error during KICS execution: {e}")

    def load_results(self):
        try:
            with open('results.json') as f:
                data = json.load(f)
            return data
        except Exception as ex:
            logger.error(f"An error ocurred loading KICS results {ex}")
            return None

    def calculate_total_vulnerabilities(self, severity_counters):
        critical = severity_counters.get("CRITICAL", 0)
        high = severity_counters.get("HIGH", 0)
        medium = severity_counters.get("MEDIUM", 0)
        low = severity_counters.get("LOW", 0)

        return critical + high + medium + low

    def process_results(self):
        data = self.load_results()

        severity_counters = data.get("severity_counters", {})

        return self.calculate_total_vulnerabilities(severity_counters)

    def get_findings(self):
        data = self.load_results()

        filtered_results = []
        for query in data.get("queries", []):
            severity = query.get("severity", "").upper()
            if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                description = query.get("query_name", "")
                query_id = query.get("query_id", "")
                for file in query.get("files", []):
                    file_name = file.get("file_name", "")
                    filtered_results.append({
                        "severity": severity,
                        "description": description,
                        "file_name": file_name,
                        "id": query_id
                    })
        return filtered_results

    def run_tool(
            self, config_tool: ConfigTool, folders_to_scan, environment, container_platform, secret_tool
    ):

        if folders_to_scan:
            name_zip = "assets_compressed.zip"
            kics_version = config_tool.version
            assets_url = f"https://github.com/Checkmarx/kics/releases/download/v{kics_version}/extracted-info.zip"
            self.download(name_zip, assets_url)

            directory_assets = "kics_assets"
            github_api = GithubApi()
            github_api.unzip_file(name_zip, directory_assets)

            os_platform = platform.system()

            if os_platform == "Linux":
                kics_zip = "kics_linux.zip"
                url_kics = config_tool.kics_linux
                self.install_tool(kics_zip, url_kics, github_api)
                command_prefix = "./kics_bin/kics"

            elif os_platform == "Windows":
                kics_zip = "kics_windows.zip"
                url_kics = config_tool.kics_windows
                self.install_tool_windows(kics_zip, url_kics, github_api)
                command_prefix = "./kics_bin/kics.exe"
            else:
                logger.warning(f"{os_platform} is not supported.")
                return None

            self.execute_kics(folders_to_scan, command_prefix)

            total_vulnerabilities = self.process_results()

            if total_vulnerabilities != 0:
                filtered_results = self.get_findings()
            else:
                return [], None

            kics_deserealizator = KicsDeserealizator()
            finding_list = kics_deserealizator.get_list_finding(filtered_results)

            return finding_list, None

        return [], None

