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

    def download(self, file, url):
        try:
            response = requests.get(url)
            with open(file, "wb") as f:
                f.write(response.content)
        except Exception as ex:
            logger.error(f"An error ocurred downloading {file} {ex}")

    def install_tool(self, file, url, command_prefix):
        utils = Utils()
        kics = f"./{command_prefix}/kics"
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self.download(file, url)
                utils.unzip_file(file, command_prefix)
                subprocess.run(["chmod", "+x", kics])
                return kics
            except Exception as e:
                logger.error(f"Error installing KICS: {e}")
        else:
            return command_prefix

    def install_tool_windows(self, file, url, command_prefix):
        try:
            subprocess.run(
                [command_prefix, "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return command_prefix
        except:
            try:
                utils = Utils()
                self.download(file, url)
                utils.unzip_file(file, command_prefix)
                return f"./{command_prefix}/kics"

            except Exception as e:
                logger.error(f"Error installing KICS: {e}")

    def execute_kics(self, folders_to_scan, prefix):
        folders = ','.join(folders_to_scan)
        command = [prefix, "scan", "-p", folders, "-q", "./kics_assets/assets", "--report-formats", "json", "-o", "./"]
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

    def select_operative_system(self, os_platform, config_tool, path_kics):
        command_prefix = path_kics
        if os_platform == "Linux":
            kics_zip = "kics_linux.zip"
            url_kics = config_tool[self.TOOL_KICS]["KICS_LINUX"]
            return self.install_tool(kics_zip, url_kics, command_prefix)
        elif os_platform == "Windows":
            kics_zip = "kics_windows.zip"
            url_kics = config_tool[self.TOOL_KICS]["KICS_WINDOWS"]
            return self.install_tool_windows(kics_zip, url_kics, command_prefix)
        elif os_platform == "Darwin":
            kics_zip = "kics_macos.zip"
            url_kics = config_tool[self.TOOL_KICS]["KICS_MAC"]
            return self.install_tool(kics_zip, url_kics, command_prefix)
        else:
            logger.warning(f"{os_platform} is not supported.")
            return [], None

    def get_assets(self, kics_version):
        name_zip = "assets_compressed.zip"
        assets_url = f"https://github.com/Checkmarx/kics/releases/download/v{kics_version}/extracted-info.zip"
        self.download(name_zip, assets_url)

        directory_assets = "kics_assets"
        utils = Utils()
        utils.unzip_file(name_zip, directory_assets)

    def run_tool(
            self, config_tool, folders_to_scan, **kwargs
    ):
        kics_version = config_tool[self.TOOL_KICS]["VERSION"]
        path_kics = config_tool[self.TOOL_KICS]["PATH_KICS"]
        download_kics_assets = config_tool[self.TOOL_KICS]["DOWNLOAD_KICS_ASSETS"]
        if download_kics_assets:
            self.get_assets(kics_version)

        os_platform = platform.system()
        command_prefix = self.select_operative_system(os_platform, config_tool, path_kics)
        self.execute_kics(folders_to_scan, command_prefix)

        data = self.load_results()
        if data:
            kics_deserealizator = KicsDeserealizator()
            total_vulnerabilities = kics_deserealizator.calculate_total_vulnerabilities(data)
            path_file = os.path.abspath("results.json")

            if total_vulnerabilities == 0:
                return [], path_file

            filtered_results = kics_deserealizator.get_findings(data)
            finding_list = kics_deserealizator.get_list_finding(filtered_results)

            return finding_list, path_file
        return [], None
