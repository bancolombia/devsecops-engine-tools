from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import requests
import subprocess
import os
import platform
import json
import shutil
import tarfile
import re

from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class DependencyCheckTool(ToolGateway):

    def excluded_files(self, remote_config, pipeline_name, exclusions):
        pattern = remote_config["DEPENDENCY_CHECK"]["REGEX_EXPRESSION_EXTENSIONS"]
        if pipeline_name in exclusions:
            for ex in exclusions[pipeline_name]["DEPENDENCY_CHECK"]:
                if ex.get("SKIP_FILES", 0):
                    exclusion = ex.get("SKIP_FILES")
                    if exclusion.get("files", 0):
                        excluded_file_types = exclusion["files"]
                        pattern2 = pattern
                        for ext in excluded_file_types:
                            pattern2 = (
                                pattern2.replace("|" + ext, "")
                                .replace(ext + "|", "")
                                .replace(ext, "")
                            )
                        pattern = pattern2

        return pattern
    
    def find_packages(self, pattern, packages, working_dir):
        packages_list = []
        files_list = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)
        for root, dirs, files in os.walk(working_dir):
            components = root.split(os.path.sep)
            flag = 0
            for package in packages:
                if not (package in components):
                    flag = 1
                    if package in dirs:
                        packages_list.append(os.path.join(root, package))
            if flag:
                for file in files:
                    if extension_pattern.search(file):
                        files_list.append(os.path.join(root, file))
        return packages_list, files_list
    
    def compress_and_mv(self, tar_path, package):
        try:
            with tarfile.open(tar_path, "w") as tar:
                tar.add(
                    package,
                    arcname=os.path.basename(package),
                    filter=lambda x: None if "/.bin/" in x.name else x,
                )

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during {package} compression: {e}")

    def move_files(self, dir_to_scan_path, finded_files):
        for file in finded_files:
            target = os.path.join(dir_to_scan_path, os.path.basename(file))
            shutil.copy2(file, target)
            logger.debug(f"File to scan: {file}")
    
    def find_artifacts(self, to_scan, pattern, packages):
        dir_to_scan_path = os.path.join(to_scan, "dependencies_to_scan")
        if os.path.exists(dir_to_scan_path):
            shutil.rmtree(dir_to_scan_path)
        os.makedirs(dir_to_scan_path)

        packages_list, files_list = self.find_packages(pattern, packages, to_scan)

        for package in packages_list:
            tar_path = os.path.join(
                dir_to_scan_path,
                "pkg"
                + str(packages_list.index(package) + 1)
                + "_"
                + os.path.basename(package)
                + ".tar",
            )
            self.compress_and_mv(tar_path, package)

        if len(files_list):
            self.move_files(dir_to_scan_path, files_list)

        files = os.listdir(dir_to_scan_path)
        files = [
            file
            for file in files
            if os.path.isfile(os.path.join(dir_to_scan_path, file))
        ]
        file_to_scan = None
        if files:
            file_to_scan = os.path.join(dir_to_scan_path, "file_to_scan.tar")
            self.compress_and_mv(file_to_scan, dir_to_scan_path)
            files_string = ", ".join(files)
            logger.debug(f"Files to scan: {files_string}")
            print(f"Files to scan: {files_string}")
        else:
            logger.warning("No artifacts found")

        return file_to_scan

    def download_tool(self, cli_version):
        try:
            zip_name = f"dependency_check_{cli_version}.zip"
            url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{cli_version}/dependency-check-{cli_version}-release.zip"
            response = requests.get(url, allow_redirects=True)
            with open(zip_name, "wb") as f:
                f.write(response.content)

            github_api = GithubApi()
            github_api.unzip_file(zip_name, None)
        except Exception as ex:
            logger.error(f"An error ocurred downloading dependency-check {ex}")

    def install_tool(self, cli_version):
        command_prefix = "dependency-check.sh"
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            current_route = os.getcwd()
            bin_route = "dependency-check\\bin\\dependency-check.sh"
            command_prefix = os.path.join(current_route, bin_route)

            installed = subprocess.run(
                ["which", command_prefix],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if installed.returncode == 1:
                try:
                    self.download_tool(cli_version)
                    current_route = os.getcwd()
                    bin_route = "dependency-check\\bin\\dependency-check.sh"
                    command_prefix = os.path.join(current_route, bin_route)

                    return command_prefix
                except Exception as e:
                    logger.error(f"Error installing OWASP dependency check: {e}")
            else:
                return command_prefix
        else:
            return command_prefix

    def install_tool_windows(self, cli_version):
        command_prefix = "dependency-check.bat"
        try:
            subprocess.run(
                [command_prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return command_prefix
        except:
            try:
                current_route = os.getcwd()
                bin_route = "dependency-check\\bin\\dependency-check.bat"
                command_prefix = os.path.join(current_route, bin_route)
                subprocess.run(
                    [command_prefix, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return command_prefix
            except:
                try:
                    self.download_tool(cli_version)

                    current_route = os.getcwd()
                    bin_route = "dependency-check\\bin\\dependency-check.bat"
                    command_prefix = os.path.join(current_route, bin_route)

                    return command_prefix
                except Exception as e:
                    logger.error(f"Error installing OWASP dependency check: {e}")

    def scan_dependencies(self, command_prefix, file_to_scan, nvd_api_key, update_nvd):

        try:
            command = [command_prefix, "--scan", file_to_scan, "--noupdate", "--format", "JSON"]
            print(command)

            if update_nvd:
                command = [command_prefix, "--scan", file_to_scan, "--nvdApiKey", nvd_api_key, "--format", "JSON"]

            subprocess.run(command, capture_output=True)
        except subprocess.CalledProcessError as error:
            logger.error(f"Error executing OWASP dependency check scan: {error}")

    def select_operative_system(self, cli_version, file_to_scan, nvd_api_key, update_nvd):
        os_platform = platform.system()
        command_prefix = None

        if os_platform in ["Linux", "Darwin"]:
            command_prefix = self.install_tool(cli_version)
        elif os_platform == "Windows":
            command_prefix = self.install_tool_windows(cli_version)
        else:
            logger.warning(f"{os_platform} is not supported.")

        self.scan_dependencies(command_prefix, file_to_scan, nvd_api_key, update_nvd)

    def load_results(self):
        try:
            with open('dependency-check-report.json') as f:
                data = json.load(f)
            return data
        except Exception as ex:
            logger.error(f"An error ocurred loading dependency-check results {ex}")
            return None

    def run_tool_dependencies_sca(
        self,
        remote_config,
        dict_args,
        exclusion,
        pipeline_name,
        to_scan,
        token,
    ):

        cli_version = remote_config["DEPENDENCY_CHECK"]["CLI_VERSION"]
        nvd_api_key = remote_config["DEPENDENCY_CHECK"]["NVD_API_KEY"]
        update_nvd = remote_config["DEPENDENCY_CHECK"]["UPDATE_NVD"]

        pattern = self.excluded_files(remote_config, pipeline_name, exclusion)
        to_scan = self.find_artifacts(
            to_scan, pattern, remote_config["DEPENDENCY_CHECK"]["PACKAGES_TO_SCAN"]
        )

        self.select_operative_system(cli_version, to_scan, nvd_api_key, update_nvd)
        data = self.load_results()
        

        return data
