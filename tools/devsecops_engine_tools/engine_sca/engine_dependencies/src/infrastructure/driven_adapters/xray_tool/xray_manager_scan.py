from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import re
import os
import json
import shutil
import tarfile

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class XrayScan(ToolGateway):
    def excluded_files(self, remote_config, pipeline_name, exclusions):
        pattern = remote_config["XRAY"]["REGEX_EXPRESSION_EXTENSIONS"]
        if pipeline_name in exclusions:
            for ex in exclusions[pipeline_name]["XRAY"]:
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

    def install_tool_linux(self, prefix, version):
        installed = subprocess.run(
            ["which", prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", prefix]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
                response = requests.get(url, allow_redirects=True)
                with open(prefix, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Linux: {error}")

    def install_tool_windows(self, prefix, version):
        try:
            subprocess.run(
                [prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe"
                response = requests.get(url, allow_redirects=True)
                with open(prefix, "wb") as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                logger.error(f"Error while Jfrog Cli installation on Windows: {error}")

    def install_tool_darwin(self, prefix, version):
        installed = subprocess.run(
            ["which", prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", prefix]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-mac-386/jf"
                response = requests.get(url, allow_redirects=True)
                with open(prefix, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Darwin: {error}")

    def config_server(self, prefix, token):
        try:
            c_import = [prefix, "c", "im", token]
            result = subprocess.run(
                c_import,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            server_id = re.search(r"'(.*?)'", result.stderr).group(1)
            c_set_server = [prefix, "c", "use", server_id]
            subprocess.run(
                c_set_server,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            logger.error(f"Error during Xray Server configuration: {error}")

    def config_audit_scan(self, to_scan):
        gradlew_path = os.path.join(to_scan, "gradlew")
        if os.path.exists(gradlew_path):
            os.chmod(gradlew_path, 0o755)

    def scan_dependencies(self, prefix, cwd, mode, to_scan):
        command = [
            prefix,
            mode,
            "--format=json",
            f"{to_scan}",
        ]
        result = subprocess.run(
            command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.stdout or all(
            word in result.stderr
            for word in ["Technology", "WorkingDirectory", "Descriptors"]
        ):
            if result.stdout:
                scan_result = json.loads(result.stdout)
            else:
                scan_result = {}
                if any(
                    word in result.stderr
                    for word in ["What went wrong", "Caused by"]
                ):
                    logger.error(f"Error executing Xray scan: {result.stderr}")
                    return None
            if result.stdout == "null\n":
                logger.warning(f"Xray scan returned null: {result.stderr}")
                return None
            file_result = os.path.join(os.getcwd(), "scan_result.json")
            with open(file_result, "w") as file:
                json.dump(scan_result, file, indent=4)
            return file_result
        else:
            logger.error(f"Error executing Xray scan: {result.stderr}")
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
        if dict_args["xray_mode"] == "scan":
            pattern = self.excluded_files(remote_config, pipeline_name, exclusion)
            to_scan = self.find_artifacts(
                to_scan, pattern, remote_config["XRAY"]["PACKAGES_TO_SCAN"]
            )
            cwd = os.getcwd()
            if not to_scan:
                return None
        else:
            self.config_audit_scan(to_scan)
            cwd = to_scan
            to_scan = ""

        cli_version = remote_config["XRAY"]["CLI_VERSION"]
        os_platform = platform.system()

        if os_platform == "Linux":
            command_prefix = os.path.join(os.path.expanduser("~"), "jf")
            self.install_tool_linux(command_prefix, cli_version)
        elif os_platform == "Windows":
            command_prefix = os.path.join(os.path.expanduser("~"), "jf.exe")
            self.install_tool_windows(command_prefix, cli_version)
        elif os_platform == "Darwin":
            command_prefix = os.path.join(os.path.expanduser("~"), "jf")
            self.install_tool_darwin(command_prefix, cli_version)
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

        self.config_server(command_prefix, token)

        results_file = self.scan_dependencies(
            command_prefix,
            cwd,
            dict_args["xray_mode"],
            to_scan,
        )

        return results_file
