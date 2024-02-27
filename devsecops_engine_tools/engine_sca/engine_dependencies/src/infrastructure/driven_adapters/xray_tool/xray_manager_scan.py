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
    def install_tool_linux(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./jf"]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
                file = "./jf"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Linux: {error}")

    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./jf.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe"
                exe_file = "./jf.exe"
                response = requests.get(url, allow_redirects=True)
                with open(exe_file, "wb") as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                logger.error(f"Error while Jfrog Cli installation on Windows: {error}")

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

    def compress_and_mv(self, npm_modules, target_dir):
        try:
            tar_path = os.path.join(target_dir, "node_modules.tar")
            if os.path.exists(tar_path):
                os.remove(tar_path)
            with tarfile.open(tar_path, "w") as tar:
                tar.add(
                    npm_modules,
                    arcname=os.path.basename(npm_modules),
                    filter=lambda x: None if "/.bin/" in x.name else x,
                )
                logger.debug(f"File to scan: {tar_path}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during npm_modules compression: {e}")

    def find_node_modules(self, working_dir):
        for root, dirs, files in os.walk(working_dir):
            if "node_modules" in dirs:
                return os.path.join(root, "node_modules")
        return None

    def find_artifacts(self, pattern, working_dir, target_dir, excluded_dir):
        finded_files = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)

        for root, dirs, files in os.walk(working_dir):
            if not (excluded_dir in root) or excluded_dir == "":
                for file in files:
                    if extension_pattern.search(file):
                        ruta_completa = os.path.join(root, file)
                        finded_files.append(ruta_completa)

        for file in finded_files:
            target = os.path.join(target_dir, os.path.basename(file))
            shutil.copy2(file, target)
            logger.debug(f"File to scan: {file}")

    def scan_dependencies(
        self, prefix, target_dir_name, working_dir, bypass_limits_flag
    ):
        try:
            if bypass_limits_flag:
                command = [
                    prefix,
                    "scan",
                    "--format=json",
                    "--bypass-archive-limits",
                    f"{target_dir_name}/",
                ]
            else:
                command = [prefix, "scan", "--format=json", f"{target_dir_name}/"]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            scan_result = json.loads(result.stdout)
            file_result = os.path.join(working_dir, "scan_result.json")
            with open(file_result, "w") as file:
                json.dump(scan_result, file, indent=4)
            return file_result
        except subprocess.CalledProcessError as error:
            logger.error(f"Error executing jf scan: {error}")

    def run_tool_dependencies_sca(
        self,
        remote_config,
        working_dir,
        skip_flag,
        scan_flag,
        bypass_limits_flag,
        pattern,
        token,
    ):
        cli_version = remote_config["XRAY"]["CLI_VERSION"]
        os_platform = platform.system()

   
        if os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"
        else:
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"

        self.config_server(command_prefix, token)

        dir_to_scan_path = os.path.join(working_dir, "dependencies_to_scan")
        if os.path.exists(dir_to_scan_path):
            shutil.rmtree(dir_to_scan_path)
        os.makedirs(dir_to_scan_path)

        if scan_flag and not (skip_flag):
            npm_modules_path = self.find_node_modules(working_dir)
            if npm_modules_path:
                self.compress_and_mv(npm_modules_path, dir_to_scan_path)
                excluded_dir = npm_modules_path
            else:
                excluded_dir = ""
            self.find_artifacts(pattern, working_dir, dir_to_scan_path, excluded_dir)

        results_file = self.scan_dependencies(
            command_prefix, dir_to_scan_path, working_dir, bypass_limits_flag
        )

        return results_file
