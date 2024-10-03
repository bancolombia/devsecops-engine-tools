from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import re
import os
import json

from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts import GetArtifacts
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class XrayScan(ToolGateway):

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
        secret_tool,
        token_engine_dependencies
    ):
        token = secret_tool["token_xray"] if secret_tool else token_engine_dependencies
        if dict_args["xray_mode"] == "scan":
            get_artifacts = GetArtifacts()
            pattern = get_artifacts.excluded_files(remote_config, pipeline_name, exclusion, "XRAY")
            to_scan = get_artifacts.find_artifacts(
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
