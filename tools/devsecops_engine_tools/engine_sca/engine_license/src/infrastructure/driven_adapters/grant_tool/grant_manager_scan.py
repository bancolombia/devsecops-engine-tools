import os
import platform
import shutil
import subprocess
import tarfile

import requests

from devsecops_engine_tools.engine_sca.engine_license.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class GrantScan(ToolGateway):
    """Anchore Grant license scanner driven adapter.

    Supports Linux (amd64, arm64) and macOS (amd64, arm64). Windows is not
    supported by the upstream Grant project and is rejected with a logged
    warning.
    """

    TOOL = "GRANT"

    def __init__(self):
        self.download_tool_called = False

    def run_tool_license_sca(
        self,
        remote_config,
        dict_args,
        exclusions,
        pipeline_name,
        to_scan,
        sbom_path,
        image_to_scan,
        secret_tool,
        **kwargs,
    ):
        try:
            grant_config = remote_config.get(self.TOOL, {})
            grant_version = grant_config.get("GRANT_VERSION", "0.6.4")
            output_format = grant_config.get("OUTPUT_FORMAT", "json")
            debug_pipelines = grant_config.get("DEBUG_PIPELINES", [])
            quiet = grant_config.get("QUIET", True)
            enable_debug = pipeline_name in debug_pipelines if debug_pipelines else False

            command_prefix = self._resolve_binary(grant_version)
            if not command_prefix:
                return None

            scan_target = self._resolve_scan_target(
                sbom_path, image_to_scan, to_scan
            )
            if not scan_target:
                logger.error("Grant scan target could not be resolved (no SBOM, image or folder).")
                return None

            return self._run_grant(
                command_prefix,
                scan_target,
                pipeline_name,
                output_format,
                quiet,
                enable_debug,
            )
        except Exception as e:
            logger.error(f"Error running Grant license scan: {e}")
            return None

    def _resolve_scan_target(self, sbom_path, image_to_scan, to_scan):
        if sbom_path and os.path.exists(sbom_path):
            return sbom_path
        if image_to_scan:
            return image_to_scan
        if to_scan and os.path.exists(to_scan):
            return to_scan
        return None

    def _resolve_binary(self, grant_version):
        installed = shutil.which("grant")
        if installed:
            logger.info(f"Using Grant from PATH: {installed}")
            return installed

        os_platform = platform.system()
        os_architecture = platform.machine()

        if os_platform == "Windows":
            logger.warning(
                "Anchore Grant does not provide a Windows binary. "
                "Skipping license scan on Windows."
            )
            return None

        os_token, arch_token = self._map_platform(os_platform, os_architecture)
        if not os_token or not arch_token:
            logger.warning(
                f"Unsupported platform for Grant: {os_platform}/{os_architecture}"
            )
            return None

        file_name = f"grant_{grant_version}_{os_token}_{arch_token}.tar.gz"
        url = (
            f"https://github.com/anchore/grant/releases/download/"
            f"v{grant_version}/{file_name}"
        )
        return self._install_tool_unix(file_name, url)

    def _map_platform(self, os_platform, os_architecture):
        os_map = {"Linux": "linux", "Darwin": "darwin"}
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }
        return os_map.get(os_platform), arch_map.get(os_architecture)

    def _install_tool_unix(self, file_name, url):
        try:
            self.download_tool_called = True
            self._download_tool(file_name, url)

            extract_dir = os.path.join(os.getcwd(), "grant_bin")
            os.makedirs(extract_dir, exist_ok=True)
            with tarfile.open(file_name, "r:gz") as tar:
                tar.extractall(extract_dir)

            binary_path = os.path.join(extract_dir, "grant")
            if not os.path.exists(binary_path):
                logger.error(f"Grant binary not found after extracting {file_name}")
                return None

            subprocess.run(
                ["chmod", "+x", binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info(f"Installed Grant binary: {binary_path}")
            return binary_path
        except Exception as e:
            logger.error(f"Error installing Grant: {e}")
            return None

    def _download_tool(self, file_name, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file_name, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading Grant: {e}")
            raise

    def _run_grant(
        self,
        command_prefix,
        scan_target,
        pipeline_name,
        output_format,
        quiet,
        enable_debug,
    ):
        result_file = f"{pipeline_name}_grant.json"

        command = [
            command_prefix,
            "list",
            scan_target,
            "-o",
            output_format,
            "-f",
            result_file,
        ]

        if quiet:
            command.append("--quiet")

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if enable_debug:
                if result.stdout:
                    logger.info(f"GRANT stdout (first 4kb): {result.stdout[:4096]}")
                if result.stderr:
                    logger.info(f"GRANT stderr: {result.stderr}")

            if os.path.exists(result_file) and os.path.getsize(result_file) > 0:
                logger.info(f"Grant report saved to: {result_file}")
                return result_file
            
            if result.stdout and result.stdout.strip().startswith("{"):
                with open(result_file, "w") as f:
                    f.write(result.stdout)
                logger.info(f"Grant report saved to: {result_file}")
                return result_file

            logger.error(
                f"Grant produced no output (exit={result.returncode}): {result.stderr}"
            )
            return None
        except Exception as e:
            logger.error(f"Error executing Grant: {e}")
            return None
