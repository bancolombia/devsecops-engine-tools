from dataclasses import dataclass
import requests
import subprocess
import platform
import os
import re

from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import (
    Component,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class CdxGen(SbomManagerGateway):

    def get_components(self, artifact, config, service_name) -> "list[Component]":
        try:
            cdxgen_config = config["CDXGEN"]
            cdxgen_version = cdxgen_config["CDXGEN_VERSION"]
            slim = "-slim" if cdxgen_config["SLIM_BINARY"] else ""
            fetch_license = cdxgen_config.get("FETCH_LICENSE", False)
            exclude_types = cdxgen_config.get("EXCLUDE_TYPES", [])
            exclude_paths = cdxgen_config.get("EXCLUDE_PATHS", [])
            recurse = cdxgen_config.get("RECURSE", True)
            install_deps = cdxgen_config.get("INSTALL_DEPENDENCIES", True)
            debug_pipelines = cdxgen_config.get("DEBUG_PIPELINES", [])
            required_only_pipelines = cdxgen_config.get("REQUIRED_ONLY_PIPELINES", [])
            spec_version = cdxgen_config.get("SPEC_VERSION", "1.6")
            break_on_build_failure = cdxgen_config.get("BREAK_ON_BUILD_FAILURE", True)
            build_failure_patterns = cdxgen_config.get("BUILD_FAILURE_PATTERNS", [])
            failure_patterns = build_failure_patterns if break_on_build_failure else []

            if cdxgen_config.get("OVERRIDE_REGISTRIES", False):
                self._apply_registry_overrides(cdxgen_config.get("REGISTRIES", {}))

            enable_debug = self._pipeline_in_list(service_name, debug_pipelines)
            if enable_debug:
                logger.info(f"Enabling debug mode for pipeline: {service_name}")
                os.environ["CDXGEN_DEBUG_MODE"] = "debug"

            if fetch_license:
                os.environ["FETCH_LICENSE"] = "true"

            command_prefix, is_supported = self._resolve_cdxgen_command_prefix(cdxgen_version, slim)
            if not is_supported:
                return None

            required_only = self._pipeline_in_list(service_name, required_only_pipelines)
            result_sbom = self._run_cdxgen(command_prefix, artifact, service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug, spec_version, failure_patterns)
            return get_list_component(result_sbom, cdxgen_config["OUTPUT_FORMAT"])
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}")
            return None

    def _apply_registry_overrides(self, registries):
        for env_var, url in registries.items():
            os.environ[env_var] = url

    def _pipeline_in_list(self, service_name, pipelines):
        return service_name in pipelines if pipelines else False

    def _resolve_cdxgen_command_prefix(self, cdxgen_version, slim):
        command_prefix = self._check_cdxgen_in_path()
        if command_prefix:
            logger.info(f"Using cdxgen from PATH: {command_prefix}")
            return command_prefix, True

        os_platform = platform.system()
        os_architecture = platform.machine()
        base_url = (
            f"https://github.com/CycloneDX/cdxgen/releases/download/v{cdxgen_version}/"
        )

        if os_platform == "Linux":
            file = (
                f"cdxgen-linux-arm64{slim}"
                if os_architecture == "aarch64"
                else f"cdxgen-linux-amd64{slim}"
            )
            return self._install_tool_unix(file, base_url + file, "cdxgen"), True
        if os_platform == "Darwin":
            file = (
                f"cdxgen-darwin-arm64{slim}"
                if os_architecture == "arm64"
                else f"cdxgen-darwin-amd64{slim}"
            )
            return self._install_tool_unix(file, base_url + file, "cdxgen"), True
        if os_platform == "Windows":
            file = f"cdxgen-windows-amd64{slim}.exe"
            return self._install_tool_windows(file, base_url + file, "cdxgen.exe"), True

        logger.warning(f"{os_platform} is not supported.")
        return None, False

    def _run_cdxgen(self, command_prefix, artifact, service_name, exclude_types, exclude_paths, recurse, install_deps, required_only=False, enable_debug=False, spec_version="1.6", failure_patterns=None):
        failure_patterns = failure_patterns or []
        result_file = f"{service_name}_SBOM.json"
        command = self._build_cdxgen_command(
            command_prefix, artifact, result_file, spec_version,
            exclude_types, exclude_paths, required_only, recurse, install_deps
        )

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self._log_debug_output(result, enable_debug)
            self._check_build_failure(result, failure_patterns, service_name, result_file)

            if result.returncode == 0:
                print(f"SBOM generated and saved to: {result_file}")
                return result_file
            else:
                raise Exception(f"CDXGEN command failed with return code: {result.returncode}")

        except Exception as e:
            logger.error(f"Error running cdxgen: {e}")

    def _build_cdxgen_command(self, command_prefix, artifact, result_file, spec_version, exclude_types, exclude_paths, required_only, recurse, install_deps):
        command = [
            command_prefix,
            artifact,
            "-o",
            result_file,
            "--spec-version",
            spec_version
        ]

        for ex in exclude_types or []:
            command.extend(["--exclude-type", ex])

        for ex in exclude_paths or []:
            command.extend(["--exclude", ex])

        if required_only:
            command.append("--required-only")

        if not recurse:
            command.append("--no-recurse")

        if not install_deps:
            command.append("--no-install-deps")

        return command

    def _log_debug_output(self, result, enable_debug):
        if not enable_debug:
            return
        if result.stdout:
            logger.info(f"CDXGEN stdout: {result.stdout}")
        if result.stderr:
            logger.info(f"CDXGEN stderr: {result.stderr}")

    def _check_build_failure(self, result, failure_patterns, service_name, result_file):
        matched_pattern = self._detect_build_failure(
            f"{result.stdout or ''}\n{result.stderr or ''}", failure_patterns
        )
        if matched_pattern:
            self._remove_incomplete_sbom(result_file)
            raise Exception(
                f"Detected build failure pattern '{matched_pattern}' in cdxgen output for "
                f"'{service_name}'. The underlying build likely failed; aborting to avoid "
                "generating an incomplete or empty SBOM."
            )

    def _detect_build_failure(self, output, patterns):
        """Return the first configured regex pattern that matches the cdxgen output, if any."""
        if not output or not patterns:
            return None
        for pattern in patterns:
            try:
                if re.search(pattern, output, re.IGNORECASE):
                    return pattern
            except re.error as e:
                logger.debug(f"Invalid build failure regex pattern '{pattern}': {e}")
        return None

    def _remove_incomplete_sbom(self, result_file):
        """Best-effort removal of a possibly incomplete/empty SBOM file left by a failed build."""
        try:
            if result_file and os.path.exists(result_file):
                os.remove(result_file)
                logger.info(f"Removed incomplete SBOM file: {result_file}")
        except OSError as e:
            logger.debug(f"Could not remove incomplete SBOM file '{result_file}': {e}")

    def _check_cdxgen_in_path(self):
        """Check if cdxgen is available in PATH and return its path if found."""
        try:
            # Try to find cdxgen in PATH
            result = subprocess.run(
                ["which", "cdxgen"] if platform.system() != "Windows" else ["where", "cdxgen"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                cdxgen_path = result.stdout.strip().split('\n')[0]  # Get first match
                # Verify it's executable by checking version
                version_check = subprocess.run(
                    [cdxgen_path, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                if version_check.returncode == 0:
                    return cdxgen_path
            return None
        except Exception as e:
            logger.debug(f"cdxgen not found in PATH: {e}")
            return None

    def _install_tool_unix(self, file, url, command_prefix):
        """Download and install cdxgen binary for Unix-like systems."""
        try:
            self._download_tool(file, url)
            subprocess.run(
                ["chmod", "+x", f"./{file}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info(f"Downloaded cdxgen binary: {file}")
            return f"./{file}"
        except Exception as e:
            logger.error(f"Error installing cdxgen: {e}")
            return None

    def _install_tool_windows(self, file, url, command_prefix):
        """Download and install cdxgen binary for Windows."""
        try:
            self._download_tool(file, url)
            logger.info(f"Downloaded cdxgen binary: {file}")
            return f"{file}"
        except Exception as e:
            logger.error(f"Error installing cdxgen: {e}")
            return None

    def _download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading cdxgen: {e}")
