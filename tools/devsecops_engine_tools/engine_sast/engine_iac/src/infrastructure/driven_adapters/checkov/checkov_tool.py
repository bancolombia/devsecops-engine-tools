import yaml
import requests
import zipfile
import subprocess
import time
import os
import queue
import threading
import json
import shutil
import platform
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.context_iac import (
    ContextIac,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_deserealizator import (
    CheckovDeserealizator,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_config import (
    CheckovConfig,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class CheckovTool(ToolGateway):

    CHECKOV_CONFIG_FILE = "checkov_config.yaml"
    TOOL_CHECKOV = "CHECKOV"
    framework_mapping = {
        "RULES_DOCKER": "dockerfile",
        "RULES_K8S": "kubernetes",
        "RULES_CLOUDFORMATION": "cloudformation",
        "RULES_OPENAPI": "openapi",
        "RULES_TERRAFORM": "terraform",
        "RULES_SERVERLESS": "serverless",
        "RULES_BICEP": "bicep"
    }
    framework_external_checks = [
        "RULES_K8S",
        "RULES_CLOUDFORMATION",
        "RULES_DOCKER",
        "RULES_OPENAPI",
        "RULES_TERRAFORM",
        "RULES_SERVERLESS",
        "RULES_BICEP"
    ]

    def run_tool(
        self,
        config_tool,
        folders_to_scan,
        environment,
        platform_to_scan,
        secret_tool,
        secret_external_checks,
        **kwargs,
    ):
        util = Utils()
        agent_env = util.configurate_external_checks(
            self.TOOL_CHECKOV, config_tool, secret_tool, secret_external_checks
        )

        install_type = config_tool[self.TOOL_CHECKOV].get("INSTALL_TYPE", "")

        command_prefix = None

        if install_type.casefold() == "remote-binary".casefold():
            command_prefix = self._install_binary(config_tool[self.TOOL_CHECKOV])
        else:
            command_prefix = self._retryable_install_package(
                "checkov", config_tool[self.TOOL_CHECKOV]["VERSION"]
            )

        if command_prefix is not None:
            result_scans, rules_run = self._scan_folders(
                folders_to_scan,
                config_tool,
                agent_env,
                environment,
                platform_to_scan,
                command_prefix,
                kwargs.get("dict_args"),
            )

            checkov_deserealizator = CheckovDeserealizator()
            findings_list = checkov_deserealizator.get_list_finding(
                result_scans,
                rules_run,
                config_tool[self.TOOL_CHECKOV]["DEFAULT_SEVERITY"],
                config_tool[self.TOOL_CHECKOV]["DEFAULT_CATEGORY"],
            )

            return (
                findings_list,
                generate_file_from_tool(
                    self.TOOL_CHECKOV,
                    result_scans,
                    rules_run,
                    config_tool[self.TOOL_CHECKOV],
                ),
            )
        else:
            return [], None

    def get_iac_context_from_results(self, path_file_results: str):
        with open(path_file_results, "r") as file:
            context_results_scan_list = json.load(file)
            context_iac_list = []
            failed_checks = context_results_scan_list.get("results", {}).get(
                "failed_checks", []
            )
            for check in failed_checks:
                file_line_range = check.get("file_line_range", ["unknown", "unknown"])
                start_line = (
                    file_line_range[0] if len(file_line_range) > 0 else "unknown"
                )
                end_line = file_line_range[1] if len(file_line_range) > 1 else "unknown"
                line_range_str = (
                    f"{start_line}-{end_line}"
                    if start_line != end_line
                    else str(start_line)
                )

                context_iac = ContextIac(
                    id=check.get("check_id", "unknown"),
                    check_name=check.get("check_name", "unknown"),
                    check_class=check.get("check_class", "unknown"),
                    severity=check.get("severity").lower(),
                    where=f"{check.get('repo_file_path', 'unknown')}: {check.get('resource', 'unknown')} (line {line_range_str})",
                    resource=check.get("resource", "unknown"),
                    description=check.get("check_name", "unknown"),
                    module="engine_iac",
                    tool="Checkov",
                )

                context_iac_list.append(context_iac)

            return context_iac_list

    def _retryable_install_package(self, package: str, version: str) -> bool:
        MAX_RETRIES = 3
        RETRY_DELAY = 1  # in seconds
        INSTALL_SUCCESS_MSG = f"Installation of {package} successful"
        INSTALL_RETRY_MSG = (
            f"Retrying installation of {package} in {RETRY_DELAY} seconds..."
        )

        installed = shutil.which(package)
        if installed:
            return "checkov"

        python_command = "python3" if platform.system() != "Windows" else "python"
        python_path = shutil.which(python_command)
        if python_path is None:
            logger.error("Python not found on the system.")
            return None

        # Detect Python version
        try:
            result = subprocess.run(
                [python_path, "--version"], capture_output=True, text=True, check=True
            )
            version_str = result.stdout.strip().split()[1]
            major, minor, *_ = map(int, version_str.split("."))
        except Exception as e:
            logger.error(f"Failed to detect Python version: {e}")
            return None

        # Prepare install command parts
        install_cmd_base = [
            python_path,
            "-m",
            "pip",
            "install",
            "-q",
            f"{package}=={version}",
            "--retries",
            str(MAX_RETRIES),
            "--timeout",
            str(RETRY_DELAY),
        ]

        if (major, minor) >= (3, 11):
            install_cmd_base.append("--break-system-packages")

        def retry(attempt):
            if attempt < MAX_RETRIES:
                logger.warning(INSTALL_RETRY_MSG)
                time.sleep(RETRY_DELAY)

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                result = subprocess.run(install_cmd_base, capture_output=True)
                if result.returncode == 0:
                    logger.debug(INSTALL_SUCCESS_MSG)
                    return "checkov"
                else:
                    logger.error(
                        f"Installation failed (attempt {attempt}): {result.stderr.decode().strip()}"
                    )
            except Exception as e:
                logger.error(f"Error during installation (attempt {attempt}): {e}")

            retry(attempt)

        return None

    def _install_binary(self, config_tool):
        os_platform = platform.system()
        if os_platform == "Linux":
            architecture = platform.machine()
            if architecture == "aarch64":
                url = config_tool["URL_FILE_LINUX_ARM64"]
            else:
                url = config_tool["URL_FILE_LINUX"]
            file = os.path.basename(url)
            self._install_tool_unix(file, url)
            return "./checkov"
        elif os_platform == "Darwin":
            url = config_tool["URL_FILE_DARWIN"]
            file = os.path.basename(url)
            self._install_tool_unix(file, url)
            return "./checkov"
        elif os_platform == "Windows":
            url = config_tool["URL_FILE_WINDOWS"]
            file = os.path.basename(url)
            self._install_tool_windows(file, url)
            return "checkov.exe"
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

    def _install_tool_unix(self, file, url):
        installed = subprocess.run(
            ["which", "./checkov"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./checkov"]
            try:
                self._download_tool(file, url)
                with zipfile.ZipFile(file, "r") as zip_file:
                    zip_file.extract(member="dist/checkov")
                source = os.path.join("dist", "checkov")
                destination = "checkov"
                shutil.move(source, destination)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except Exception as e:
                logger.error(f"Error installing Checkov: {e}")

    def _install_tool_windows(self, file, url):
        try:
            subprocess.run(
                ["checkov.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self._download_tool(file, url)
                with zipfile.ZipFile(file, "r") as zip_file:
                    zip_file.extract(member="dist/checkov.exe")
                source = os.path.join("dist", "checkov.exe")
                destination = "checkov.exe"
                shutil.move(source, destination)
            except Exception as e:
                logger.error(f"Error installing Checkov: {e}")

    def _download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading Checkov: {e}")

    def _scan_folders(
        self,
        folders_to_scan,
        config_tool,
        agent_env,
        environment,
        platform_to_scan,
        command_prefix,
        dict_args,
    ):
        output_queue = queue.Queue()
        # Crea una lista para almacenar los hilos
        threads = []
        rules_run = {}
        
        # Incluir reglas adicionales para serverless si se especifica en la configuración SERVERLESS_ADITIONAL_CHECKS
        ADDITIONAL_CHECKS = config_tool[self.TOOL_CHECKOV].get("SERVERLESS_ADITIONAL_CHECKS", [])
        if any(p.lower() in ["serverless", "all"] for p in platform_to_scan) and ADDITIONAL_CHECKS:
            for additional_check_type in ADDITIONAL_CHECKS:
                config_tool[self.TOOL_CHECKOV]["RULES"]["RULES_SERVERLESS"].update(config_tool[self.TOOL_CHECKOV]["RULES"][additional_check_type])
                
        # Configurar LOG_LEVEL si está definido
        log_level = config_tool[self.TOOL_CHECKOV].get("LOG_LEVEL")
        if log_level:
            if agent_env is None:
                agent_env = {}
            agent_env["LOG_LEVEL"] = log_level
        
        for folder in folders_to_scan:
            for rule in config_tool[self.TOOL_CHECKOV]["RULES"]:
                if "all" in platform_to_scan or any(
                    elem.upper() in rule for elem in platform_to_scan
                ):
                    framework = [self.framework_mapping[rule]]
                    repo_root = None
                    if "terraform" in platform_to_scan or (
                        "all" in platform_to_scan
                        and self.framework_mapping[rule] == "terraform"
                    ):
                        framework.append("terraform_plan")
                        repo_root = dict_args.get("terraform_repo_root", None)

                    checkov_config = CheckovConfig(
                        path_config_file="",
                        config_file_name=rule,
                        framework=framework,
                        checks=[
                            key
                            for key, value in config_tool[self.TOOL_CHECKOV]["RULES"][
                                rule
                            ].items()
                            if value["environment"].get(environment)
                        ],
                        soft_fail=False,
                        directories=folder,
                        external_checks_git=(
                            [
                                f"{config_tool[self.TOOL_CHECKOV]['EXTERNAL_CHECKS_GIT']}/{self.framework_mapping[rule]}"
                            ]
                            if config_tool[self.TOOL_CHECKOV]["USE_EXTERNAL_CHECKS_GIT"]
                            and agent_env is not None
                            and rule in self.framework_external_checks
                            else []
                        ),
                        env=agent_env,
                        external_checks_dir=(
                            self._get_external_checks_dirs(config_tool, rule, platform_to_scan)
                            if config_tool[self.TOOL_CHECKOV]["USE_EXTERNAL_CHECKS_DIR"]
                            and rule in self.framework_external_checks
                            else []
                        ),
                        repo_root_for_plan_enrichment=repo_root,
                        deep_analysis=(True if repo_root else None),
                        download_external_modules=config_tool[self.TOOL_CHECKOV].get(
                            "DOWNLOAD_EXTERNAL_MODULES", False
                        ),
                    )

                    checkov_config.create_config_dict()
                    self._create_config_file(checkov_config)
                    rules_run.update(config_tool[self.TOOL_CHECKOV]["RULES"][rule])
                    t = threading.Thread(
                        target=self._async_scan,
                        args=(output_queue, checkov_config, command_prefix),
                    )
                    t.start()
                    threads.append(t)
        # Espera a que todos los hilos terminen
        for t in threads:
            t.join()
        # Recopila las salidas de las tareas
        result_scans = []
        while not output_queue.empty():
            result = output_queue.get()
            result_scans.extend(result)
        return result_scans, rules_run
    
    #Function to add multiple temporary directories for external rules in serverless
    def _get_external_checks_dirs(self, config_tool, rule, platform_to_scan):
        # default directory
        dirs = [f"/tmp/rules/{self.framework_mapping[rule]}"]
        
        # # If it's Serverless, check if there are additional checks configured
        if rule == "RULES_SERVERLESS" and any(p.lower() in ["serverless", "all"] for p in platform_to_scan):
            additional_checks = config_tool[self.TOOL_CHECKOV].get("SERVERLESS_ADITIONAL_CHECKS", [])
            for additional_check_type in additional_checks:
                if additional_check_type in self.framework_mapping:
                    additional_dir = f"/tmp/rules/{self.framework_mapping[additional_check_type]}"
                    if additional_dir not in dirs:
                        dirs.append(additional_dir)
        
        return dirs

    def _create_config_file(self, checkov_config: CheckovConfig):
        with open(
            checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE,
            "w",
        ) as file:
            yaml.dump(checkov_config.dict_confg_file, file)
            file.close()

    def _async_scan(self, queue, checkov_config: CheckovConfig, command_prefix):
        result = []
        try:
            output = self._execute(checkov_config, command_prefix)
            result.append(json.loads(output))
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse Checkov output as JSON: {e}"
            logger.error(error_msg)
            result.append({"error": error_msg, "checkov_config": checkov_config.config_file_name})
        except Exception as e:
            error_msg = f"Error during Checkov scan: {e}"
            logger.error(error_msg)
            result.append({"error": error_msg, "checkov_config": checkov_config.config_file_name})
        
        queue.put(result)

    def _execute(self, checkov_config: CheckovConfig, command_prefix):
        command = (
            f"{command_prefix} --config-file "
            + checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE
        )
        env_modified = dict(os.environ)
        if checkov_config.env is not None:
            env_modified = {**dict(os.environ), **checkov_config.env}
        
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, shell=True, env=env_modified
            )
            output = result.stdout.strip()
            error = result.stderr.strip()
            
            if result.returncode != 0:
                error_msg = f"Checkov execution failed with return code {result.returncode}"
                if error:
                    error_msg += f": {error}"
                logger.warning(error_msg)
                return output
            
            if error and "error" in error.lower():
                logger.warning(f"Checkov execution completed with warnings: {error}")
            
            return output
            
        except subprocess.TimeoutExpired as e:
            error_msg = f"Checkov execution timed out: {e}"
            logger.warning(error_msg)
            return ""
        except Exception as e:
            error_msg = f"Error executing Checkov command: {e}"
            logger.warning(error_msg)
            return ""
