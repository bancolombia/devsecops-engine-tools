import yaml
import subprocess
import time
import os
import queue
import threading
import json
import shutil
import platform
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
        "RULES_TERRAFORM": "terraform"
    }
    framework_external_checks = [
        "RULES_K8S",
        "RULES_CLOUDFORMATION",
        "RULES_DOCKER",
        "RULES_OPENAPI",
        "RULES_TERRAFORM"
    ]

    def create_config_file(self, checkov_config: CheckovConfig):
        with open(
            checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE,
            "w",
        ) as file:
            yaml.dump(checkov_config.dict_confg_file, file)
            file.close()


    def retryable_install_package(self, package: str, version: str) -> bool:
        MAX_RETRIES = 3
        RETRY_DELAY = 1  # in seconds
        INSTALL_SUCCESS_MSG = f"Installation of {package} successful"
        INSTALL_RETRY_MSG = (
            f"Retrying installation of {package} in {RETRY_DELAY} seconds..."
        )

        installed = shutil.which(package)
        if installed:
            return True

        python_command = "python3" if platform.system() != "Windows" else "python"

        python_path = shutil.which(python_command)
        if python_path is None:
            logger.error("Python3 not found on the system.")
            return False

        def retry(attempt):
            if attempt < MAX_RETRIES:
                logger.warning(INSTALL_RETRY_MSG)
                time.sleep(RETRY_DELAY)

        for attempt in range(1, MAX_RETRIES + 1):
            install_cmd = [
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

            try:
                result = subprocess.run(install_cmd, capture_output=True)
                if result.returncode == 0:
                    logger.debug(INSTALL_SUCCESS_MSG)
                    return True
            except Exception as e:
                logger.error(f"Error during installation: {e}")

            retry(attempt)

        return False

    def execute(self, checkov_config: CheckovConfig):
        command = (
            "checkov --config-file "
            + checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE
        )
        env_modified = dict(os.environ)
        if checkov_config.env is not None:
            env_modified = {**dict(os.environ), **checkov_config.env}
        result = subprocess.run(
            command, capture_output=True, text=True, shell=True, env=env_modified
        )
        output = result.stdout.strip()
        error = result.stderr.strip()
        return output

    def async_scan(self, queue, checkov_config: CheckovConfig):
        result = []
        output = self.execute(checkov_config)
        result.append(json.loads(output))
        queue.put(result)

    def scan_folders(
        self,
        folders_to_scan,
        config_tool,
        agent_env,
        environment,
        platform_to_scan,
    ):
        output_queue = queue.Queue()
        # Crea una lista para almacenar los hilos
        threads = []
        rules_run = {}
        for folder in folders_to_scan:
            for rule in config_tool[self.TOOL_CHECKOV]["RULES"]:
                if "all" in platform_to_scan or any(
                    elem.upper() in rule for elem in platform_to_scan
                ):
                    framework = [self.framework_mapping[rule]]
                    if "terraform" in platform_to_scan or ("all" in platform_to_scan and self.framework_mapping[rule] == "terraform"): 
                        framework.append("terraform_plan")

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
                            f"/tmp/rules/{self.framework_mapping[rule]}"
                            if config_tool[self.TOOL_CHECKOV]["USE_EXTERNAL_CHECKS_DIR"]
                            and rule in self.framework_external_checks
                            else []
                        ),
                    )

                    checkov_config.create_config_dict()
                    self.create_config_file(checkov_config)
                    rules_run.update(config_tool[self.TOOL_CHECKOV]["RULES"][rule])
                    t = threading.Thread(
                        target=self.async_scan,
                        args=(output_queue, checkov_config),
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

    def run_tool(
        self,
        config_tool,
        folders_to_scan,
        environment,
        platform_to_scan,
        secret_tool,
        secret_external_checks,
    ):
        util = Utils()
        agent_env = util.configurate_external_checks(self.TOOL_CHECKOV,config_tool, secret_tool,secret_external_checks)

        checkov_install = self.retryable_install_package(
            "checkov", config_tool[self.TOOL_CHECKOV]["VERSION"]
        )

        if checkov_install:
            result_scans, rules_run = self.scan_folders(
                folders_to_scan, config_tool, agent_env, environment, platform_to_scan
            )

            checkov_deserealizator = CheckovDeserealizator()
            findings_list = checkov_deserealizator.get_list_finding(
                result_scans, 
                rules_run, 
                config_tool[self.TOOL_CHECKOV]["DEFAULT_SEVERITY"],
                config_tool[self.TOOL_CHECKOV]["DEFAULT_CATEGORY"]
            )

            return (
                findings_list,
                generate_file_from_tool(
                    self.TOOL_CHECKOV, 
                    result_scans, 
                    rules_run, 
                    config_tool[self.TOOL_CHECKOV]["DEFAULT_SEVERITY"],
                    config_tool[self.TOOL_CHECKOV]["DEFAULT_CATEGORY"]
                ),
            )
        else:
            return [], None