import yaml
import subprocess
import time
import os
import platform
import queue
import threading
import json
import shutil
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
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import (
    GithubApi,
)
from devsecops_engine_tools.engine_utilities.ssh.managment_private_key import (
    create_ssh_private_file,
    add_ssh_private_key,
    decode_base64,
    config_knowns_hosts,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class CheckovTool(ToolGateway):
    CHECKOV_CONFIG_FILE = "checkov_config.yaml"
    TOOL_CHECKOV = "CHECKOV"
    framework_mapping = {
        "RULES_DOCKER": "dockerfile",
        "RULES_K8S": "kubernetes",
        "RULES_CLOUDFORMATION": "cloudformation",
        "RULES_OPENAPI": "openapi",
    }
    framework_external_checks = [
        "RULES_K8S",
        "RULES_CLOUDFORMATION",
        "RULES_DOCKER",
        "RULES_OPENAPI",
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

    def configurate_external_checks(self, config_tool, secret):
        agent_env = None
        try:
            if secret is None:
                logger.warning("The secret is not configured for external controls")

            # Create configuration git external checks
            elif config_tool[self.TOOL_CHECKOV][
                "USE_EXTERNAL_CHECKS_GIT"
            ] == "True" and platform.system() in (
                "Linux",
                "Darwin",
            ):
                config_knowns_hosts(
                    config_tool[self.TOOL_CHECKOV]["EXTERNAL_GIT_SSH_HOST"],
                    config_tool[self.TOOL_CHECKOV][
                        "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT"
                    ],
                )
                ssh_key_content = decode_base64(secret["repository_ssh_private_key"])
                ssh_key_file_path = "/tmp/ssh_key_file"
                create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                ssh_key_password = decode_base64(secret["repository_ssh_password"])
                agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

            # Create configuration dir external checks
            elif config_tool[self.TOOL_CHECKOV]["USE_EXTERNAL_CHECKS_DIR"] == "True":
                github_api = GithubApi(secret["github_token"])
                github_api.download_latest_release_assets(
                    config_tool[self.TOOL_CHECKOV]["EXTERNAL_DIR_OWNER"],
                    config_tool[self.TOOL_CHECKOV]["EXTERNAL_DIR_REPOSITORY"],
                    "/tmp",
                )

        except Exception as ex:
            logger.error(f"An error ocurred configuring external checks {ex}")
        return agent_env

    def retryable_install_package(self, package: str, version: str) -> bool:
        MAX_RETRIES = 3
        RETRY_DELAY = 1  # in seconds
        INSTALL_SUCCESS_MSG = f"Installation of {package} successful"
        INSTALL_RETRY_MSG = (
            f"Retrying installation of {package} in {RETRY_DELAY} seconds..."
        )

        installed = subprocess.run(
            ["which", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if installed.returncode == 0:
            return True

        python_path = shutil.which("python3")
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
                    checkov_config = CheckovConfig(
                        path_config_file="",
                        config_file_name=rule,
                        framework=self.framework_mapping[rule],
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
                            == "True"
                            and agent_env is not None
                            and rule in self.framework_external_checks
                            else []
                        ),
                        env=agent_env,
                        external_checks_dir=(
                            f"/tmp/rules/{self.framework_mapping[rule]}"
                            if config_tool[self.TOOL_CHECKOV]["USE_EXTERNAL_CHECKS_DIR"]
                            == "True"
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
        secret = None
        if secret_tool is not None:
            secret = secret_tool
        elif secret_external_checks is not None:
            secret = {
                "github_token": (
                    secret_external_checks.split("github:")[1]
                    if "github" in secret_external_checks
                    else None
                ),
                "repository_ssh_private_key": (
                    secret_external_checks.split("ssh:")[1].split(":")[0]
                    if "ssh" in secret_external_checks
                    else None
                ),
                "repository_ssh_password": (
                    secret_external_checks.split("ssh:")[1].split(":")[1]
                    if "ssh" in secret_external_checks
                    else None
                ),
            }

        agent_env = self.configurate_external_checks(config_tool, secret)

        checkov_install = self.retryable_install_package(
            "checkov", config_tool[self.TOOL_CHECKOV]["VERSION"]
        )

        if checkov_install:
            result_scans, rules_run = self.scan_folders(
                folders_to_scan, config_tool, agent_env, environment, platform_to_scan
            )

            checkov_deserealizator = CheckovDeserealizator()
            findings_list = checkov_deserealizator.get_list_finding(
                result_scans, rules_run
            )

            return (
                findings_list,
                generate_file_from_tool(self.TOOL_CHECKOV, result_scans, rules_run),
            )
        else:
            return [], None
