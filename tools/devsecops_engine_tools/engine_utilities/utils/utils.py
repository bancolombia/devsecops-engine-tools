import zipfile
import tarfile
import platform
import time
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
import base64
import re

from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.level_vulnerability import (
    LevelVulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.level_compliance import (
    LevelCompliance,
)


class Utils:

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)
    
    def extract_targz_file(self, tar_file_path, extract_path):
        with tarfile.open(tar_file_path, "r:gz") as tar_ref:
            tar_ref.extractall(path=extract_path)

    def configurate_external_checks(self, tool, config_tool, secret_tool, secret_external_checks, agent_work_folder="/tmp"):
        try:
            agent_env = None
            secret = None
            github_token = None
            github_api = GithubApi()

            if secret_tool is not None:
                secret = secret_tool
                github_token = github_api.get_installation_access_token(
                    secret["github_token"],
                    config_tool[tool]["APP_ID_GITHUB"],
                    config_tool[tool]["INSTALLATION_ID_GITHUB"]
                )

            elif secret_external_checks is not None:
                secret_external_checks_parts = {
                    "github_token": (
                        secret_external_checks.split("github_token:")[1]
                        if "github_token" in secret_external_checks
                        else None
                    ),
                    "github_apps": (
                        secret_external_checks.split("github_apps:")[1]
                        if "github_apps" in secret_external_checks
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

                secret = {
                    key: secret_external_checks_parts[key]
                    for key in secret_external_checks_parts
                    if secret_external_checks_parts[key] is not None
                }

            if secret is None:
                logger.warning("The secret is not configured for external controls")

            
            elif config_tool[tool]["USE_EXTERNAL_CHECKS_GIT"] and platform.system() in (
                "Linux", "Darwin",
            ):
                config_knowns_hosts(
                        config_tool[tool]["EXTERNAL_GIT_SSH_HOST"],
                        config_tool[tool]["EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT"],
                )
                ssh_key_content = decode_base64(secret["repository_ssh_private_key"])
                ssh_key_file_path = "/tmp/ssh_key_file"
                create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                ssh_key_password = decode_base64(secret["repository_ssh_password"])
                agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

            elif config_tool[tool]["USE_EXTERNAL_CHECKS_DIR"]:
                if not github_token:
                    github_token = github_api.get_installation_access_token(
                        secret.get("github_apps"),
                        config_tool[tool]["APP_ID_GITHUB"],
                        config_tool[tool]["INSTALLATION_ID_GITHUB"]
                    ) if secret.get("github_apps") else secret.get("github_token") 
                github_api.download_latest_release_assets(
                        config_tool[tool]["EXTERNAL_DIR_OWNER"],
                        config_tool[tool]["EXTERNAL_DIR_REPOSITORY"],
                        github_token,
                        agent_work_folder
                    )
    
        except Exception as ex:
            logger.error(f"An error occurred configuring external checks: {ex}")
        return agent_env
    
    def encode_token_to_base64(self, token):
        token_bytes = f"{token}:".encode("utf-8")
        base64_token = base64.b64encode(token_bytes).decode("utf-8")
        return base64_token

    def update_threshold(self, threshold: Threshold, exclusions_data, pipeline_name):
        def set_threshold(new_threshold):
            threshold.vulnerability = LevelVulnerability(new_threshold.get("VULNERABILITY"))
            threshold.compliance = LevelCompliance(new_threshold.get("COMPLIANCE")) if new_threshold.get("COMPLIANCE") else threshold.compliance
            threshold.cve = new_threshold.get("CVE") if new_threshold.get("CVE") is not None else threshold.cve
            threshold.name = new_threshold.get("reason", "Exclusion")
            return threshold

        threshold_pipeline = exclusions_data.get(pipeline_name, {}).get("THRESHOLD", {})
        if threshold_pipeline:
            return set_threshold(threshold_pipeline)

        search_patterns = exclusions_data.get("BY_PATTERN_SEARCH", {})
        
        match_pattern = next(
            (v["THRESHOLD"]
            for pattern, v in search_patterns.items()
            if re.match(pattern, pipeline_name, re.IGNORECASE)),
            None
        )

        return set_threshold(match_pattern) if match_pattern else threshold

    def retries_requests(self, request_func, max_retries, retry_delay):
        for attempt in range(max_retries):
            try:
                return request_func()
            except Exception as e:
                logger.error(f"Error making the request: {e}")
                if attempt < max_retries - 1:
                    logger.warning(f"Retry in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("Maximum number of retries reached, aborting.")
                    raise e
