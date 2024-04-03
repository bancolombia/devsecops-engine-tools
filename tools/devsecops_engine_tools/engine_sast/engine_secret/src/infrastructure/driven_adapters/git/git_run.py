from dataclasses import dataclass
import re
import subprocess
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway import GitGateway
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

@dataclass
class GitRun(GitGateway):

    def get_files_pull_request(self, sys_working_dir, target_branch, config_target_branch):
        try:
            files_pr = []
            if target_branch in config_target_branch:             
                command = f"cd {sys_working_dir} && git fetch && git branch -a"
                result = subprocess.run(command, capture_output=True, shell=True)
                print(result)
                branches = result.stdout.decode('utf-8').strip().splitlines()               
                regex = r'remotes/(.*)'
                branches_modify = re.sub(regex, r'\1', branches[1])

                command = f"cd {sys_working_dir} && git diff --name-only {branches_modify.strip()}..origin/{target_branch}"
                result = subprocess.run(command, capture_output=True, shell=True)
                print(result)
                files_pr = result.stdout.decode('utf-8').strip().splitlines()
                print(files_pr)
            return files_pr
        except Exception as e:
            logger.warning(f"Error getting variable {str(e)}")