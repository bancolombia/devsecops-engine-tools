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
        if target_branch not in config_target_branch:             
            return []

        source_branch = self.get_git_source_branch(sys_working_dir)
        
        command = f"cd {sys_working_dir} && git diff --name-only {source_branch.strip()}..origin/{target_branch}"
        result = subprocess.run(command, capture_output=True, shell=True)
        print(result)
        if result.returncode != 0:
            logger.warning(f"Error getting pullrequest files: {result.stderr}")
            return []
        files_pr = result.stdout.decode('utf-8').strip().splitlines()
        print(files_pr)
        return files_pr

    def get_git_source_branch(self, sys_working_dir):
        command = f"cd {sys_working_dir} && git fetch && git branch -a"
        result = subprocess.run(command, capture_output=True, shell=True)
        print(result)
        if result.returncode != 0:
            logger.warning(f"Error getting branches: {result.stderr}")
            return []
        branches = result.stdout.decode('utf-8').strip().splitlines()               
        regex = r'remotes/(.*)'
        return re.sub(regex, r'\1', branches[1])