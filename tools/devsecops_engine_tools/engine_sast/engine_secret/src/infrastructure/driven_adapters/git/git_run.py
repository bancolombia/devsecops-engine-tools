from dataclasses import dataclass
import os
from git import Repo
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway import GitGateway
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

@dataclass
class GitRun(GitGateway):

    def get_files_pull_request(self, sys_working_dir, target_branch, config_target_branch, source_branch):
        try:
            if target_branch not in config_target_branch:
                return []
            os.chdir(sys_working_dir)
            repository = Repo(sys_working_dir)
            source_branch = self.get_git_source_branch(repository, source_branch)
            diff = repository.git.diff(f"origin/{source_branch}..origin/{target_branch}", name_only=True)
            if diff:
                diff_files = diff.strip().split("\n")
            print("Pull Requests Files:",diff_files)
            return diff_files
        except Exception as e:
            logger.warning(f"Error getting files PullRequest: {e}")
    
    def get_git_source_branch(self, repository, source_branch):
        try:            
            remote_branches = repository.remotes.origin.fetch()
            source_branch = source_branch.replace("refs/heads/", "")
            print("remote_branches", [i.name for i in remote_branches])
            return source_branch
        except Exception as e:
            logger.warning(f"Error getting branches: {e}")