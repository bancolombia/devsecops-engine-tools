from dataclasses import dataclass
import os
import subprocess
from urllib.parse import quote
from devsecops_engine_tools.engine_utilities.git_cli.model.gateway.git_gateway import GitGateway

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

@dataclass
class GitRun(GitGateway):

    def get_files_pull_request(self,
                               sys_working_dir,
                               target_branch,
                               source_branch,
                               message_info_engine_secret
                               ):
        try:
            source_branch = source_branch.replace("refs/heads/", "")
            os.chdir(sys_working_dir)
            subprocess.run(['git', 'checkout', '-b', source_branch, f'origin/{source_branch}'], text=True, capture_output=True, check=True)    
            env = os.environ.copy()
            env["GIT_COMMITTER_NAME"] = "Your Name"
            env["GIT_COMMITTER_EMAIL"] = "your.email@example.com"
            env["GIT_AUTHOR_NAME"] = "Your Name"
            env["GIT_AUTHOR_EMAIL"] = "your.email@example.com"
            command = ["git", "rebase", f"origin/{target_branch}", "-X", "theirs"]
            subprocess.run(command, env=env, text=True, capture_output=True)

            diff = subprocess.run(['git', 'diff', f'origin/{target_branch}..{source_branch}', '--name-only'], capture_output=True, text=True)
            if diff.returncode == 0:
                diff_files = diff.stdout.strip().split("\n")
                print("Pull Requests Associated Files:",diff_files)
                return diff_files
        except subprocess.CalledProcessError as e:
            raise Exception(f"Error in pipeline configuration, {message_info_engine_secret}") from e
        except Exception as e:
            logger.warning(f"Error getting files PullRequest: {e}")
            return []