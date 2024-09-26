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
                               config_target_branch,
                               source_branch,
                               access_token,
                               collection_uri,
                               team_project,
                               repository_name,
                               repository_provider):
        try:
            if repository_provider == 'GitHub' or target_branch not in config_target_branch:
                os.chdir(sys_working_dir)
                subprocess.run(['git', 'checkout', '-b', source_branch, f'origin/{source_branch}'], capture_output=True, text=True)
                env = os.environ.copy()
                env["GIT_COMMITTER_NAME"] = "Your Name"
                env["GIT_COMMITTER_EMAIL"] = "your.email@example.com"
                env["GIT_AUTHOR_NAME"] = "Your Name"
                env["GIT_AUTHOR_EMAIL"] = "your.email@example.com"
                command = ["git", "rebase", f"origin/{target_branch}", "-X", "theirs"]
                subprocess.run(command, env=env, capture_output=True, text=True)

                diff = subprocess.run(['git', 'diff', f'origin/{target_branch}..{source_branch}', '--name-only'], capture_output=True, text=True)
                if diff.returncode == 0:
                    diff_files = diff.stdout.strip().split("\n")
                    print("Pull Requests Associated Files:",diff_files)
                    return diff_files
                return []
            base_compact_url = (
            f"https://{collection_uri.rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{quote(team_project)}/_git/"
            f"{repository_name}"
            )
            
            url_without_https = base_compact_url.replace("https://", "")
            url_with_token = f"https://x-access-token:{access_token}@{url_without_https}"

            path_new_folder = sys_working_dir + '/' + repository_name
            
            if os.path.exists(path_new_folder):
                logger.warning(f"Error: folder {repository_name} already exist")
                return []
            os.makedirs(path_new_folder)
            os.chdir(sys_working_dir)
            subprocess.run(["git", "clone", "--branch", target_branch, url_with_token, path_new_folder], capture_output=True, text=True)
            os.chdir(path_new_folder)
 
            source_branch = source_branch.replace("refs/heads/", "")
            subprocess.run(["git", "checkout", "-b", source_branch], capture_output=True, text=True)
            command = ["git","-c","user.email=you@example.com","-c","user.name=Your Name","pull","--rebase","-X", "theirs","--no-edit","origin",source_branch]
            subprocess.run(command, capture_output=True, text=True)

            if source_branch != None:
                diff = subprocess.run(['git', 'diff', '--name-only', f'{source_branch}..{target_branch}'], capture_output=True, text=True)
                if diff:
                    diff_files = diff.stdout.strip().split("\n")
                print("Pull Requests Associated Files:",len(diff_files))
                return diff_files
        except Exception as e:
            logger.warning(f"Error getting files PullRequest: {e}")
            return []