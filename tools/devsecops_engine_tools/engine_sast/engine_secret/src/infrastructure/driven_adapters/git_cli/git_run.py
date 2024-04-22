from dataclasses import dataclass
import os
import subprocess
import git
from urllib.parse import quote
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.git_gateway import GitGateway
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

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
                               repository_name):
        try:
            if target_branch not in config_target_branch:
                return []
            base_compact_url = (
            f"https://{collection_uri.rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{quote(team_project)}/_git/"
            f"{repository_name}"
            )
            
            base_compact_url = 'https://grupobancolombia.visualstudio.com/Vicepresidencia%20Servicios%20de%20Tecnolog%C3%ADa/_git/AW1122003_Cliente_Fork'
            url_sin_https = base_compact_url.replace("https://", "")
            url_with_token = f"https://x-access-token:{access_token}@{url_sin_https}"

            ruta_nueva_carpeta = sys_working_dir + '/' + repository_name
            os.makedirs(ruta_nueva_carpeta)
            os.chdir(sys_working_dir)
            subprocess.run(["git", "clone", url_with_token, ruta_nueva_carpeta])
            # subprocess.run(["git", "clone", url_with_token, ruta_nueva_carpeta], capture_output=True, text=True)
            os.chdir(ruta_nueva_carpeta)
            subprocess.run(["git", "branch", "-a"])
            repository = git.Repo(ruta_nueva_carpeta)

            source_branch = source_branch.replace("refs/heads/", "")
            source_branch = 'develop'
            subprocess.run(["git", "checkout", f"origin/{source_branch}"], capture_output=True, text=True)
            if source_branch != None:
                source_branch = 'develop'
                target_branch = 'master'
                diff = repository.git.diff(f"origin/{source_branch}..origin/{target_branch}", name_only=True)
                if diff:
                    diff_files = diff.strip().split("\n")
                print("Pull Requests Associated Files:",len(diff_files))
                return diff_files
        except Exception as e:
            logger.warning(f"Error getting files PullRequest: {e}")
            return []