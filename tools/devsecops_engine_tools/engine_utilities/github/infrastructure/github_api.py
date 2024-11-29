import requests
import zipfile
import json
from github import Github, GithubIntegration
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


class GithubApi:

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)
    
    def get_installation_access_token(self,private_key,app_id,instalation_id):
        if private_key:
            private_key = private_key.replace("\\n", "\n")
        integration = GithubIntegration(app_id, private_key)
        access_token = integration.get_access_token(instalation_id)
        return access_token.token

    def download_latest_release_assets(
        self, owner, repository, token, download_path=".",
    ):               
        url = f"https://api.github.com/repos/{owner}/{repository}/releases/latest"
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            latest_release = response.json()
            assets = latest_release["assets"]

            for asset in assets:
                asset_url = asset["url"]
                asset_name = asset["name"]
                headers.update({"Accept": "application/octet-stream"})
                response = requests.get(asset_url, headers=headers, stream=True)
                if response.status_code == 200:
                    with open(f"{download_path}/{asset_name}", "wb") as file:
                        for chunk in response.iter_content(chunk_size=8192):
                            file.write(chunk)
                    self.unzip_file(f"{download_path}/{asset_name}", download_path)
                else:
                    print(
                        f"Error downloading asset {asset_name}. status code: {response.status_code}"
                    )
        else:
            print(
                f"Error getting the assets of the last release. Status code: {response.status_code}"
            )

    def get_github_connection(self,personal_access_token):
        git_client = Github(personal_access_token)
        return git_client

    def get_remote_json_config(self, git_client: Github, owner, repository, path, branch=""):
        try:
            repo = git_client.get_repo(f"{owner}/{repository}")

            if branch: file_content = repo.get_contents(path, ref=branch)
            else: file_content = repo.get_contents(path)

            data = file_content.decoded_content.decode()
            content_json = json.loads(data)

            return content_json
        except Exception as e:
            raise ApiError("Error getting remote github configuration file: " + str(e))