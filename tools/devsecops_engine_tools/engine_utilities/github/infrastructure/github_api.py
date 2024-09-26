import requests
import zipfile
import json
from github import Github
from devsecops_engine_tools.engine_utilities.utils.api_error import ApiError


class GithubApi:
    def __init__(
            self,
            personal_access_token: str = ""
    ):
        self.__personal_access_token = personal_access_token

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

    def download_latest_release_assets(
        self, owner, repository, download_path="."
    ):
        url = f"https://api.github.com/repos/{owner}/{repository}/releases/latest"

        headers = {"Authorization": f"token {self.__personal_access_token}"}

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

    def get_github_connection(self):
        git_client = Github(self.__personal_access_token)

        return git_client

    def get_remote_json_config(self, git_client: Github, owner, repository, path):
        try:
            repo = git_client.get_repo(f"{owner}/{repository}")
            file_content = repo.get_contents(path)
            data = file_content.decoded_content.decode()
            content_json = json.loads(data)

            return content_json
        except Exception as e:
            raise ApiError("Error getting remote github configuration file: " + str(e))
