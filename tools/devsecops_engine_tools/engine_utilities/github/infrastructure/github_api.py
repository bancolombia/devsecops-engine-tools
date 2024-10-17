import requests
import zipfile
import json
import jwt
import time
from github import Github, GithubIntegration
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

    def generate_jwt(self):
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + (10 * 60),
            "iss": self.app_id,
        }
        token = jwt.encode(payload, self.personal_access_token, algorithm="RS256")
        return token

    def get_installation_access_token(self):
        jwt_token = self.generate_jwt()
        headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"}
        url = f"https://api.github.com/app/installations/{self.installation_id}/access_tokens"
        response = requests.post(url, headers=headers)

        if response.status_code == 201:
            token_data = response.json()
            return token_data["token"]
        else:
            raise Exception(f"Failed to get installation access token: {response.status_code} {response.text}")

    def download_latest_release_assets(
        self, owner, repository, download_path="."
    ):
        installation_token = self.get_installation_access_token()
        url = f"https://api.github.com/repos/{owner}/{repository}/releases/latest"

        headers = {"Authorization": f"token {installation_token}", "Accept": "application/vnd.github+json"}

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
