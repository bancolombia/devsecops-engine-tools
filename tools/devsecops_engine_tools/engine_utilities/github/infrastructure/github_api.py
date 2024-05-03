import requests
import zipfile


class GithubApi:
    def __init__(
        self,
        token: str = ""
    ):
        self.token = token

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

    def download_latest_release_assets(
        self, owner, repository, download_path="."
    ):
        url = f"https://api.github.com/repos/{owner}/{repository}/releases/latest"

        headers = {"Authorization": f"token {self.token}"}

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
