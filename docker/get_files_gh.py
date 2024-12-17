import requests
import os
import sys
from concurrent.futures import ThreadPoolExecutor

def download_folder_from_github(owner, repository, path, token, download_path):
    url = f"https://api.github.com/repos/{owner}/{repository}/contents/{path}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.raw"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        contents = response.json()
        if isinstance(contents, list):
            # It's a directory
            with ThreadPoolExecutor(max_workers=5) as executor:
                for item in contents:
                    item_path = item['path']
                    if item['type'] == 'file':
                        executor.submit(download_file_from_github, owner, repository, item_path, token, download_path)
                    elif item['type'] == 'dir':
                        new_download_path = os.path.join(download_path, os.path.basename(item_path))
                        os.makedirs(new_download_path, exist_ok=True)
                        executor.submit(download_folder_from_github, owner, repository, item_path, token, new_download_path)
        else:
            print(f"Error: Expected a directory but got a file at {path}")
    else:
        print(f"Error downloading folder. Status code: {response.status_code}")

def download_file_from_github(owner, repository, path, token, download_path="."):
    url = f"https://api.github.com/repos/{owner}/{repository}/contents/{path}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.raw"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        file_name = os.path.basename(path)
        file_path = os.path.join(download_path, file_name)
        with open(file_path, "wb") as file:
            file.write(response.content)
        print(f"File {file_name} downloaded successfully to {file_path}")
    else:
        print(f"Error downloading file. Status code: {response.status_code}")

owner = sys.argv[1]
repository = sys.argv[2]
path = sys.argv[3]
token = sys.argv[4]
download_path = sys.argv[5]

download_folder_from_github(owner, repository, path, token, download_path)