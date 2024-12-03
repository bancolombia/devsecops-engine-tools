import requests
import os
import sys

def download_folder_from_azure_devops(organization, project, repository, path, token, download_path):
    url = f"https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository}/items?scopePath={path}&recursionLevel=Full&api-version=7.1"
    headers = {"Authorization": f"Basic {token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        contents = response.json()['value']
        if isinstance(contents, list):
            for item in contents:
                item_path = item['path']
                if item['gitObjectType'] == 'blob':
                    download_file_from_azure_devops(organization, project, repository, item_path, token, download_path)
                elif item['gitObjectType'] == 'tree':
                    new_download_path = os.path.join(download_path, os.path.relpath(item_path, path))
                    os.makedirs(new_download_path, exist_ok=True)
                    download_folder_from_azure_devops(organization, project, repository, item_path, token, new_download_path)
        else:
            print(f"Error: Expected a directory but got a file at {path}")
    else:
        print(f"Error downloading folder. Status code: {response.status_code}")
        print(response.text)

def download_file_from_azure_devops(organization, project, repository, path, token, download_path="."):
    url = f"https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository}/items?path={path}&api-version=7.1"
    headers = {"Authorization": f"Basic {token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        file_name = os.path.basename(path)
        file_path = os.path.join(download_path, file_name)
        with open(file_path, "wb") as file:
            file.write(response.content)
        print(f"File {file_name} downloaded successfully to {file_path}")
    else:
        print(f"Error downloading file. Status code: {response.status_code}")
        print(response.text)

# Example usage
# organization = "your-organization"
# project = "your-project"
# repository = "your-repository"
# path = "path/to/your/folder"
# token = "your-personal-access-token"
# download_path = "."

if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Usage: python get_files_ad.py <organization> <project> <repository> <path> <token> <download_path>")
        sys.exit(1)

    organization = sys.argv[1]
    project = sys.argv[2]
    repository = sys.argv[3]
    path = sys.argv[4] # path to download
    token = sys.argv[5] # your personal access token
    download_path = sys.argv[6]

    download_folder_from_azure_devops(organization, project, repository, path, token, download_path)