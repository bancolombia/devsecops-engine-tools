import requests
import sys
import json

def download_folder_from_azure_devops(organization, project, repository, path, token, download_path):
    print(download_path)
    url = f"https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repository}/items?scopePath={path}&recursionLevel=Full&api-version=7.1"
    headers = {"Authorization": f"Basic {token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        data['CHECKOV']['USE_EXTERNAL_CHECKS_DIR'] = "True"
        content = str(json.dumps(data))
        file_path = "example_remote_config_local/engine_sast/engine_iac/ConfigTool.json"
        with open(file_path, "w") as file:
            file.write(content)
            print(f"File '{file_path}' downloaded successfully.")
    else:
        print(f"Error downloading folder. Status code: {response.status_code}")
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