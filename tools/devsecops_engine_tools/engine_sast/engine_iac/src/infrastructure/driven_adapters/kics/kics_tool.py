import subprocess
import requests
import zipfile
import os
import json
import glob
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_deserealizator import (
    KicsDeserealizator
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KicsTool(ToolGateway):

    def run_tool(
            self, config_tool: ConfigTool, folders_to_scan, environment, container_platform, secret_tool
    ):

        zip_file_name = self.download_latest_zip()
        self.unzip_repo(zip_file_name)
        directory = self.generate_binary()

        self.execute_kics(folders_to_scan, directory)

        filtered_results = self.get_findings()

        kics_deserealizator = KicsDeserealizator()
        finding_list = kics_deserealizator.get_list_finding(filtered_results)

        generate_file = "/home/user/documents/my_file.json"

        return finding_list, generate_file

    def download_latest_zip(self):

        owner = "Checkmarx"
        repository_name = "kics"
        url = f"https://api.github.com/repos/{owner}/{repository_name}/releases/latest"

        response = requests.get(url)

        data = json.loads(response.text)

        zip_url = data["zipball_url"]

        zip_response = requests.get(zip_url)

        zip_file_name = f"{repository_name}_latest.zip"
        with open(zip_file_name, "wb") as file:
            file.write(zip_response.content)

        return zip_file_name

    def unzip_repo(self, zip_filename):

        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall()

        os.remove(zip_filename)

    def generate_binary(self):

        directories = glob.glob('Checkmarx-kics-*')
        directory = directories[0]

        os.chdir(f"./{directory}")

        subprocess.run(['go', 'mod', 'vendor'], capture_output=True, text=True)
        subprocess.run("go build -o ./bin/kics cmd/console/main.go", capture_output=True, text=True)

        os.chdir('..')

        return directory

    def execute_kics(self, folders_to_scan, directory):
        try:
            for folder in folders_to_scan:
                command = f"./{directory}/bin/kics scan -p {folder} -q ./{directory}/assets --report-formats json -o ./results"
                subprocess.run(command, capture_output=True)

        except Exception as ex:
            logger.error(f"Error executing Kics: {ex}")

    def get_findings(self):
        with open('./results/results.json') as f:
            data = json.load(f)

        filtered_results = []
        for query in data.get("queries", []):
            severity = query.get("severity", "").upper()
            if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                description = query.get("description", "")
                query_id = query.get("query_id", "")
                for file in query.get("files", []):
                    file_name = file.get("file_name", "")
                    filtered_results.append({
                        "severity": severity,
                        "description": description,
                        "file_name": file_name,
                        "id": query_id
                    })
        return filtered_results
