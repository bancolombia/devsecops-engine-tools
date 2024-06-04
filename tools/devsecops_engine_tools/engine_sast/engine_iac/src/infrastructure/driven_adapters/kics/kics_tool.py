import subprocess
import requests
import zipfile
import os
import json
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
        self.download_repo(folders_to_scan)
        filtered_results = self.get_findings()

        kics_deserealizator = KicsDeserealizator()
        finding_list = kics_deserealizator.get_list_finding(filtered_results)

        generate_file = "/home/user/documents/my_file.json"

        return finding_list, generate_file

    def download_repo(self, folders_to_scan):

        owner = "Checkmarx"
        repository_name = "kics"

        url = f"https://github.com/{owner}/{repository_name}/archive/refs/heads/master.zip"

        response = requests.get(url)

        if response.status_code == 200:
            zip_filnename = f"{repository_name}.zip"

            with open(zip_filnename, "wb") as file:
                file.write(response.content)

            self.unzip_repo(zip_filnename, folders_to_scan)

    def unzip_repo(self, zip_filename, folders_to_scan):

        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall()

        os.remove(zip_filename)

        self.generate_binary(folders_to_scan)

    def generate_binary(self, folders_to_scan):

        os.chdir('./kics-master')

        subprocess.run(['go', 'mod', 'vendor'], capture_output=True, text=True)
        subprocess.run("go build -o ./bin/kics cmd/console/main.go", capture_output=True, text=True)

        os.chdir('..')
        self.execute_kics(folders_to_scan)

    def execute_kics(self, folders_to_scan):
        try:
            for folder in folders_to_scan:
                command = f"./kics-master/bin/kics scan -p {folder} -q ./kics-master/assets --report-formats json -o ./results"
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
                for file in query.get("files", []):
                    file_name = file.get("file_name", "")
                    filtered_results.append({
                        "severity": severity,
                        "description": description,
                        "file_name": file_name
                    })
        return filtered_results

