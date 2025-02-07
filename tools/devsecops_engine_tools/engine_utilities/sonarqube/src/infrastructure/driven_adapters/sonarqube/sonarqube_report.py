from devsecops_engine_tools.engine_utilities.utils.utils import (
    Utils
)
from devsecops_engine_tools.engine_utilities.sonarqube.src.domain.model.gateways.sonar_gateway import (
    SonarGateway
)
import os
import re
import requests
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class SonarAdapter(SonarGateway):
    def get_project_keys(self, pipeline_name):
        project_keys = [pipeline_name]
        sonar_scanner_params = os.getenv("SONARQUBE_SCANNER_PARAMS", "")
        pattern = r'"sonar\.scanner\.metadataFilePath":"(.*?)"'
        match_result = re.search(pattern, sonar_scanner_params)
        
        if match_result and match_result.group(1):
            metadata_file_path = match_result.group(1)
            project_key_found = self.parse_project_key(metadata_file_path)
            
            if project_key_found:
                print(f"ProjectKey scanner params: {project_key_found}")
                project_keys = [project_key_found]
        
        return project_keys

    def parse_project_key(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
                print(f"[SQ] Parse Task report file:\n{file_content}")
                if not file_content or len(file_content) <= 0:
                    print("[SQ] Error reading file")
                    logger.warning("[SQ] Error reading file")
                    return None
                try:
                    settings = self.create_task_report_from_string(file_content)
                    return settings.get("projectKey")
                except Exception as err:
                    print(f"[SQ] Parse Task report error: {err}")
                    logger.warning(f"[SQ] Parse Task report error: {err}")
                    return None
        except Exception as err:
            logger.warning(f"[SQ] Error reading file: {str(err)}")
            return None

    def create_task_report_from_string(self, file_content):
        lines = file_content.replace('\r\n', '\n').split('\n')
        settings = {}
        for line in lines:
            split_line = line.split('=')
            if len(split_line) > 1:
                settings[split_line[0]] = '='.join(split_line[1:])
        return settings
    
    def filter_by_sonarqube_tag(self, findings):
        return [finding for finding in findings if "sonarqube" in finding.tags]
    
    def change_finding_status(self, sonar_url, sonar_token, endpoint, data, finding_type, sonar_max_retry):
        try:
            def request_func():
                response = requests.post(
                    f"{sonar_url}{endpoint}",
                    headers={
                        "Authorization": f"Basic {Utils().encode_token_to_base64(sonar_token)}"
                    },
                    data=data
                )
                response.raise_for_status()

                if finding_type == "issue": 
                    info = data["transition"]
                else:
                    resolution_info = ""
                    if data.get("resolution"): resolution_info = f" ({data['resolution']})"

                    info = f"{data['status']}{resolution_info}"

                print(f"The state of the {finding_type} {data[finding_type]} was changed to {info}.")

            Utils().retries_requests(request_func, sonar_max_retry, retry_delay=5)
                
        except Exception as e:
            logger.warning(f"Unable to change the status of {finding_type} {data[finding_type]}. Error: {e}")
            pass

    def get_findings(self, sonar_url, sonar_token, endpoint, params, finding_type, sonar_max_retry):
        findings = []
        try:
            def request_func():
                while True:
                    response = requests.get(
                        f"{sonar_url}{endpoint}",
                        headers={
                            "Authorization": f"Basic {Utils().encode_token_to_base64(sonar_token)}"
                        },
                        params=params
                    )
                    response.raise_for_status()
                    data = response.json()

                    findings.extend(data[finding_type])
                    if len(data[finding_type]) < params["ps"]: break
                    params["p"] = params["p"] + 1
            
            Utils().retries_requests(request_func, sonar_max_retry, 5)

            return findings
        except Exception as e:
            logger.warning(f"It was not possible to obtain the {finding_type}: {str(e)}")
            return []

    def search_finding_by_id(self, issues, issue_id):
        return next((issue for issue in issues if issue["key"] in issue_id), None)