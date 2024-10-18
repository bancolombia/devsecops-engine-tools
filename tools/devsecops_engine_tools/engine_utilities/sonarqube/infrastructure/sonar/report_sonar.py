from devsecops_engine_tools.engine_utilities.utils.utils import (
    Utils
)
import os
import re
import requests

class SonarAdapter():
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
                print(f"[SQ] Parse Task report file: {file_content}")
                if not file_content or len(file_content) <= 0:
                    print(f"[SQ] Error reading file: {file_content}")
                    return None
                try:
                    settings = self.create_task_report_from_string(file_content)
                    return settings.get('projectKey')
                except Exception as err:
                    print(f"[SQ] Parse Task report error: {err}")
                    return None
        except Exception as err:
            print(f"[SQ] Error reading file: {str(err)}")
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

    def change_issue_transition(self, sonar_url, sonar_token, issue_id, transition):
        endpoint = f"{sonar_url}/api/issues/do_transition"
        try:
            response = requests.post(
                endpoint,
                headers={
                    "Authorization": f"Basic {Utils().encode_token_to_base64(sonar_token)}"
                },
                data={
                    "issue": issue_id,
                    "transition": transition
                }
            )
            response.raise_for_status()
            print(f'The state of the issue {issue_id} was changed.')
        except:
            pass
    
    def get_vulnerabilities(self, sonar_url, sonar_token, project_key):
        endpoint = f"{sonar_url}/api/issues/search"
        try:
            response = requests.get(
                endpoint,
                headers={
                    "Authorization": f"Basic {Utils().encode_token_to_base64(sonar_token)}"
                },
                params={
                    "componentKeys": project_key,
                    "types": "VULNERABILITY",
                    "ps": 500,
                    "s": "CREATION_DATE",
                    "asc": "false"
                }
            )
            response.raise_for_status()
            data = response.json()
            return data["issues"]
        except Exception as e:
            print(f"It was not possible to obtain the vulnerabilities: {str(e)}")
            return []

    def find_issue_by_id(self, issues, issue_id):
        for issue in issues:
            if issue["key"] == issue_id:
                return issue
        return None