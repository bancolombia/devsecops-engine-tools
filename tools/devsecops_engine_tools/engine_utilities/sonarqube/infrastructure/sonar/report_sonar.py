import os
import re

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