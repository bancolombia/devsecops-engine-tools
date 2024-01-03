import subprocess
import json
import re
import os

class Nuclei:
    """A class that wraps the nuclei scanner functionality"""

    def __init__(self, taget_config=None, data_config_cli=None):
        """Initialize the class with the data from the config file and the cli"""
        self.taget_config = taget_config
        self.data_config_cli = data_config_cli

    def nuclei(self, url, templates=None, cookie=None, other_flags=None):
        """Interact with nuclei's core application"""

        if (templates is not None) and cookie is not None:
            template = str(templates).replace("[", "").replace("]", "").replace("'", "")
            result = subprocess.run(
                f'nuclei -duc -u {url} -ud {templates} -H "Cookie: {cookie}" -ni -dc -je result.json {other_flags} -debug',
                shell=True,
                capture_output=True,
            )
        elif templates is not None:
                result = subprocess.run(
                f'nuclei -duc -u {url} -ud {templates} -H "Authorization: Bearer {self.data_config_cli["access_token"]}" -ni -dc -je result.json {other_flags} -debug',
                shell=True,
                capture_output=True,
            )
        file_path = "result.json"
        with open(file_path, 'r') as f:
            json_response = json.load(f)
        return json_response
