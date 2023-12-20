import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.azure.azure_remote_config import (
    AzureRemoteConfig
)

class TrivyScan(ToolGateway):

    def run_tool_container_sca(self, dict_args, token, scan_image):
        
        try:
            remote_config_repo = AzureRemoteConfig().get_remote_config(dict_args)
            images_scanned = []
            for image in scan_image:
                pattern = remote_config_repo['PRISMA_CLOUD']['REGEX_EXPRESSION_PROJECTS']
                if re.match(pattern, image['Repository'].upper()):
                    repository = image['Repository']
                    tag = image['Tag']
                    image_name = f"{repository}:{tag}"
                    try:
                        result = subprocess.run("trivy --scanners vuln --format json --quiet image " + image_name , shell=True, capture_output=True, text=True)
                        with open(image_name+'_scan_result.json', 'w') as file:
                            file.write(result.stdout)
                        images_scanned.append(image_name+"_scan_result.json")
                        print("Image "+repository+" scanned.")
                    except subprocess.CalledProcessError as e:
                        print("Error scanning "+repository+" image: "+e.stderr)
            
            return images_scanned
        
        except Exception as ex:
            print(f"Could not get Azure Remote Config: {ex}")
        