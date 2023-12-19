import subprocess

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.azure.azure_remote_config import (
    AzureRemoteConfig
)

class TrivyScan(ToolGateway):

    def run_tool_container_sca(self, dict_args, token, scan_image):
        remote_config_repo = AzureRemoteConfig().get_remote_config(dict_args)
        images_scanned = []
        
        for image in scan_image:
            repository = image['Repository']
            tag = image['Tag']
            image_name = f"{repository}:{tag}"
            try:
                result = subprocess.run("trivy --format json --quiet image " + image_name , shell=True, capture_output=True, text=True)
                with open(image_name+'_scan_result.json', 'w') as file:
                    file.write(result.stdout)
                images_scanned.append(image_name+"_scan_result.json")
                print("Image "+image['Repository']+" scanned.")
            except subprocess.CalledProcessError as e:
                print("Error during image scan: "+e.stderr)
        
        return images_scanned