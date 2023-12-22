import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway
)

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned
)


class TrivyScan(ToolGateway):

    def run_tool_container_sca(self, remoteconfig, token, scan_image):
        
        try:
            pattern = remoteconfig['PRISMA_CLOUD']['REGEX_EXPRESSION_PROJECTS']
            previosly_scanned = ImagesScanned()
            file_name = 'scanned_images.txt'
            images_scanned = []
            for image in scan_image:
                if re.match(pattern, image['Repository'].upper()):
                # if True:
                    repository = image['Repository']
                    tag = image['Tag']
                    image_name = f"{repository}:{tag}"
                    if (image_name+'_scan_result.json') in previosly_scanned.get_images_already_scanned(file_name):
                        print(f"The image {image_name} has already been scan previously.")
                    else:
                        try:
                            result = subprocess.run("trivy --scanners vuln --format json --quiet image " + image_name , shell=True, capture_output=True, text=True)
                            with open(image_name+'_scan_result.json', 'w') as file:
                                file.write(result.stdout)
                            images_scanned.append(image_name+"_scan_result.json")
                            print("Image "+repository+" scanned.")
                            with open(file_name, 'a') as file:
                                file.write(image_name+'_scan_result.json\n')
                        except subprocess.CalledProcessError as e:
                            print("Error scanning "+repository+" image: "+e.stderr)
            
            return images_scanned
        
        except Exception as ex:
            print(f"Could not get Azure Remote Config: {ex}")
        