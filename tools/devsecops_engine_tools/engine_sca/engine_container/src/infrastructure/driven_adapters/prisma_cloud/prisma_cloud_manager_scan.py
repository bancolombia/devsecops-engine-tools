import stat
import requests
import os
import subprocess
import logging
import re
import base64
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway)


class PrismaCloudManagerScan(ToolGateway):

    def download_twistcli(self, file_path, prisma_access_key, prisma_secret_key, prisma_console_url):
        
        """
        Download the Prisma Cloud twistcli plugin and save it to the file system.
        """
        url = f"{prisma_console_url}/api/v1/util/twistcli"  # path to console of the Tenant
        credentials = base64.b64encode(f"{prisma_access_key}:{prisma_secret_key}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            with open(file_path, "wb") as file:
                file.write(response.content)
            os.chmod(file_path, stat.S_IRWXU)
            logging.info(f"twistcli downloaded and saved to: {file_path}")
            return 0
        except Exception as e:
            raise ValueError(f"Error downloading twistcli: {e}")
                     
    def run_tool_container_sca(self, remoteconfig, prisma_secret_key, scan_image):
        try:
                        
            file_path = os.path.join(os.getcwd(), remoteconfig['PRISMA_CLOUD']['TWISTCLI_PATH'])

            if not os.path.exists(file_path):
                self.download_twistcli(file_path, remoteconfig['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], prisma_secret_key,
                                        remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'])
            
            previosly_scanned = ImagesScanned()
            file_name = 'scanned_images.txt'
            images_scanned = []
            
            for image in scan_image:
                repository = image['Repository']
                tag = image['Tag']
                image_name = f"{repository}:{tag}"

                # Check if the image has already been scanned
                if (image_name+'_scan_result.json') in previosly_scanned.get_images_already_scanned(file_name):
                    print(f"The image {image_name} has already been scanned previously.")
                else:
                    pattern = remoteconfig['REGEX_EXPRESSION_PROJECTS']
                    if re.match(pattern, repository.upper()):
                        command = (file_path, "images", "scan", "--address", remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'],
                                   "--user", remoteconfig['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], "--password", prisma_secret_key,
                                   image_name, "--output-file", image_name + '_scan_result.json', "--details")
                        try:
                            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                    text=True)
                            images_scanned.append(image_name+'_scan_result.json')
                            with open(file_name, 'a') as file:
                                file.write(image_name+'_scan_result.json\n')
                        except subprocess.CalledProcessError as e:
                            print(f"Error during image scan of {repository}: {e.stderr}")


            return images_scanned

        except Exception as ex:
            print(f"An overall error occurred: {ex}")

        return 0