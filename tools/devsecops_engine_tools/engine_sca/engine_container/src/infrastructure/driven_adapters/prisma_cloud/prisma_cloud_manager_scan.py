import requests
import os
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import ToolGateway
import subprocess
import logging
import re
import base64

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.azure.azure_remote_config import (
    AzureRemoteConfig
)


class PrismaCloudManagerScan(ToolGateway):
  
       
    def download_twistcli(self, file_path, prisma_access_key, prisma_secret_key, prisma_console_url):
        
        """
        Download the Prisma Cloud twistcli plugin and save it to the file system.
        """
        url = f"{prisma_console_url}/api/v1/util/twistcli"  # path to console of the Tenant
        credentials = base64.b64encode(f"{prisma_access_key}:{prisma_secret_key}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}"}

        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            
            with open(file_path, "wb") as file:
                file.write(response.content)
            os.chmod(file_path, 0o755)
            logging.info(f"twistcli downloaded and saved to: {file_path}")
            return 0
        except Exception as e:
            raise ValueError(f"Error downloading twistcli: {e}")
     
     
    def run_tool_container_sca(self, remoteconfig, prisma_secret_key, scan_image):
        try:
            token = os.environ.get("TOKEN_PRISMA", "")  # Change to secret manager token
            
            file_path = os.path.join(os.getcwd(), remoteconfig['PRISMA_CLOUD']['TWISTCLI_PATH'])

            if not os.path.exists(file_path):
                self.download_twistcli(file_path, remoteconfig['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], token,
                                        remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'])
            
            # Path to the scanned images file
            scanned_images_file = os.path.join(os.getcwd(), 'scanned_images.txt')

            # Check if the file exists; if not, create it
            if not os.path.exists(scanned_images_file):
                open(scanned_images_file, 'w').close()

            # Read previously scanned images from the file
            with open(scanned_images_file, 'r') as file:
                images_scanned = file.read().splitlines()

            images_to_scan = []

            for image in scan_image:
                repository = image['Repository']
                tag = image['Tag']
                image_name = f"{repository}:{tag}"

                # Check if the image has already been scanned
                if image_name in images_scanned:
                    print(f"The image {image_name} has already been scanned previously.")
                else:
                    pattern = remoteconfig['PRISMA_CLOUD']['REGEX_EXPRESSION_PROJECTS']
                    if re.match(pattern, repository.upper()):
                        command = (file_path, "images", "scan", "--address", remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'],
                                   "--user", remoteconfig['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], "--password", token,
                                   image_name, "--output-file", image_name + '_scan_result.json', "--details")
                        try:
                            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                    text=True)
                            images_scanned.append(image_name)
                            print(f"Image {repository} scanned")
                            images_to_scan.append(image_name + '_scan_result.json')
                        except subprocess.CalledProcessError as e:
                            print(f"Error during image scan of {repository}: {e.stderr}")
                    else:
                        print(f"The image {repository} is not scanned")

            # Save the scanned images to the file
            with open(scanned_images_file, 'a') as file:
                for scanned_image in images_scanned:
                    file.write(scanned_image + '\n')

            return images_to_scan

        except Exception as ex:
            print(f"An overall error occurred: {ex}")

        return 0