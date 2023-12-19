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
     
         
    def run_tool_container_sca(self, dict_args, prisma_secret_key, scan_image):
        try:
            token = os.environ.get("TOKEN_PRISMA", "")  # Change to secret manager token
            remote_config_repo = AzureRemoteConfig().get_remote_config(dict_args)
            file_path = os.path.join(os.getcwd(), remote_config_repo['PRISMA_CLOUD']['TWISTCLI_PATH'])

            if not os.path.exists(file_path):
                self.download_twistcli(file_path, remote_config_repo['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], token,
                                        remote_config_repo['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'])
            images_scanned = []
            for image in scan_image:
                
                pattern = remote_config_repo['PRISMA_CLOUD']['REGEX_EXPRESSION_PROJECTS']
                #print(f"Search pattern: {pattern}")
                if re.match(pattern, image['Repository'].upper()):
                    repository = image['Repository']
                    tag = image['Tag']
                    image_name = f"{repository}:{tag}"
                    #print(f"Image to scan: {image_name}")
                    command = (file_path, "images", "scan", "--address", remote_config_repo['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'],
                               "--user", remote_config_repo['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], "--password", token,
                               image_name, "--output-file", image_name+'_scan_result.json', "--details")
                    try:
                        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True)
                        #print(result.stdout)
                        images_scanned.append(image_name+'_scan_result.json')
                        print(f"Image {image['Repository']} scanned")
                    except subprocess.CalledProcessError as e:
                        print(f"Error during image scan: {e.stderr}")
                        # raise ValueError(f"Error during image scan: {e.stderr}")
                else:
                    print(f"Image {image['Repository']} is not scanned")
            
            return images_scanned

        except Exception as ex:
            print(f"An overall error occurred: {ex}")
            # raise ValueError(f"An overall error occurred: {ex}")

        return 0
