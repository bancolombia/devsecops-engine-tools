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
  
       
    def download_twistcli(self,file_path,prisma_access_key, prisma_secret_key, prisma_console_url):
        
        """
        Descarga el plugin de twistcli de Prisma Cloud y lo guarda en el sistema de archivos.
        """
        url = f"{prisma_console_url}/api/v1/util/twistcli"  # path to console del Tenant
        credentials = base64.b64encode(f"{prisma_access_key}:{prisma_secret_key}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}"}

        try:
            response = requests.get(url, headers=headers,verify=False)
            response.raise_for_status()
            
            with open(file_path, "wb") as file:
                file.write(response.content)
            os.chmod(file_path, 0o755)
            logging.info(f"twistcli descargado y guardado en: {file_path}")
            return 0
        except Exception as e:
            raise ValueError(f"Error al descargar twistcli: {e}")
     
         
    def run_tool_container_sca(self, dict_args, prisma_secret_key, scan_image):
        try:
            token = os.environ.get("TOKEN_PRISMA", "")  # Cambiar por token secret manager
            remote_config_repo = AzureRemoteConfig().get_remote_config(dict_args)
            file_path = os.path.join(os.getcwd(), remote_config_repo['PRISMA_CLOUD']['TWISTCLI_PATH'])

            self.download_twistcli(file_path, remote_config_repo['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], token,
                                    remote_config_repo['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'])

            for image in scan_image:
                
                pattern = remote_config_repo['PRISMA_CLOUD']['REGEX_EXPRESSION_PROJECTS']
                print(pattern)
                #pattern= r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS[A-Z]{3})\\d+)_"
                print(f"Patron de busqueda: {pattern}")
                if re.match(pattern, image['Repository'].upper()):
                    repository = image['Repository']
                    tag = image['Tag']
                    image_name = f"{repository}:{tag}"
                    print(f"Imagen a escanear: {image_name}")
                    command = (file_path, "images", "scan", "--address", remote_config_repo['PRISMA_CLOUD']['PRISMA_CONSOLE_URL'],
                               "--user", remote_config_repo['PRISMA_CLOUD']['PRISMA_ACCESS_KEY'], "--password", token,
                               image_name, "--output-file", image_name+'_scan_result.json', "--details")
                    try:
                        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True)
                        print(result.stdout)
                        # return result.stdout
                    except subprocess.CalledProcessError as e:
                        print(f"Error durante el escaneo de la imagen: {e.stderr}")
                        # raise ValueError(f"Error durante el escaneo de la imagen: {e.stderr}")
                else:
                    print(f"No se escanea la imagen {image['Repository']}")

        except Exception as ex:
            print(f"Se produjo un error general: {ex}")
            # raise ValueError(f"Se produjo un error general: {ex}")

        finally:
            print("Finalizando el escaneo.")

        return 0
    
   