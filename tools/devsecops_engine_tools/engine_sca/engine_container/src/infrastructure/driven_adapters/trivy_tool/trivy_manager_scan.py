import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway
)

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned
)


class TrivyScan(ToolGateway):

    def install_trivy(self,version):
        try:
            subprocess.run(['which', 'trivy'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("trivy está instalado.")
        except subprocess.CalledProcessError:
            print("Intentando instalar trivy.")
            try:
                command1 = ['wget', 'https://github.com/aquasecurity/trivy/releases/download/v'+version+'/trivy_'+version+'_Linux-64bit.deb']
                subprocess.run(command1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                command2 = ['sudo', 'dpkg', '-i', 'trivy_'+version+'_Linux-64bit.deb']
                subprocess.run(command2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                # print("trivy instalado.")
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error al instalar trivy: {error}")

    def run_tool_container_sca(self, remoteconfig, token, scan_image):
        try:
            trivy_version = remoteconfig['TRIVY']['TRIVY_VERSION']
            self.install_trivy(trivy_version)
            pattern = remoteconfig['REGEX_EXPRESSION_PROJECTS']
            previosly_scanned = ImagesScanned()
            file_name = 'scanned_images.txt'
            images_scanned = []
            for image in scan_image:
                if re.match(pattern, image['Repository'].upper()):
                    repository = image['Repository']
                    tag = image['Tag']
                    image_name = f"{repository}:{tag}"
                    if (image_name+'_scan_result.json') in previosly_scanned.get_images_already_scanned(file_name):
                        print(f"The image {image_name} has already been scan previously.")
                    else:
                        try:
                            command1 = ['trivy', 'image', '--download-db-only']
                            subprocess.run(command1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            command2 = ['trivy', '--scanners', 'vuln', '-f', 'json', '-o', image_name+'_scan_result.json']
                            command2.extend(['--quiet', 'image', image_name])
                            subprocess.run(command2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            images_scanned.append(image_name+"_scan_result.json")
                            with open(file_name, 'a') as file:
                                file.write(image_name+'_scan_result.json\n')
                        except subprocess.CalledProcessError as e:
                            print("Error scanning "+image_name+" image: "+e.stderr)

            return images_scanned

        except Exception as ex:
            print(f"Could not get Azure Remote Config: {ex}")
