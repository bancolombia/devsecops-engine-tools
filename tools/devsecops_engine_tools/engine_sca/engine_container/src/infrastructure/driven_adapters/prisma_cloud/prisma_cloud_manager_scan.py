import requests
import os
import subprocess
import time
import base64
import json
from typing import List
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import (
    ContextContainer,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils import download_twistcli

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class PrismaCloudManagerScan(ToolGateway):
    def download_twistcli(self, file_path, prisma_key, prisma_console_url, prisma_api_version) -> int:
        """
        Método de instancia separado (lo que usan los tests),
        delega en el util compat 'basic' para no romper aserciones.
        """
        return download_twistcli(file_path, prisma_key, prisma_console_url, prisma_api_version)
    def scan_image(
        self, file_path, image_name, result_file, remoteconfig, prisma_key, docker_address, is_compressed_file
    ):
        prisma_config = remoteconfig.get("PRISMA_CLOUD", {})
        max_attempts_normal = int(prisma_config.get("SCAN_RETRIES", 1))
        retry_delay_normal = float(prisma_config.get("SCAN_RETRY_DELAY_SECONDS", 0))
        max_attempts_tar = int(prisma_config.get("SCAN_RETRIES_TAR", 1))
        retry_delay_tar = float(prisma_config.get("SCAN_RETRY_DELAY_TAR_SECONDS", 0))
        if max_attempts_tar < 1:
            max_attempts_tar = 1

        base_command = [
            file_path,
            "images",
            "scan",
            "--address",
            remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            "--user",
            self._split_prisma_token(prisma_key)[0],
            "--password",
            self._split_prisma_token(prisma_key)[1],
        ]

        if docker_address:
            base_command.extend(["--docker-address", docker_address])

        base_command.extend(["--output-file", result_file, "--details"])

        # First attempt: normal scan (single try, no retries)
        command = base_command + [image_name]
        if is_compressed_file:
           command = base_command + ["--tarball", image_name]
        if self._execute_scan(command, image_name, max_attempts_normal, retry_delay_normal):
            return result_file

        # Tarball fallback (Linux only) with retries
        tarball_path = f"/tmp/{image_name.replace('/', '_').replace(':', '_')}.tar"
        logger.warning(
            "Normal scan failed for %s, attempting tarball fallback at %s",
            image_name,
            tarball_path,
        )
        try:
            subprocess.run(
                ["docker", "save", "-o", tarball_path, image_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            logger.info("Image %s saved as tarball at %s", image_name, tarball_path)
            tarball_command = base_command + ["--tarball", tarball_path]
            if self._execute_scan(tarball_command, image_name, max_attempts_tar, retry_delay_tar):
                return result_file
        except subprocess.CalledProcessError as e:
            logger.error(
                "Error saving image %s as tarball: %s", image_name, e.stderr
            )
        finally:
            if os.path.exists(tarball_path):
                os.remove(tarball_path)
                logger.info("Cleaned up tarball %s", tarball_path)

        return None

    def _execute_scan(self, command, image_name, max_attempts, retry_delay):
        for attempt in range(1, max_attempts + 1):
            try:
                result = subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if result.stderr:
                    logger.warning("Prisma scan stderr for %s: %s", image_name, result.stderr)
                print(f"The image {image_name} was scanned")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(
                    "Error during image scan of %s. Return code: %s. Stderr: %s. Stdout: %s",
                    image_name,
                    e.returncode,
                    e.stderr,
                    e.stdout,
                )
                if attempt < max_attempts:
                    logger.warning(
                        "Retrying Prisma scan for %s (attempt %s/%s)",
                        image_name,
                        attempt + 1,
                        max_attempts,
                    )
                    if retry_delay > 0:
                        time.sleep(retry_delay)
        return False

    def _write_image_base(self, result_file, base_image, exclusions_data, remoteconfig):
        try:
            with open(result_file, "r") as file:
                data = json.load(file)

            prisma_exclusions = exclusions_data.get("All", {}).get("PRISMA", [])
            modified = False
            base_image_list = base_image[0][0] if base_image and base_image[0][0] else []
            
            
            key_image_exception = remoteconfig.get("GET_IMAGE_BASE", {}).get("LABEL_KEYS", {}).get("key_image_exception", None)
            
            for result in data.get("results", []):
                for vulnerability in result.get("vulnerabilities", []):
                    for exclusion in prisma_exclusions:
                        if (
                            vulnerability.get("id") == exclusion.get("id") and
                            any(b_image.startswith(ex_image) for b_image in base_image_list for ex_image in exclusion.get(key_image_exception, []))
                        ):
                            vulnerability["baseImage"] = str(base_image_list) if base_image_list else ""
                            modified = True

            if modified:
                with open(result_file, "w") as file:
                    json.dump(data, file, indent=4)
        except subprocess.CalledProcessError as e:
             logger.error(f"Error during write image base of {base_image}: {e.stderr}")
            
    def _generate_sbom(self, image_scanned, remoteconfig, prisma_key, image_name):

        url = f"{remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL']}/api/{remoteconfig['PRISMA_CLOUD']['PRISMA_API_VERSION']}/sbom/download/cli-images"
        credentials = base64.b64encode(
            prisma_key.encode()
        ).decode()
        headers = {"Authorization": f"Basic {credentials}"}
        try:

            with open(image_scanned, "rb") as file:
                image_object = file.read()
                json_data = json.loads(image_object)

            if not json_data["results"]:
                print("No results found in the scan, SBOM not generated")
                return None

            response = requests.get(
                url,
                headers=headers,
                params={
                    "id": json_data["results"][0]["scanID"],
                    "sbomFormat": remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"],
                },
            )
            response.raise_for_status()

            result_sbom = f"{image_name.replace('/', '_')}_SBOM.json"
            with open(result_sbom, "wb") as file:
                file.write(response.content)
            
            print(f"SBOM generated and saved to: {result_sbom}")

            return get_list_component(result_sbom, remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"])
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}")

    def _split_prisma_token(self, prisma_key):
        try:
            access_prisma, token_prisma = prisma_key.split(":")
            return access_prisma, token_prisma
        except ValueError:
            raise ValueError("The string is not properly formatted. Make sure it contains a ':'.")
        
    def run_tool_container_sca(
        self, remoteconfig, secret_tool, token_engine_container, image_name, result_file, base_image, exclusions, generate_sbom, docker_address, is_compressed_file=False
    ):

        prisma_key = (
            f"{secret_tool['access_prisma']}:{secret_tool['token_prisma']}" if secret_tool else token_engine_container
        )
        file_path = os.path.join(
            os.getcwd(), remoteconfig["PRISMA_CLOUD"]["TWISTCLI_PATH"]
        )
        sbom_components = None

        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                prisma_key,
                remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
            )
        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            prisma_key,
            docker_address,
            is_compressed_file
        )
        if base_image:
            self._write_image_base(result_file, base_image, exclusions, remoteconfig)
        if generate_sbom:
            sbom_components = self._generate_sbom(
                image_scanned,
                remoteconfig,
                prisma_key,
                image_name
            )

        return image_scanned, sbom_components

    def get_container_context_from_results(self, path_file_results: str) -> List[ContextContainer]:
        SEVERITY_MAP = {
            "unimportant": "low",
            "unassigned": "low",
            "negligible": "low",
            "not yet assigned": "low",
            "low": "low",
            "medium": "medium",
            "moderate": "medium",
            "high": "high",
            "important": "high",
            "critical": "critical",
        }

        context_container_list = []

        with open(path_file_results, "rb") as file:
            image_object = file.read()
            json_data = json.loads(image_object)

        results = json_data.get("results", [])

        for result in results:
            target_image = result.get("name") or result.get("id", "unknown")
            os_type = result.get("distro", "unknown")
            vulnerabilities = result.get("vulnerabilities", [])

            for vul in vulnerabilities:
                status = vul.get("status", "unknown")
                link = vul.get("link")
                context_container = ContextContainer(
                    cve_id=vul.get("id", "unknown"),
                    cwe_id=vul.get("cwe", "unknown"),
                    vendor_id=vul.get("vendorId", "unknown"),
                    severity=SEVERITY_MAP.get(
                        vul.get("severity", "").lower(), vul.get("severity", "unknown")
                    ),
                    vulnerability_status=status,
                    target_image=target_image,
                    package_name=vul.get("packageName", "unknown"),
                    installed_version=vul.get("packageVersion", "unknown"),
                    fixed_version=self._extract_fixed_version(status),
                    cvss_score=vul.get("cvss"),
                    cvss_vector=vul.get("vector", "unknown"),
                    description=vul.get("description", "unknown").replace("\n", ""),
                    os_type=os_type,
                    layer_digest=result.get("id", "unknown"),
                    published_date=vul.get("publishedDate"),
                    last_modified_date=vul.get("discoveredDate", "unknown"),
                    references=[link] if link else "unknown",
                    source_tool="PrismaCloud",
                )
                context_container_list.append(context_container)

        return context_container_list

    def _extract_fixed_version(self, status: str) -> str:
        """Extract fixed version from Prisma status like 'fixed in 1.2.3'."""
        prefix = "fixed in "
        if isinstance(status, str) and status.lower().startswith(prefix):
            return status[len(prefix):].strip()
        return "unknown"
