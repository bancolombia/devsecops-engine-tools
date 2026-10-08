from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import (
    ContextContainer,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils import (
    TrivyManagerScanUtils
)
import subprocess
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class TrivyScan(ToolGateway):

    def scan_image(self, prefix, image_name, result_file, base_image, vuln_type, ignore_unfixed=False, is_compressed_file=False):
        command = [
            prefix,
            "--scanners",
            "vuln",
            "-f",
            "json",
            "-o",
            result_file,
            "--pkg-types",
            vuln_type
        ]

        if ignore_unfixed:
            command.append("--ignore-unfixed")
        
        if is_compressed_file:
            command.extend(["--quiet", "image", "--input", image_name])
        else:
            command.extend(["--quiet", "image", image_name])
            
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"The image {image_name} was scanned")

            return result_file

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during image scan of {image_name}: {e} \nCommand stdout: {e.stdout} \nCommand stderr: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error during image scan of {image_name}: {e}")

    def _generate_sbom(self, prefix, image_name, remoteconfig, vuln_type, ignore_unfixed=False, is_compressed_file=False):
        result_sbom = f"{image_name.replace('/', '_')}_SBOM.json"
        command = [
            prefix,
            "image",
            "--format",
            remoteconfig["TRIVY"]["SBOM_FORMAT"],
            "--output",
            result_sbom,
            "--pkg-types",
            vuln_type
        ]
        if ignore_unfixed:
            command.append("--ignore-unfixed")
        if is_compressed_file:
            command.extend(["--quiet", "--input", image_name])
        else:
            command.extend(["--quiet", image_name])
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"SBOM generated and saved to: {result_sbom}")

            return get_list_component(result_sbom, remoteconfig["TRIVY"]["SBOM_FORMAT"])

        except subprocess.CalledProcessError as e:
            logger.error(f"Error generating SBOM: {e} \nCommand stdout: {e.stdout} \nCommand stderr: {e.stderr}")
        except Exception as e:
            logger.error(f"Unexpected error generating SBOM: {e}")

    def run_tool_container_sca(self, remoteconfig, secret_tool, token_engine_container, image_name, result_file, base_image, exclusions, generate_sbom, docker_address, is_compressed_file=False, cross_approval_exclusions=None):
        trivy_version = remoteconfig["TRIVY"]["TRIVY_VERSION"]
        vuln_type = remoteconfig["TRIVY"].get("VULN_TYPE", "all").lower()
        vuln_type = vuln_type if vuln_type in ["os", "library"] else "os,library"
        ignore_unfixed = remoteconfig["TRIVY"].get("IGNORE_UNFIXED", False)      
        command_prefix = TrivyManagerScanUtils().identify_os_and_install(trivy_version)
        sbom_components = None
        
        if not command_prefix:
            return None

        image_scanned = (
            self.scan_image(command_prefix, image_name, result_file, base_image, vuln_type, ignore_unfixed, is_compressed_file)
        )
        if generate_sbom:
            sbom_components = self._generate_sbom(command_prefix, image_name, remoteconfig, vuln_type, ignore_unfixed, is_compressed_file)

        return image_scanned, sbom_components

    def get_container_context_from_results(self, path_file_results: str) -> List[ContextContainer]:
        context_container_list = []

        with open(path_file_results, "rb") as file:
            image_object = file.read()
            json_data = json.loads(image_object)

        results = json_data.get("Results", [])

        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            for vul in vulnerabilities:
                cvss_score = TrivyManagerScanUtils.get_cvss_v3_score(vul.get("CVSS"))
                context_container = ContextContainer(
                    cve_id=vul.get("VulnerabilityID", "unknown"),
                    cwe_id=vul.get("CweIDs", "unknown"),
                    vendor_id=vul.get("VendorIDs", "unknown"),
                    severity=TrivyManagerScanUtils.get_cvss_v3_severity(
                        cvss_score, 
                        vul.get("Severity", "unknown").lower()
                    ),
                    vulnerability_status=vul.get("Status", "unknown"),
                    target_image=result.get("Target", "unknown"),
                    package_name=vul.get("PkgName", "unknown"),
                    installed_version=vul.get("InstalledVersion", "unknown"),
                    fixed_version=vul.get("FixedVersion", "unknown"),
                    cvss_score=cvss_score,
                    cvss_vector=vul.get("CVSS", "unknown"),
                    description=vul.get("Description", "unknown").replace("\n", ""),
                    os_type=result.get("Type", "unknown"),
                    layer_digest=vul.get("Layer", {}).get("DiffID", "unknown"),
                    published_date=(
                        self._check_date_format(vul)
                        if vul.get("PublishedDate")
                        else None
                    ),
                    last_modified_date=vul.get("LastModifiedDate", "unknown"),
                    references=vul.get("References", "unknown"),
                    source_tool="Trivy",
                )
                context_container_list.append(context_container)

        return context_container_list

    def _check_date_format(self, vul):
        """Check and format date from vulnerability data."""
        try:
            published_date_cve = (
                datetime.strptime(vul.get("PublishedDate"), "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=timezone.utc)
                .isoformat()
            )
        except:
            published_date_cve = (
                datetime.strptime(vul.get("PublishedDate"), "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc)
                .isoformat()
            )
        return published_date_cve
