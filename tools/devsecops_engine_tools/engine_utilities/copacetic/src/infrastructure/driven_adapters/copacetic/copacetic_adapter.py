import subprocess
import os
import json
import platform
import requests
import tarfile
import tempfile
import docker
from typing import Dict, Optional
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class CopaceticAdapter:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def install_tool(self, version, path="."):
        if self._is_copa_installed():
            return

        os_platform = platform.system()
        try:
            curr_os, arch = self._resolve_copa_platform(os_platform)
            url = f"https://github.com/project-copacetic/copacetic/releases/download/v{version}/copa_{version}_{curr_os}_{arch}.tar.gz"

            response = requests.get(url, allow_redirects=True)
            response.raise_for_status()

            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as temp_file:
                temp_file.write(response.content)
                temp_path = temp_file.name

            os.makedirs(path, exist_ok=True)
            extracted_path = self._extract_copa_binary(temp_path, path)

            os.unlink(temp_path)
            return extracted_path

        except requests.RequestException as error:
            logger.error(f"Error downloading Copa for {os_platform}: {error}")
        except tarfile.TarError as error:
            logger.error(f"Error extracting Copa archive: {error}")
        except Exception as error:
            logger.error(f"Error during Copa installation on {os_platform}: {error}")

    def _is_copa_installed(self):
        try:
            installed = subprocess.run(
                ["which", "copa"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return installed.returncode == 0
        except FileNotFoundError:
            return False

    def _resolve_copa_platform(self, os_platform):
        architecture = platform.machine()
        arch = "arm64" if architecture in ("aarch64", "arm64") else "amd64"

        if os_platform == "Linux":
            return "linux", arch
        if os_platform == "Darwin":
            return "darwin", arch
        raise OSError(f"Copa installation is not supported on {os_platform}")

    def _extract_copa_binary(self, temp_path, path):
        with tarfile.open(temp_path, 'r:gz') as tar:
            copa_member = next(
                (
                    member
                    for member in tar.getmembers()
                    if member.name.endswith('copa') and member.isfile()
                ),
                None,
            )
            if not copa_member:
                return None

            extracted_path = os.path.join(path, 'copa')
            with tar.extractfile(copa_member) as extracted_file, open(extracted_path, 'wb') as output_file:
                output_file.write(extracted_file.read())
            os.chmod(extracted_path, 0o755)
            return extracted_path

    def patch_image(
        self,
        image: str,
        vulnerability_report: str,
        output_image: Optional[str] = None,
        patch_format: str = "trivy",
        config: Optional[Dict] = None,
        work_folder: str = ".",
        platform: str = ""
    ):
        config = config or {}
        timeout_duration = config.get("TIMEOUT", 5)
        try:
            prefix = self.install_tool(config.get("VERSION"), path=work_folder)
            output_file = f"{image.replace('/', '_')}-patch-vex.json"
            copa_cmd = self._build_copa_command(
                prefix,
                image,
                vulnerability_report,
                output_image,
                patch_format,
                config,
                output_file,
                platform,
                timeout_duration,
            )

            result = subprocess.run(
                copa_cmd,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                return self._build_patch_success_result(
                    result, output_file, vulnerability_report, image, output_image, config
                )

            return self._build_patch_failure_result(result)

        except subprocess.TimeoutExpired:
            error_msg = f"Copa command timed out after {timeout_duration} minutes"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Unexpected error during Copa execution: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }

    def _build_copa_command(
        self,
        prefix,
        image,
        vulnerability_report,
        output_image,
        patch_format,
        config,
        output_file,
        platform_arg,
        timeout_duration,
    ):
        buildkit_config = config.get("BUILDKIT_CONFIG", {})
        copa_cmd = [
            prefix,
            "patch",
            "--image",
            image,
            "--scanner",
            patch_format,
            "--format",
            "openvex",
            "--output",
            output_file
        ]

        if vulnerability_report:
            copa_cmd.extend(["--report", vulnerability_report])

        buildkit_addr = buildkit_config.get("DEFAULT_ADDR")
        if buildkit_addr:
            copa_cmd.extend(["--addr", buildkit_addr])

        progress_mode = buildkit_config.get("PROGRESS", "auto")
        if progress_mode not in ["auto", "plain", "tty", "quiet", "rawjson"]:
            raise ValueError(f"Invalid progress mode: {progress_mode}")
        copa_cmd.extend(["--progress", progress_mode])

        if output_image:
            copa_cmd.extend(["--tag", output_image])
        else:
            tag_suffix = config.get("DEFAULT_OUTPUT_SUFFIX", "-patched")
            if tag_suffix.startswith("-"):
                tag_suffix = tag_suffix[1:]
            copa_cmd.extend(["--tag-suffix", tag_suffix])

        if platform_arg:
            copa_cmd.extend(["--platform", platform_arg])
        elif not vulnerability_report:
            raise ValueError(
                "If a vulnerability report is not provided, the platforms to be patched must be provided."
            )

        copa_cmd.extend(["--timeout", f"{timeout_duration}m"])

        if buildkit_config.get("IGNORE_ERRORS", False):
            copa_cmd.append("--ignore-errors")

        return copa_cmd

    def _build_patch_failure_result(self, result):
        error_msg = f"Copa command failed with return code {result.returncode}. Error: {result.stderr}"
        logger.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "copa_output": result.stdout,
            "copa_error": result.stderr
        }

    def _build_patch_success_result(
        self, result, output_file, vulnerability_report, image, output_image, config
    ):
        if os.path.exists(output_file):
            subprocess.run(["chmod", "644", f"./{output_file}"])
            patch_details = self._parse_copa_output(output_file)
        else:
            if not vulnerability_report:
                logger.info("Note: VEX report file not generated (no vulnerability report provided)")
                logger.info("Image patching completed successfully without VEX output")
            patch_details = self._empty_patch_details()

        patched_image = self._resolve_patched_image_tag(image, output_image, config)

        return {
            "success": True,
            "original_image": image,
            "patched_image": patched_image,
            "platforms_processed": patch_details.get("platforms_processed", []),
            "vulnerabilities_patched": patch_details.get("vulnerabilities_patched", 0),
            "packages_updated": len(patch_details.get("packages_updated", [])),
            "patch_details": patch_details.get("details", []),
            "copa_output": result.stdout,
            "vex_file_generated": os.path.exists(output_file)
        }

    def _resolve_patched_image_tag(self, image, output_image, config):
        if output_image:
            return output_image

        tag_suffix = config.get("DEFAULT_OUTPUT_SUFFIX", "-patched")
        if ":" in image:
            base_image, tag = image.rsplit(":", 1)
            return f"{base_image}:{tag}{tag_suffix}"
        return f"{image}{tag_suffix}"

    def get_image_info(self, image: str) -> Dict:
        try:
            client = docker.from_env()
            image_data = client.api.inspect_image(image)
            rootfs = image_data.get("RootFS", {})
            
            return {
                "exists": True,
                "architecture": image_data.get("Architecture"),
                "os": image_data.get("Os"),
                "size": image_data.get("Size"),
                "layers": len(rootfs.get("Layers", []))
            }
            
        except Exception as e:
            logger.error(f"Unexpected error while getting image info for '{image}': {str(e)}")
            return {"exists": False, "error": str(e)}

    def _empty_patch_details(self) -> Dict:
        return {
            "vulnerabilities_patched": 0,
            "details": [],
            "packages_updated": [],
            "platforms_processed": []
        }

    def _parse_copa_output(self, output_path: str) -> Dict:
        try:
            if not os.path.exists(output_path):
                logger.info(f"VEX output file not found at {output_path}")
                return self._empty_patch_details()

            with open(output_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return self._extract_patch_details_from_vex(data)

        except FileNotFoundError:
            logger.error(f"VEX output file not found: {output_path}")
            return self._empty_patch_details()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing VEX JSON file: {e}")
            return self._empty_patch_details()
        except Exception as e:
            logger.error(f"Error processing VEX output file {output_path}: {e}")
            return self._empty_patch_details()

    def _extract_patch_details_from_vex(self, data: Dict) -> Dict:
        details = {
            "vulnerabilities_patched": 0,
            "details": [],
            "packages_updated": set(),
            "platforms_processed": set()
        }

        for stmt in data.get("statements", []):
            if stmt.get("status") == "fixed":
                self._accumulate_fixed_statement(stmt, details)

        details["packages_updated"] = list(details["packages_updated"])
        details["platforms_processed"] = list(details["platforms_processed"])

        return details

    def _accumulate_fixed_statement(self, stmt, details):
        arch_str = "?arch="
        vuln_id = stmt.get("vulnerability", {}).get("@id")
        products = stmt.get("products", [])
        packages = []

        details["vulnerabilities_patched"] += 1

        for product in products:
            for sub in product.get("subcomponents", []):
                pkg_id = sub.get("@id", "")
                packages.append(pkg_id.split(arch_str)[0])
                details["packages_updated"].add(pkg_id)

                if arch_str in pkg_id:
                    arch = pkg_id.split(arch_str)[-1]
                    details["platforms_processed"].add(arch)

        details["details"].append({
            "vulnerability": vuln_id,
            "status": "fixed",
            "products": [p.get("@id") for p in products],
            "packages": packages
        })


