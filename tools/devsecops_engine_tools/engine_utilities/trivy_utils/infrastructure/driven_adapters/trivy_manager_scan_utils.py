import subprocess
import platform
import requests
import tarfile
import zipfile
import hashlib
import os
import re
import certifi
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

# Explicitly blocked versions (supply chain attack CVE-2026-33634)
BLOCKED_TRIVY_VERSIONS = {"0.69.4", "0.69.5", "0.69.6"}


class TrivyManagerScanUtils():
    def identify_os_and_install(self, trivy_version):
        # Security check: block compromised versions
        if trivy_version in BLOCKED_TRIVY_VERSIONS:
            logger.error(
                f"TRIVY VERSION BLOCKED: v{trivy_version} is compromised (CVE-2026-33634). "
                f"Please use a safe version (<=0.69.3 or >=0.70.1). "
                f"See: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23"
            )
            return None

        os_platform = platform.system()
        arch_platform = platform.architecture()[0]
        os_architecture = platform.machine()
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/"

        command_prefix = "trivy"

        if os_platform == "Linux":
            if os_architecture == "aarch64":
                file = f"trivy_{trivy_version}_Linux-ARM64.tar.gz"
            else:
                file=f"trivy_{trivy_version}_Linux-{arch_platform}.tar.gz"
            command_prefix = self._install_tool(file, base_url+file, "trivy")
        elif os_platform == "Darwin":
            if os_architecture == "arm64":
                file = f"trivy_{trivy_version}_macOS-ARM64.tar.gz"
            else:
                file=f"trivy_{trivy_version}_macOS-{arch_platform}.tar.gz"
            command_prefix = self._install_tool(file, base_url+file, "trivy")
        elif os_platform == "Windows":
            file=f"trivy_{trivy_version}_windows-{arch_platform}.zip"
            command_prefix = self._install_tool_windows(file, base_url+file, "trivy.exe")
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

        return command_prefix

    def _install_tool(self, file, url, command_prefix):
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                # Download and verify integrity
                if not self._download_and_verify(file, url):
                    return None

                # Extract and install
                with tarfile.open(file, 'r:gz') as tar_file:
                    tar_file.extract(member=tar_file.getmember("trivy"))
                    return self._make_executable("trivy")
            except Exception as e:
                logger.error(f"Error installing trivy: {e}")
        else:
            return installed.stdout.decode().strip()

    def _install_tool_windows(self, file, url, command_prefix):
        try:
            subprocess.run(
                [command_prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return command_prefix
        except:
            try:
                # Download and verify integrity
                if not self._download_and_verify(file, url):
                    return None

                # Extract and install
                with zipfile.ZipFile(file, 'r') as zip_file:
                    zip_file.extract(member="trivy.exe")
                    return os.path.abspath("trivy.exe")
            except Exception as e:
                logger.error(f"Error installing trivy: {e}")

    def _download_and_verify(self, file, url):
        """Download tool and verify SHA256 checksum. Returns True if successful."""
        self._download_tool(file, url)

        if not self._verify_checksum(file):
            logger.error(
                f"Checksum verification failed for {file}. "
                f"The downloaded file may have been compromised. "
                f"Please verify the SHA256 checksum manually from: "
                f"https://github.com/aquasecurity/trivy/releases"
            )
            self._cleanup_file(file)
            return False

        return True

    def _cleanup_file(self, file_path):
        """Safely remove a downloaded file if it exists."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError as e:
            logger.warning(f"Failed to cleanup file {file_path}: {e}")

    def _make_executable(self, filename):
        """Set executable permissions and return absolute path."""
        abs_path = os.path.abspath(filename)
        os.chmod(abs_path, 0o755)
        return abs_path

    def _verify_checksum(self, file_path):
        """
        Verify SHA256 checksum by downloading official checksums.txt from Trivy releases.
        Returns True if checksum matches or if verification is not possible.
        Returns False if checksum doesn't match.
        """
        try:
            # Extract version from filename (e.g., "trivy_0.69.3_Linux-64bit.tar.gz")
            match = re.search(r'trivy_(\d+\.\d+\.\d+)', file_path)
            if not match:
                logger.warning(f"Could not extract version from filename: {file_path}")
                return True

            version = match.group(1)
            filename = os.path.basename(file_path)

            # Download official checksums.txt from Trivy releases
            checksums_url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt"
            logger.info(f"Downloading official checksums from: {checksums_url}")

            response = requests.get(
                checksums_url,
                allow_redirects=True,
                verify=certifi.where(),
                timeout=30
            )

            if response.status_code == 404:
                logger.warning(
                    f"No official checksums available for Trivy v{version}. "
                    f"Skipping verification. Please manually verify from: "
                    f"https://github.com/aquasecurity/trivy/releases"
                )
                return True

            response.raise_for_status()

            # Parse checksums.txt to find expected hash for this file
            expected_checksum = None
            for line in response.text.splitlines():
                parts = line.strip().split()
                if len(parts) == 2 and parts[1] == filename:
                    expected_checksum = parts[0].lower()
                    break

            if not expected_checksum:
                logger.warning(
                    f"No checksum found for file: {filename} in official checksums.txt. "
                    f"Skipping verification."
                )
                return True

            # Calculate SHA256 checksum of downloaded file
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            actual_checksum = sha256_hash.hexdigest()

            # Compare checksums
            if actual_checksum != expected_checksum:
                logger.error(
                    f"CHECKSUM MISMATCH for {file_path}!\n"
                    f"Expected: {expected_checksum}\n"
                    f"Actual:   {actual_checksum}\n"
                    f"The file may have been compromised!"
                )
                return False

            logger.info(f"Checksum verification passed for {file_path}")
            return True

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Failed to download checksums.txt: {e}. "
                f"Skipping verification."
            )
            return True
        except Exception as e:
            logger.error(f"Error during checksum verification: {e}")
            return True

    def _download_tool(self, file, url):
        try:
            # Use certifi's CA bundle for stricter TLS verification
            response = requests.get(
                url,
                allow_redirects=True,
                verify=certifi.where(),  # Use certifi's CA bundle
                timeout=300  # 5 minutes timeout for large files
            )
            response.raise_for_status()  # Raise exception for HTTP errors

            with open(file, "wb") as compress_file:
                compress_file.write(response.content)

            logger.info(f"Successfully downloaded Trivy from {url}")
        except requests.exceptions.SSLError as e:
            logger.error(f"TLS/SSL verification failed when downloading Trivy: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error when downloading Trivy: {e}")
            raise
        except Exception as e:
            logger.error(f"Error downloading trivy: {e}")
            raise

    @staticmethod
    def get_cvss_v3_severity(cvss_score: str, severity: str) -> str:
        if not cvss_score:
            return severity
        else:
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                return severity
            if cvss_score < 4.0:
                return "low"
            elif 4.0 <= cvss_score < 7.0:
                return "medium"
            elif 7.0 <= cvss_score < 9.0:
                return "high"
            elif cvss_score >= 9.0:
                return "critical"

    @staticmethod
    def get_cvss_v3_score(cvss_data: any) -> str:
        if not cvss_data:
            return ""
        else:
            return str(
                next(
                    (
                        v["V3Score"]
                        for v in cvss_data.values()
                        if "V3Score" in v
                    ),
                    "",
                )
            )
