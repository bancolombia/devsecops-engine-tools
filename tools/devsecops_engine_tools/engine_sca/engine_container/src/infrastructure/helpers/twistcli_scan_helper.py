import os
import subprocess
import tempfile
import time

from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def create_temp_tarball_path(image_name):
    safe_prefix = image_name.replace("/", "_").replace(":", "_")
    file_descriptor, tarball_path = tempfile.mkstemp(
        suffix=".tar", prefix=f"{safe_prefix}_"
    )
    os.close(file_descriptor)
    return tarball_path


def split_basic_auth_token(key, error_message=None):
    try:
        access, secret = key.split(":")
        return access, secret
    except ValueError:
        raise ValueError(
            error_message
            or "The string is not properly formatted. Make sure it contains a ':'."
        )


def build_scan_base_command(file_path, console_url, key, docker_address, result_file):
    access, secret = split_basic_auth_token(key)
    base_command = [
        file_path,
        "images",
        "scan",
        "--address",
        console_url,
        "--user",
        access,
        "--password",
        secret,
    ]
    if docker_address:
        base_command.extend(["--docker-address", docker_address])
    base_command.extend(["--output-file", result_file, "--details"])
    return base_command


def execute_scan(command, image_name, max_attempts, retry_delay, tool_label):
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
                logger.warning(
                    "%s scan stderr for %s: %s", tool_label, image_name, result.stderr
                )
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
                    "Retrying %s scan for %s (attempt %s/%s)",
                    tool_label,
                    image_name,
                    attempt + 1,
                    max_attempts,
                )
                if retry_delay > 0:
                    time.sleep(retry_delay)
    return False


def get_scan_retry_settings(config):
    max_attempts_normal = int(config.get("SCAN_RETRIES", 1))
    retry_delay_normal = float(config.get("SCAN_RETRY_DELAY_SECONDS", 0))
    max_attempts_tar = int(config.get("SCAN_RETRIES_TAR", 1))
    retry_delay_tar = float(config.get("SCAN_RETRY_DELAY_TAR_SECONDS", 0))
    if max_attempts_tar < 1:
        max_attempts_tar = 1
    return (
        max_attempts_normal,
        retry_delay_normal,
        max_attempts_tar,
        retry_delay_tar,
    )


def scan_image_with_tarball_fallback(
    base_command,
    image_name,
    result_file,
    is_compressed_file,
    retry_settings,
    tool_label,
):
    (
        max_attempts_normal,
        retry_delay_normal,
        max_attempts_tar,
        retry_delay_tar,
    ) = retry_settings

    command = base_command + [image_name]
    if is_compressed_file:
        command = base_command + ["--tarball", image_name]
    if execute_scan(
        command, image_name, max_attempts_normal, retry_delay_normal, tool_label
    ):
        return result_file

    tarball_path = create_temp_tarball_path(image_name)
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
        if execute_scan(
            tarball_command,
            image_name,
            max_attempts_tar,
            retry_delay_tar,
            tool_label,
        ):
            return result_file
    except subprocess.CalledProcessError as e:
        logger.error("Error saving image %s as tarball: %s", image_name, e.stderr)
    finally:
        if os.path.exists(tarball_path):
            os.remove(tarball_path)
            logger.info("Cleaned up tarball %s", tarball_path)

    return None
