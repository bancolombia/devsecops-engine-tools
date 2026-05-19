import base64
import json
import subprocess

import requests

from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


def generate_sbom(image_scanned, console_url, api_version, sbom_format, key, image_name):
    url = f"{console_url}/api/{api_version}/sbom/download/cli-images"
    credentials = base64.b64encode(key.encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}
    try:
        with open(image_scanned, "rb") as file:
            json_data = json.loads(file.read())

        if not json_data["results"]:
            print("No results found in the scan, SBOM not generated")
            return None

        response = requests.get(
            url,
            headers=headers,
            params={
                "id": json_data["results"][0]["scanID"],
                "sbomFormat": sbom_format,
            },
        )
        response.raise_for_status()

        result_sbom = f"{image_name.replace('/', '_')}_SBOM.json"
        with open(result_sbom, "wb") as file:
            file.write(response.content)

        print(f"SBOM generated and saved to: {result_sbom}")
        return get_list_component(result_sbom, sbom_format)
    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")


def apply_base_image_exclusions(
    result_file, base_image, exclusions_data, remoteconfig, exclusions_tool_key
):
    try:
        with open(result_file, "r") as file:
            data = json.load(file)

        tool_exclusions = exclusions_data.get("All", {}).get(exclusions_tool_key, [])
        modified = False
        base_image_list = base_image[0][0] if base_image and base_image[0][0] else []

        key_image_exception = (
            remoteconfig.get("GET_IMAGE_BASE", {})
            .get("LABEL_KEYS", {})
            .get("key_image_exception", None)
        )

        for result in data.get("results", []):
            for vulnerability in result.get("vulnerabilities", []):
                for exclusion in tool_exclusions:
                    if vulnerability.get("id") == exclusion.get("id") and any(
                        b_image.startswith(ex_image)
                        for b_image in base_image_list
                        for ex_image in exclusion.get(key_image_exception, [])
                    ):
                        vulnerability["baseImage"] = (
                            str(base_image_list) if base_image_list else ""
                        )
                        modified = True

        if modified:
            with open(result_file, "w") as file:
                json.dump(data, file, indent=4)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during write image base of {base_image}: {e.stderr}")
