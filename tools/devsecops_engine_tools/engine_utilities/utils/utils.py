import zipfile
import base64
import re

from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.level_vulnerability import (
    LevelVulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.level_compliance import (
    LevelCompliance,
)


class Utils:

    def unzip_file(self, zip_file_path, extract_path):
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

    def encode_token_to_base64(self, token):
        token_bytes = f"{token}:".encode("utf-8")
        base64_token = base64.b64encode(token_bytes).decode("utf-8")
        return base64_token

    def update_threshold(self, threshold: Threshold, exclusions_data, pipeline_name):
        def set_threshold(new_threshold):
            threshold.vulnerability = LevelVulnerability(new_threshold.get("VULNERABILITY"))
            threshold.compliance = LevelCompliance(new_threshold.get("COMPLIANCE")) if new_threshold.get("COMPLIANCE") else threshold.compliance
            threshold.cve = new_threshold.get("CVE") if new_threshold.get("CVE") is not None else threshold.cve
            return threshold

        threshold_pipeline = exclusions_data.get(pipeline_name, {}).get("THRESHOLD", {})
        if threshold_pipeline:
            return set_threshold(threshold_pipeline)

        search_patterns = exclusions_data.get("BY_PATTERN_SEARCH", {})
        
        match_pattern = next(
            (v["THRESHOLD"]
            for pattern, v in search_patterns.items()
            if re.match(pattern, pipeline_name, re.IGNORECASE)),
            None
        )

        return set_threshold(match_pattern) if match_pattern else threshold
