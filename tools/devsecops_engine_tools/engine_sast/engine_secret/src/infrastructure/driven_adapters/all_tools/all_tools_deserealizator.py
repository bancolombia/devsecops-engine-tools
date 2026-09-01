from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import os
import re
from typing import List
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway
)
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_deserealizator import (
    GitleaksDeserealizator
)
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import (
    SecretScanDeserealizator
)

@dataclass
class AllToolsSecretScanDeserealizator(DeseralizatorGateway):
    gitleaks_deserealizator: GitleaksDeserealizator = field(default_factory=GitleaksDeserealizator)
    trufflehog_deserealizator: SecretScanDeserealizator = field(default_factory=SecretScanDeserealizator)

    def get_list_vulnerability(
        self, 
        results_scan_list: List[dict], 
        path_directory: str, 
        os: str
        ) -> List[Finding]:
        list_open_vulnerabilities = []
        all_results = results_scan_list[0]
        findings_gitleaks = all_results.get("gitleaks", [])
        findings_trufflehog = all_results.get("trufflehog", [])
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_gitleaks = executor.submit(
                self.gitleaks_deserealizator.get_list_vulnerability,
                findings_gitleaks, path_directory, os
            )
            future_trufflehog = executor.submit(
                self.trufflehog_deserealizator.get_list_vulnerability,
                findings_trufflehog, os, path_directory
            )
            list_open_gitleaks = future_gitleaks.result()
            list_open_trufflehog = future_trufflehog.result()
        
        # Add all vulnerabilities (already deduplicated in all_tools.py)
        list_open_vulnerabilities.extend(list_open_gitleaks)
        list_open_vulnerabilities.extend(list_open_trufflehog)

        return list_open_vulnerabilities
    
    def get_where_correctly(self, result: dict, path_directory=""):
        full_path = self._extract_full_path(result)
        path = self._relativize_path(full_path, path_directory)
        line = self._extract_line(result)
        detector = self._extract_detector(result)
        hidden_secret = self._extract_hidden_secret(result)

        where = f"{path}"
        if line:
            where += f":{line}"
        if detector:
            where += f", Detector: {detector}"
        where += f", Secret: {hidden_secret}"

        return where

    def _extract_full_path(self, result):
        # Build a more detailed where string including line and detector/extra name
        full_path = result.get("File", "") or ""
        # Try trufflehog style nested path
        if full_path:
            return full_path
        try:
            return (
                result.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file", "")
            )
        except Exception:
            return full_path

    def _relativize_path(self, full_path, path_directory):
        # Remove path_directory prefix
        try:
            relative = full_path.replace(path_directory, "") if path_directory else full_path
        except Exception:
            relative = full_path
        return relative.lstrip('/')

    def _extract_line(self, result):
        return result.get("StartLine") or result.get("line") or (
            result.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line")
        )

    def _extract_detector(self, result):
        return (result.get("ExtraData") or {}).get("name") or result.get("DetectorName") or result.get("RuleID") or ""

    def _extract_hidden_secret(self, result):
        secret = str(result.get("Secret", "") or result.get("Match", "") or result.get("Raw", "") or result.get("RawV2", "") or result.get("Redacted", ""))
        if '*' in secret:
            return secret
        return (secret[:3] + '*' * 9 + secret[-3:]) if len(secret) > 6 else secret